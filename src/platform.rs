//! Imperative Shell (Layer 4): narrow `trait Platform` boundary and macOS implementation
//! (`rustix`, `File::try_lock`, bounded `lsof -n -P -F0pcftn`, `/sbin/mount`, `tmutil`, `git`)
//! plus non-macOS `NoPlatform`.
//!
//! Allowed dependencies: `error`, `model`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use compact_str::CompactString;

use crate::error::AppError;
use crate::model::{DiskStats, MountEntry, ProcessEntry, ProcessSnapshot};

pub(crate) const DEFAULT_VOLUME_MOUNT: &str = "/System/Volumes/Data";

#[cfg(target_os = "macos")]
const LSOF_TIMEOUT_SECS: u64 = 10;
#[cfg(target_os = "macos")]
const LSOF_STDOUT_CAP: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
const SUBPROCESS_TIMEOUT_SECS: u64 = 5;
#[cfg(target_os = "macos")]
const SUBPROCESS_STDOUT_CAP: usize = 4 * 1024 * 1024;
#[cfg(target_os = "macos")]
const SUBPROCESS_STDERR_CAP: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommandOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum LockProbe {
    Acquired(#[allow(dead_code)] File),
    Contested,
    NotFound,
}

pub(crate) trait Platform {
    fn euid(&self) -> Result<u32, AppError>;
    fn now_unix(&self) -> u64;
    fn disk_stats(&self, volume: &Path) -> Result<DiskStats, AppError>;
    fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError>;
    fn mount_table(&self) -> Result<Vec<MountEntry>, AppError>;
    fn run_git(&self, cwd: &Path, args: &[&str]) -> Result<CommandOutput, AppError>;
    fn try_lock_readonly(&self, path: &Path) -> Result<LockProbe, AppError>;
}

#[cfg(target_os = "macos")]
pub(crate) type DefaultPlatform = MacPlatform;

#[cfg(not(target_os = "macos"))]
pub(crate) type DefaultPlatform = NoPlatform;

pub(crate) fn default_platform() -> DefaultPlatform {
    DefaultPlatform::default()
}

#[cfg(not(target_os = "macos"))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoPlatform;

#[cfg(not(target_os = "macos"))]
impl Platform for NoPlatform {
    fn euid(&self) -> Result<u32, AppError> {
        Err(AppError::UnsupportedPlatform)
    }

    fn now_unix(&self) -> u64 {
        unix_now()
    }

    fn disk_stats(&self, _volume: &Path) -> Result<DiskStats, AppError> {
        Err(AppError::UnsupportedPlatform)
    }

    fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
        Err(AppError::UnsupportedPlatform)
    }

    fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
        Err(AppError::UnsupportedPlatform)
    }

    fn run_git(&self, _cwd: &Path, _args: &[&str]) -> Result<CommandOutput, AppError> {
        Err(AppError::UnsupportedPlatform)
    }

    fn try_lock_readonly(&self, _path: &Path) -> Result<LockProbe, AppError> {
        Err(AppError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MacPlatform;

#[cfg(target_os = "macos")]
impl Platform for MacPlatform {
    fn euid(&self) -> Result<u32, AppError> {
        Ok(rustix::process::geteuid().as_raw())
    }

    fn now_unix(&self) -> u64 {
        unix_now()
    }

    fn disk_stats(&self, volume: &Path) -> Result<DiskStats, AppError> {
        let stat = rustix::fs::statvfs(volume).map_err(|error| AppError::DiskStats {
            path: volume.to_path_buf(),
            message: error.to_string(),
        })?;
        let frsize = stat.f_frsize;
        if frsize == 0 || stat.f_blocks == 0 {
            return Err(AppError::DiskStats {
                path: volume.to_path_buf(),
                message: "statvfs returned zero block size or zero total blocks".to_owned(),
            });
        }
        let total_bytes = stat.f_blocks.saturating_mul(frsize);
        let free_bytes = stat.f_bavail.saturating_mul(frsize);
        let local_snapshots = list_local_snapshots();
        Ok(DiskStats {
            mount: volume.to_path_buf(),
            total_bytes,
            free_bytes,
            local_snapshots,
        })
    }

    fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
        let output = run_bounded_command(
            "/usr/sbin/lsof",
            &["-n", "-P", "-F0pcftn"],
            None,
            &[],
            std::time::Duration::from_secs(LSOF_TIMEOUT_SECS),
            LSOF_STDOUT_CAP,
            SUBPROCESS_STDERR_CAP,
        )
        .map_err(|error| AppError::ProcessSnapshot(error.to_string()))?;

        if output.status_code != Some(0) {
            return Err(AppError::ProcessSnapshot(format!(
                "lsof exited with status {:?}: {}",
                output.status_code,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if !output.stderr.is_empty() {
            return Err(AppError::ProcessSnapshot(format!(
                "lsof wrote unexpected stderr: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        parse_lsof_output(&output.stdout, unix_now(), std::process::id())
    }

    fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
        let output = run_bounded_command(
            "/sbin/mount",
            &[],
            None,
            &[],
            std::time::Duration::from_secs(SUBPROCESS_TIMEOUT_SECS),
            SUBPROCESS_STDOUT_CAP,
            SUBPROCESS_STDERR_CAP,
        )
        .map_err(|error| AppError::MountTable(error.to_string()))?;

        if output.status_code != Some(0) {
            return Err(AppError::MountTable(format!(
                "/sbin/mount exited with status {:?}",
                output.status_code
            )));
        }
        if !output.stderr.is_empty() {
            return Err(AppError::MountTable(format!(
                "/sbin/mount wrote stderr: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let text = std::str::from_utf8(&output.stdout).map_err(|error| {
            AppError::MountTable(format!("/sbin/mount output is not valid UTF-8: {error}"))
        })?;
        parse_mount_output(text)
    }

    fn run_git(&self, cwd: &Path, args: &[&str]) -> Result<CommandOutput, AppError> {
        run_bounded_command(
            "git",
            args,
            Some(cwd),
            &[("GIT_TERMINAL_PROMPT", "0"), ("GIT_OPTIONAL_LOCKS", "0")],
            std::time::Duration::from_secs(SUBPROCESS_TIMEOUT_SECS),
            SUBPROCESS_STDOUT_CAP,
            SUBPROCESS_STDERR_CAP,
        )
    }

    fn try_lock_readonly(&self, path: &Path) -> Result<LockProbe, AppError> {
        use std::fs::TryLockError;

        use rustix::fs::{Mode, OFlags};
        use rustix::io::Errno;

        let fd = match rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(LockProbe::NotFound),
            Err(error) => {
                return Err(AppError::LockProbe {
                    path: path.to_path_buf(),
                    source: std::io::Error::from(error),
                });
            }
        };

        let file = File::from(fd);
        match file.try_lock() {
            Ok(()) => Ok(LockProbe::Acquired(file)),
            Err(TryLockError::WouldBlock) => Ok(LockProbe::Contested),
            Err(TryLockError::Error(source)) => Err(AppError::LockProbe {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(target_os = "macos")]
fn list_local_snapshots() -> Option<Vec<CompactString>> {
    let output = run_bounded_command(
        "/usr/bin/tmutil",
        &["listlocalsnapshots", "/"],
        None,
        &[],
        std::time::Duration::from_secs(SUBPROCESS_TIMEOUT_SECS),
        SUBPROCESS_STDOUT_CAP,
        SUBPROCESS_STDERR_CAP,
    )
    .ok()?;
    if output.status_code != Some(0) {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?;
    Some(parse_tmutil_snapshots(text))
}

#[cfg(target_os = "macos")]
fn run_bounded_command(
    program: &'static str,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: &[(&str, &str)],
    timeout: std::time::Duration,
    stdout_cap: usize,
    stderr_cap: usize,
) -> Result<CommandOutput, AppError> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    use rustix::io::Errno;
    use rustix::process::{Pid, Signal, kill_process_group};

    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }

    let mut child = command.spawn().map_err(|error| AppError::CommandFailed {
        program,
        message: format!("spawn failed: {error}"),
    })?;
    let child_pid = Pid::from_raw(i32::try_from(child.id()).unwrap_or(0));

    let kill_and_reap = |child: &mut std::process::Child| {
        if let Some(pid) = child_pid {
            let _ = kill_process_group(pid, Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    };

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    for pipe in [stdout_pipe.as_ref().map(|p| p as &dyn std::os::fd::AsFd)]
        .into_iter()
        .flatten()
    {
        if let Ok(flags) = fcntl_getfl(pipe) {
            let _ = fcntl_setfl(pipe, flags | OFlags::NONBLOCK);
        }
    }
    if let Some(pipe) = stderr_pipe.as_ref()
        && let Ok(flags) = fcntl_getfl(pipe)
    {
        let _ = fcntl_setfl(pipe, flags | OFlags::NONBLOCK);
    }

    let deadline = Instant::now() + timeout;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];

    while stdout_pipe.is_some() || stderr_pipe.is_some() {
        let now = Instant::now();
        if now >= deadline {
            drop(stdout_pipe);
            drop(stderr_pipe);
            kill_and_reap(&mut child);
            return Err(AppError::CommandFailed {
                program,
                message: format!("timed out after {}s", timeout.as_secs()),
            });
        }
        let remaining = deadline.saturating_duration_since(now);
        let ts = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };

        let poll_outcome = {
            let mut poll_fds: smallvec::SmallVec<[PollFd<'_>; 2]> = smallvec::SmallVec::new();
            let stdout_slot = stdout_pipe.as_ref().map(|pipe| {
                let idx = poll_fds.len();
                poll_fds.push(PollFd::new(pipe, PollFlags::IN));
                idx
            });
            let stderr_slot = stderr_pipe.as_ref().map(|pipe| {
                let idx = poll_fds.len();
                poll_fds.push(PollFd::new(pipe, PollFlags::IN));
                idx
            });
            match poll(&mut poll_fds, Some(&ts)) {
                Ok(0) => Ok(None),
                Ok(_) => Ok(Some((
                    stdout_slot.is_some_and(|idx| !poll_fds[idx].revents().is_empty()),
                    stderr_slot.is_some_and(|idx| !poll_fds[idx].revents().is_empty()),
                ))),
                Err(error) => Err(error),
            }
        };

        let (stdout_ready, stderr_ready) = match poll_outcome {
            Ok(Some(flags)) => flags,
            Ok(None) => {
                drop(stdout_pipe);
                drop(stderr_pipe);
                kill_and_reap(&mut child);
                return Err(AppError::CommandFailed {
                    program,
                    message: format!("timed out after {}s", timeout.as_secs()),
                });
            }
            Err(Errno::INTR) => continue,
            Err(error) => {
                drop(stdout_pipe);
                drop(stderr_pipe);
                kill_and_reap(&mut child);
                return Err(AppError::CommandFailed {
                    program,
                    message: format!("poll failed: {error}"),
                });
            }
        };

        if stdout_ready {
            let mut closed = false;
            if let Some(pipe) = stdout_pipe.as_mut() {
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) => {
                            closed = true;
                            break;
                        }
                        Ok(n) => {
                            if stdout.len().saturating_add(n) > stdout_cap {
                                drop(stdout_pipe);
                                drop(stderr_pipe);
                                kill_and_reap(&mut child);
                                return Err(AppError::CommandFailed {
                                    program,
                                    message: format!("stdout exceeded {stdout_cap} byte limit"),
                                });
                            }
                            stdout.extend_from_slice(&buf[..n]);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            drop(stdout_pipe);
                            drop(stderr_pipe);
                            kill_and_reap(&mut child);
                            return Err(AppError::CommandFailed {
                                program,
                                message: format!("stdout read error: {error}"),
                            });
                        }
                    }
                }
            }
            if closed {
                stdout_pipe = None;
            }
        }

        if stderr_ready {
            let mut closed = false;
            if let Some(pipe) = stderr_pipe.as_mut() {
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) => {
                            closed = true;
                            break;
                        }
                        Ok(n) => {
                            if stderr.len().saturating_add(n) > stderr_cap {
                                drop(stdout_pipe);
                                drop(stderr_pipe);
                                kill_and_reap(&mut child);
                                return Err(AppError::CommandFailed {
                                    program,
                                    message: format!("stderr exceeded {stderr_cap} byte limit"),
                                });
                            }
                            stderr.extend_from_slice(&buf[..n]);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            drop(stdout_pipe);
                            drop(stderr_pipe);
                            kill_and_reap(&mut child);
                            return Err(AppError::CommandFailed {
                                program,
                                message: format!("stderr read error: {error}"),
                            });
                        }
                    }
                }
            }
            if closed {
                stderr_pipe = None;
            }
        }
    }

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(CommandOutput {
                    status_code: status.code(),
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_and_reap(&mut child);
                    return Err(AppError::CommandFailed {
                        program,
                        message: format!("timed out waiting for exit after {}s", timeout.as_secs()),
                    });
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(error) => {
                kill_and_reap(&mut child);
                return Err(AppError::CommandFailed {
                    program,
                    message: format!("wait failed: {error}"),
                });
            }
        }
    }
}

/// Strictly parse `/usr/sbin/lsof -n -P -F0pcftn` output.
/// Fails closed on empty output, `fNOFD`, invalid escape sequences, malformed headers,
/// or unexpected empty `n` fields outside `{PIPE, NPOLICY, NEXUS}`.
pub(crate) fn parse_lsof_output(
    raw: &[u8],
    captured_at_unix: u64,
    self_pid: u32,
) -> Result<ProcessSnapshot, AppError> {
    let mut processes: Vec<ProcessEntry> = Vec::new();
    let mut current: Option<ProcessEntry> = None;

    for line in raw.split(|&byte| byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Some(trimmed) = line.strip_suffix(b"\0") else {
            return Err(AppError::ProcessSnapshot(
                "lsof record missing NUL field terminator".to_owned(),
            ));
        };
        if trimmed.is_empty() {
            return Err(AppError::ProcessSnapshot(
                "lsof emitted empty NUL-terminated record".to_owned(),
            ));
        }

        let mut fields = trimmed.split(|&byte| byte == 0);
        let Some(first) = fields.next() else {
            return Err(AppError::ProcessSnapshot("empty lsof record".to_owned()));
        };
        let Some((&tag, rest)) = first.split_first() else {
            return Err(AppError::ProcessSnapshot("empty lsof field".to_owned()));
        };

        match tag {
            b'p' => {
                if let Some(entry) = current.take() {
                    processes.push(entry);
                }
                let pid_str = std::str::from_utf8(rest).map_err(|_| {
                    AppError::ProcessSnapshot("lsof pid field is not valid UTF-8".to_owned())
                })?;
                let pid: u32 = pid_str.parse().map_err(|_| {
                    AppError::ProcessSnapshot(format!("invalid lsof pid: {pid_str}"))
                })?;
                if pid == 0 {
                    return Err(AppError::ProcessSnapshot(
                        "lsof reported zero pid".to_owned(),
                    ));
                }

                let mut comm: Option<CompactString> = None;
                for field in fields {
                    let Some((&ftag, fval)) = field.split_first() else {
                        return Err(AppError::ProcessSnapshot(
                            "empty field in lsof process record".to_owned(),
                        ));
                    };
                    if ftag == b'c' {
                        let decoded = decode_lsof_bytes(fval)?;
                        comm = Some(CompactString::from(String::from_utf8_lossy(&decoded)));
                    } else {
                        return Err(AppError::ProcessSnapshot(format!(
                            "unexpected field tag `{}` in lsof process header",
                            char::from(ftag)
                        )));
                    }
                }
                let comm = comm.ok_or_else(|| {
                    AppError::ProcessSnapshot(format!(
                        "lsof process record for pid {pid} missing `c` command field"
                    ))
                })?;

                current = Some(ProcessEntry {
                    pid,
                    comm,
                    exe_path: None,
                    cwd: None,
                    open_paths: Vec::new(),
                });
            }
            b'f' => {
                let entry = current.as_mut().ok_or_else(|| {
                    AppError::ProcessSnapshot(
                        "lsof file descriptor record appeared before process header".to_owned(),
                    )
                })?;
                let fd = rest;
                if fd == b"NOFD" {
                    return Err(AppError::ProcessSnapshot(format!(
                        "lsof reported NOFD for pid {} ({})",
                        entry.pid, entry.comm
                    )));
                }

                let mut file_type: Option<&[u8]> = None;
                let mut name_raw: Option<&[u8]> = None;
                for field in fields {
                    let Some((&ftag, fval)) = field.split_first() else {
                        return Err(AppError::ProcessSnapshot(
                            "empty field in lsof fd record".to_owned(),
                        ));
                    };
                    match ftag {
                        b't' => file_type = Some(fval),
                        b'n' => name_raw = Some(fval),
                        other => {
                            return Err(AppError::ProcessSnapshot(format!(
                                "unexpected field tag `{}` in lsof fd record",
                                char::from(other)
                            )));
                        }
                    }
                }

                let ftype = file_type.ok_or_else(|| {
                    AppError::ProcessSnapshot(format!(
                        "lsof fd record missing `t` type field for pid {}",
                        entry.pid
                    ))
                })?;

                let allowed_empty_name = matches!(ftype, b"PIPE" | b"NPOLICY" | b"NEXUS");
                let decoded_name = match name_raw {
                    Some(bytes) if !bytes.is_empty() => Some(decode_lsof_bytes(bytes)?),
                    _ if allowed_empty_name => None,
                    _ => {
                        return Err(AppError::ProcessSnapshot(format!(
                            "lsof emitted empty `n` field for unexpected type `{}` on pid {}",
                            String::from_utf8_lossy(ftype),
                            entry.pid
                        )));
                    }
                };

                if let Some(bytes) = decoded_name
                    && bytes.starts_with(b"/")
                {
                    let path = bytes_to_pathbuf(bytes);
                    if fd == b"cwd" {
                        entry.cwd = Some(path);
                    } else if fd == b"txt" && ftype == b"REG" {
                        if entry.exe_path.is_none() {
                            entry.exe_path = Some(path.clone());
                        }
                        entry.open_paths.push(path);
                    } else if ftype == b"REG" || ftype == b"DIR" {
                        entry.open_paths.push(path);
                    }
                }
            }
            other => {
                return Err(AppError::ProcessSnapshot(format!(
                    "unexpected lsof record prefix `{}`",
                    char::from(other)
                )));
            }
        }
    }

    if let Some(entry) = current {
        processes.push(entry);
    }

    if processes.is_empty() {
        return Err(AppError::ProcessSnapshot(
            "lsof returned zero processes".to_owned(),
        ));
    }

    Ok(ProcessSnapshot {
        captured_at_unix,
        self_pid,
        processes,
    })
}

/// Decode lsof escape sequences (`\\`, `\n`, `\r`, `\t`, `\b`, `\f`, `\a`, `\xHH`).
/// Fails closed on any unrecognized or truncated escape.
pub(crate) fn decode_lsof_bytes(raw: &[u8]) -> Result<Vec<u8>, AppError> {
    if !raw.contains(&b'\\') {
        return Ok(raw.to_vec());
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut idx = 0;
    while idx < raw.len() {
        let byte = raw[idx];
        if byte != b'\\' {
            out.push(byte);
            idx += 1;
            continue;
        }
        idx += 1;
        let Some(&next) = raw.get(idx) else {
            return Err(AppError::ProcessSnapshot(
                "truncated escape sequence in lsof field".to_owned(),
            ));
        };
        match next {
            b'\\' => {
                out.push(b'\\');
                idx += 1;
            }
            b'n' => {
                out.push(b'\n');
                idx += 1;
            }
            b'r' => {
                out.push(b'\r');
                idx += 1;
            }
            b't' => {
                out.push(b'\t');
                idx += 1;
            }
            b'b' => {
                out.push(0x08);
                idx += 1;
            }
            b'f' => {
                out.push(0x0c);
                idx += 1;
            }
            b'a' => {
                out.push(0x07);
                idx += 1;
            }
            b'x' => {
                let Some(hex_slice) = raw.get(idx + 1..idx + 3) else {
                    return Err(AppError::ProcessSnapshot(
                        "truncated \\xHH escape in lsof field".to_owned(),
                    ));
                };
                let hi = hex_nibble(hex_slice[0])?;
                let lo = hex_nibble(hex_slice[1])?;
                out.push((hi << 4) | lo);
                idx += 3;
            }
            other => {
                return Err(AppError::ProcessSnapshot(format!(
                    "unsupported escape sequence `\\{}` in lsof field",
                    char::from(other)
                )));
            }
        }
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, AppError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AppError::ProcessSnapshot(format!(
            "invalid hex digit `{}` in lsof \\xHH escape",
            char::from(byte)
        ))),
    }
}

#[cfg(unix)]
fn bytes_to_pathbuf(bytes: Vec<u8>) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    PathBuf::from(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn bytes_to_pathbuf(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

/// Strictly parse macOS `/sbin/mount` lines (`<source> on <mount_point> (<fstype>, ...)`).
/// Fails closed on empty output, missing parentheses, or ambiguous ` on ` separators.
pub(crate) fn parse_mount_output(raw: &str) -> Result<Vec<MountEntry>, AppError> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((lhs, opts_with_close)) = trimmed.rsplit_once(" (") else {
            return Err(AppError::MountTable(format!(
                "malformed mount line (missing options): {trimmed}"
            )));
        };
        let Some(opts) = opts_with_close.strip_suffix(')') else {
            return Err(AppError::MountTable(format!(
                "malformed mount line (unclosed options): {trimmed}"
            )));
        };
        let fstype = opts
            .split(',')
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::MountTable(format!("malformed mount line (empty fstype): {trimmed}"))
            })?;
        let Some((source, mount_point)) = lhs.split_once(" on ") else {
            return Err(AppError::MountTable(format!(
                "malformed mount line (missing ` on `): {trimmed}"
            )));
        };
        if source.is_empty() || !mount_point.starts_with('/') || mount_point.contains(" on ") {
            return Err(AppError::MountTable(format!(
                "ambiguous or invalid mount line: {trimmed}"
            )));
        }
        entries.push(MountEntry {
            source: CompactString::from(source),
            mount_point: PathBuf::from(mount_point),
            fstype: CompactString::from(fstype),
        });
    }
    if entries.is_empty() {
        return Err(AppError::MountTable(
            "/sbin/mount produced zero entries".to_owned(),
        ));
    }
    Ok(entries)
}

/// Parse `/usr/bin/tmutil listlocalsnapshots /` output into a sorted deduplicated list.
pub(crate) fn parse_tmutil_snapshots(raw: &str) -> Vec<CompactString> {
    let mut snapshots: Vec<CompactString> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.ends_with(':'))
        .map(CompactString::from)
        .collect();
    snapshots.sort();
    snapshots.dedup();
    snapshots
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use compact_str::CompactString;

    use super::{decode_lsof_bytes, parse_lsof_output, parse_mount_output, parse_tmutil_snapshots};

    #[test]
    fn parse_lsof_handles_spaces_31b_comm_escapes_and_allowed_empty_names() {
        let sample = concat!(
            "p41797\0cAntigravity Helper (Plugin)\0\n",
            "fcwd\0tDIR\0n/Users/dev/Projects/\\xd1\\x82\\xd0\\xb5\\xd1\\x81\\xd1\\x82\\\\repo\0\n",
            "ftxt\0tREG\0n/Applications/Antigravity.app/Contents/MacOS/Antigravity Helper\0\n",
            "ftxt\0tREG\0n/usr/lib/dyld\0\n",
            "f3\0tPIPE\0\n",
            "f4\0tNPOLICY\0n\0\n",
            "f5\0tNEXUS\0\n",
            "f6\0tREG\0n/Users/dev/Projects/repo/target/debug/deps/libmacro.dylib\0\n",
            "f7\0tsystm\0n[ctl com.apple.netsrc id 7 unit 16]\0\n",
        );

        let snap = parse_lsof_output(sample.as_bytes(), 1234, 9999).unwrap();
        assert_eq!(snap.captured_at_unix, 1234);
        assert_eq!(snap.processes.len(), 1);
        let p = &snap.processes[0];
        assert_eq!(p.pid, 41797);
        assert_eq!(p.comm.as_str(), "Antigravity Helper (Plugin)");
        assert_eq!(
            p.exe_path.as_deref(),
            Some(std::path::Path::new(
                "/Applications/Antigravity.app/Contents/MacOS/Antigravity Helper"
            ))
        );
        assert_eq!(
            p.cwd.as_deref(),
            Some(std::path::Path::new("/Users/dev/Projects/тест\\repo"))
        );
        assert!(p.open_paths.contains(&PathBuf::from(
            "/Users/dev/Projects/repo/target/debug/deps/libmacro.dylib"
        )));
        assert!(
            !p.open_paths
                .iter()
                .any(|path| path.to_string_lossy().contains("netsrc"))
        );
    }

    #[test]
    fn parse_lsof_fails_closed_on_nofd_invalid_escape_and_unexpected_empty_name() {
        let nofd = b"p10\0ccargo\0\nfNOFD\0tREG\0n/tmp/a\0\n";
        assert!(parse_lsof_output(nofd, 1, 0).is_err());

        let bad_empty = b"p10\0ccargo\0\nf3\0tREG\0n\0\n";
        assert!(parse_lsof_output(bad_empty, 1, 0).is_err());

        let bad_hex = b"p10\0ccargo\0\nf3\0tREG\0n/tmp/\\xZZ\0\n";
        assert!(parse_lsof_output(bad_hex, 1, 0).is_err());

        let truncated_escape = b"p10\0ccargo\0\nf3\0tREG\0n/tmp/\\\0\n";
        assert!(parse_lsof_output(truncated_escape, 1, 0).is_err());

        assert!(parse_lsof_output(b"", 1, 0).is_err());
        assert!(decode_lsof_bytes(b"\\q").is_err());
    }

    #[test]
    fn parse_mount_handles_real_macos_lines_and_rejects_ambiguous() {
        let sample = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse, protect, root data)
OrbStack:/OrbStack on /Users/dev/OrbStack (nfs, nodev, nosuid, noatime, mounted by dev)
/dev/disk4s1 on /Volumes/My External SSD (apfs, local, nodev)
";
        let entries = parse_mount_output(sample).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries[1].mount_point,
            PathBuf::from("/System/Volumes/Data")
        );
        assert_eq!(entries[1].fstype.as_str(), "apfs");
        assert_eq!(entries[2].mount_point, PathBuf::from("/Users/dev/OrbStack"));
        assert_eq!(entries[2].fstype.as_str(), "nfs");
        assert_eq!(
            entries[3].mount_point,
            PathBuf::from("/Volumes/My External SSD")
        );

        let ambiguous = "/dev/disk1 on /Volumes/a on b (apfs, local)\n";
        assert!(parse_mount_output(ambiguous).is_err());
        assert!(parse_mount_output("").is_err());
        assert!(parse_mount_output("/dev/disk1 / (apfs)\n").is_err());
    }

    #[test]
    fn parse_tmutil_sorts_and_ignores_headers() {
        let sample = "\
Snapshots for volume group containing disk /:
com.apple.os.update-ZZZ
com.apple.os.update-AAA
com.apple.os.update-ZZZ
";
        assert_eq!(
            parse_tmutil_snapshots(sample),
            vec![
                CompactString::new("com.apple.os.update-AAA"),
                CompactString::new("com.apple.os.update-ZZZ"),
            ]
        );
        assert!(parse_tmutil_snapshots("Snapshots for disk /:\n").is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_try_lock_readonly_detects_missing_unlocked_and_contested() {
        use super::{LockProbe, MacPlatform, Platform};

        let platform = MacPlatform;
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.lock");
        assert!(matches!(
            platform.try_lock_readonly(&missing).unwrap(),
            LockProbe::NotFound
        ));

        let lock_path = dir.path().join(".cargo-build-lock");
        std::fs::write(&lock_path, b"").unwrap();

        let holder = std::fs::File::open(&lock_path).unwrap();
        holder.try_lock().unwrap();
        assert!(matches!(
            platform.try_lock_readonly(&lock_path).unwrap(),
            LockProbe::Contested
        ));
        drop(holder);

        assert!(matches!(
            platform.try_lock_readonly(&lock_path).unwrap(),
            LockProbe::Acquired(_)
        ));
    }
}
