//! Imperative Shell (Layer 4): narrow `trait Platform` boundary and macOS implementation
//! (`rustix`, `File::try_lock`, bounded `lsof -n -P -F0pcftn`, `/sbin/mount`, `tmutil`, `git`)
//! plus non-macOS `NoPlatform`.
//!
//! Allowed dependencies: `error`, `model`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use compact_str::CompactString;
use smallvec::SmallVec;

use crate::error::AppError;
use crate::model::{
    DiskStats, FastU64BuildHasher, MountEntry, PathPool, PathRef, ProcessEntry, ProcessSnapshot,
};

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
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct CommandOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum LockProbe {
    Acquired(#[allow(dead_code)] File),
    Contested,
    NotFound,
}

pub(crate) trait Platform {
    fn euid(&self) -> Result<u32, AppError>;
    fn now_unix(&self) -> u64;
    fn disk_stats(&self, volume: &Path) -> Result<DiskStats, AppError>;
    /// Fast free-space probe (`statvfs` only, without invoking `tmutil`).
    fn free_bytes(&self, volume: &Path) -> Result<u64, AppError> {
        self.disk_stats(volume).map(|stats| stats.free_bytes)
    }
    fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError>;
    fn mount_table(&self) -> Result<Vec<MountEntry>, AppError>;
    fn run_git(&self, cwd: &Path, args: &[&str]) -> Result<CommandOutput, AppError>;
    fn try_lock_readonly(&self, path: &Path) -> Result<LockProbe, AppError>;
    fn run_launchctl(&self, args: &[&str]) -> Result<CommandOutput, AppError>;
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

    fn run_launchctl(&self, _args: &[&str]) -> Result<CommandOutput, AppError> {
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
        let (total_bytes, free_bytes) = statvfs_totals(volume)?;
        let local_snapshots = list_local_snapshots();
        Ok(DiskStats {
            mount: volume.to_path_buf(),
            total_bytes,
            free_bytes,
            local_snapshots,
        })
    }

    fn free_bytes(&self, volume: &Path) -> Result<u64, AppError> {
        statvfs_totals(volume).map(|(_, free_bytes)| free_bytes)
    }

    fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
        let mut parser = LsofStreamParser::new();
        let (status_code, stderr) = run_bounded_command_streaming(
            "/usr/sbin/lsof",
            &["-n", "-P", "-F0pcftn"],
            Some(Path::new("/")),
            &[],
            std::time::Duration::from_secs(LSOF_TIMEOUT_SECS),
            LSOF_STDOUT_CAP,
            SUBPROCESS_STDERR_CAP,
            |chunk| parser.feed(chunk),
        )
        .map_err(|error| AppError::ProcessSnapshot(error.to_string()))?;

        if status_code != Some(0) {
            return Err(AppError::ProcessSnapshot(format!(
                "lsof exited with status {:?}: {}",
                status_code,
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        if !stderr.is_empty() {
            return Err(AppError::ProcessSnapshot(format!(
                "lsof wrote unexpected stderr: {}",
                String::from_utf8_lossy(&stderr).trim()
            )));
        }

        parser.finish(unix_now(), std::process::id())
    }

    fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
        let output = run_bounded_command(
            "/sbin/mount",
            &[],
            Some(Path::new("/")),
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

    fn run_launchctl(&self, args: &[&str]) -> Result<CommandOutput, AppError> {
        run_bounded_command(
            "/bin/launchctl",
            args,
            Some(Path::new("/")),
            &[],
            std::time::Duration::from_secs(SUBPROCESS_TIMEOUT_SECS),
            SUBPROCESS_STDOUT_CAP,
            SUBPROCESS_STDERR_CAP,
        )
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(target_os = "macos")]
fn statvfs_totals(volume: &Path) -> Result<(u64, u64), AppError> {
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
    Ok((total_bytes, free_bytes))
}

#[cfg(target_os = "macos")]
fn list_local_snapshots() -> Option<Vec<CompactString>> {
    let output = run_bounded_command(
        "/usr/bin/tmutil",
        &["listlocalsnapshots", "/"],
        Some(Path::new("/")),
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
    let mut stdout = Vec::new();
    let (status_code, stderr) = run_bounded_command_streaming(
        program,
        args,
        cwd,
        extra_env,
        timeout,
        stdout_cap,
        stderr_cap,
        |chunk| stdout.extend_from_slice(chunk),
    )?;
    Ok(CommandOutput {
        status_code,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn run_bounded_command_streaming<F>(
    program: &'static str,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: &[(&str, &str)],
    timeout: std::time::Duration,
    stdout_cap: usize,
    stderr_cap: usize,
    mut on_stdout: F,
) -> Result<(Option<i32>, Vec<u8>), AppError>
where
    F: FnMut(&[u8]),
{
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

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

    if let Some(pipe) = stdout_pipe.as_ref()
        && let Ok(flags) = fcntl_getfl(pipe)
    {
        let _ = fcntl_setfl(pipe, flags | OFlags::NONBLOCK);
    }
    if let Some(pipe) = stderr_pipe.as_ref()
        && let Ok(flags) = fcntl_getfl(pipe)
    {
        let _ = fcntl_setfl(pipe, flags | OFlags::NONBLOCK);
    }

    let deadline = Instant::now() + timeout;
    let mut stdout_len: usize = 0;
    let mut stderr = Vec::new();
    let mut buf = [0u8; 8 * 1024];

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
            let mut poll_fds: SmallVec<[PollFd<'_>; 2]> = SmallVec::new();
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
                            let next_len = stdout_len.saturating_add(n);
                            if next_len > stdout_cap {
                                drop(stdout_pipe);
                                drop(stderr_pipe);
                                kill_and_reap(&mut child);
                                return Err(AppError::CommandFailed {
                                    program,
                                    message: format!("stdout exceeded {stdout_cap} byte limit"),
                                });
                            }
                            stdout_len = next_len;
                            on_stdout(&buf[..n]);
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

    let mut yields = 0u8;
    let mut backoff = Duration::from_micros(50);
    let max_backoff = Duration::from_millis(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok((status.code(), stderr));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_and_reap(&mut child);
                    return Err(AppError::CommandFailed {
                        program,
                        message: format!("timed out waiting for exit after {}s", timeout.as_secs()),
                    });
                }
                if yields < 2 {
                    yields += 1;
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(max_backoff);
                }
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
#[cfg(test)]
pub(crate) fn parse_lsof_output(
    raw: &[u8],
    captured_at_unix: u64,
    self_pid: u32,
) -> Result<ProcessSnapshot, AppError> {
    let mut parser = LsofStreamParser::new();
    parser.feed(raw);
    parser.finish(captured_at_unix, self_pid)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct LsofStreamParser {
    processes: Vec<ProcessEntry>,
    open_path_refs: Vec<PathRef>,
    path_pool: PathPool,
    current: Option<ProcessEntry>,
    pending: Vec<u8>,
    decode_scratch: Vec<u8>,
    /// Global cross-PID path interning table: maps FNV-1a hash -> `(PathRef, last_open_proc_seq)`.
    /// Deduplicates shared system `.dylib`/framework paths across all PIDs (~43% smaller `PathPool`)
    /// while also deduplicating duplicate open FDs within each PID via `proc_seq`.
    interned_paths: HashMap<u64, SmallVec<[(PathRef, u32); 2]>, FastU64BuildHasher>,
    proc_seq: u32,
    error: Option<AppError>,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl LsofStreamParser {
    fn new() -> Self {
        Self {
            processes: Vec::with_capacity(256),
            open_path_refs: Vec::with_capacity(4096),
            path_pool: PathPool::with_capacity(256 * 1024),
            current: None,
            pending: Vec::new(),
            decode_scratch: Vec::new(),
            interned_paths: HashMap::with_capacity_and_hasher(1024, FastU64BuildHasher),
            proc_seq: 0,
            error: None,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        if self.error.is_some() || chunk.is_empty() {
            return;
        }
        let mut rest = chunk;
        if !self.pending.is_empty() {
            if let Some(nl) = memchr::memchr(b'\n', rest) {
                self.pending.extend_from_slice(&rest[..nl]);
                let line = std::mem::take(&mut self.pending);
                if let Err(err) = self.parse_line(&line) {
                    self.error = Some(err);
                    return;
                }
                self.pending = line;
                self.pending.clear();
                rest = &rest[nl + 1..];
            } else {
                self.pending.extend_from_slice(rest);
                return;
            }
        }

        while !rest.is_empty() {
            if let Some(nl) = memchr::memchr(b'\n', rest) {
                let line = &rest[..nl];
                if let Err(err) = self.parse_line(line) {
                    self.error = Some(err);
                    return;
                }
                rest = &rest[nl + 1..];
            } else {
                self.pending.extend_from_slice(rest);
                break;
            }
        }
    }

    fn finish(mut self, captured_at_unix: u64, self_pid: u32) -> Result<ProcessSnapshot, AppError> {
        if let Some(err) = self.error {
            return Err(err);
        }
        if !self.pending.is_empty() {
            let tail = std::mem::take(&mut self.pending);
            self.parse_line(&tail)?;
        }
        if let Some(entry) = self.current.take() {
            self.processes.push(entry);
        }
        if self.processes.is_empty() {
            return Err(AppError::ProcessSnapshot(
                "lsof returned zero processes".to_owned(),
            ));
        }
        Ok(ProcessSnapshot {
            captured_at_unix,
            self_pid,
            processes: self.processes,
            open_path_refs: self.open_path_refs,
            path_pool: self.path_pool,
        })
    }

    fn parse_line(&mut self, line: &[u8]) -> Result<(), AppError> {
        if line.is_empty() {
            return Ok(());
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

        let (first, mut field_rest) = split_next_nul(trimmed);
        let Some((&tag, rest)) = first.split_first() else {
            return Err(AppError::ProcessSnapshot("empty lsof field".to_owned()));
        };

        match tag {
            b'p' => {
                if let Some(entry) = self.current.take() {
                    self.processes.push(entry);
                }
                self.proc_seq = self.proc_seq.checked_add(1).ok_or_else(|| {
                    AppError::ProcessSnapshot("lsof exceeded process sequence capacity".to_owned())
                })?;

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
                while let Some(rem) = field_rest {
                    let (field, next_rest) = split_next_nul(rem);
                    field_rest = next_rest;
                    let Some((&ftag, fval)) = field.split_first() else {
                        return Err(AppError::ProcessSnapshot(
                            "empty field in lsof process record".to_owned(),
                        ));
                    };
                    if ftag == b'c' {
                        let decoded = decode_lsof_cow(fval, &mut self.decode_scratch)?;
                        comm = Some(CompactString::from(String::from_utf8_lossy(decoded)));
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

                let open_paths_start = u32::try_from(self.open_path_refs.len()).unwrap_or(u32::MAX);
                self.current = Some(ProcessEntry {
                    pid,
                    comm,
                    exe_path: None,
                    cwd: None,
                    open_paths_start,
                    open_paths_len: 0,
                });
                Ok(())
            }
            b'f' => {
                let entry = self.current.as_mut().ok_or_else(|| {
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
                while let Some(rem) = field_rest {
                    let (field, next_rest) = split_next_nul(rem);
                    field_rest = next_rest;
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

                let Some(ftype) = file_type else {
                    // Darwin `lsof` omits the `t` field when a numeric FD closes between
                    // `PROC_PIDLISTFDS` and `proc_pidfdinfo`, emitting `n<kind>: FD unavailable`.
                    let is_numeric_fd = !fd.is_empty() && fd.iter().all(u8::is_ascii_digit);
                    if is_numeric_fd && name_raw.is_some_and(|n| n.ends_with(b": FD unavailable")) {
                        return Ok(());
                    }
                    return Err(AppError::ProcessSnapshot(format!(
                        "lsof fd record missing `t` type field for pid {}",
                        entry.pid
                    )));
                };

                let allowed_empty_name = matches!(ftype, b"PIPE" | b"NPOLICY" | b"NEXUS");
                let raw_name = match name_raw {
                    Some(bytes) if !bytes.is_empty() => bytes,
                    _ if allowed_empty_name => return Ok(()),
                    _ => {
                        return Err(AppError::ProcessSnapshot(format!(
                            "lsof emitted empty `n` field for unexpected type `{}` on pid {}",
                            String::from_utf8_lossy(ftype),
                            entry.pid
                        )));
                    }
                };

                let keep_type = fd == b"cwd" || ftype == b"REG" || ftype == b"DIR";
                let may_start_with_slash = raw_name[0] == b'/' || raw_name[0] == b'\\';
                if !keep_type || !may_start_with_slash {
                    validate_lsof_escapes(raw_name)?;
                    return Ok(());
                }

                let decoded = decode_lsof_cow(raw_name, &mut self.decode_scratch)?;
                if !decoded.starts_with(b"/") {
                    return Ok(());
                }

                let hash = fnv1a_bytes(decoded);
                let bucket = self.interned_paths.entry(hash).or_default();
                let found_idx = bucket
                    .iter()
                    .position(|&(r, _)| self.path_pool.bytes_eq(r, decoded));

                if fd == b"cwd" {
                    let path_ref = if let Some(idx) = found_idx {
                        bucket[idx].0
                    } else {
                        let r = self.path_pool.try_push_bytes(decoded).ok_or_else(|| {
                            AppError::ProcessSnapshot("lsof path pool exceeded 4 GiB".to_owned())
                        })?;
                        bucket.push((r, 0));
                        r
                    };
                    entry.cwd = Some(path_ref);
                } else {
                    let is_txt_reg = fd == b"txt" && ftype == b"REG";
                    if let Some(idx) = found_idx {
                        let (existing_ref, last_seq) = &mut bucket[idx];
                        let path_ref = *existing_ref;
                        if is_txt_reg && entry.exe_path.is_none() {
                            entry.exe_path = Some(path_ref);
                        }
                        if *last_seq != self.proc_seq {
                            *last_seq = self.proc_seq;
                            self.open_path_refs.push(path_ref);
                            entry.open_paths_len = entry.open_paths_len.saturating_add(1);
                        }
                    } else {
                        let path_ref = self.path_pool.try_push_bytes(decoded).ok_or_else(|| {
                            AppError::ProcessSnapshot("lsof path pool exceeded 4 GiB".to_owned())
                        })?;
                        if is_txt_reg && entry.exe_path.is_none() {
                            entry.exe_path = Some(path_ref);
                        }
                        self.open_path_refs.push(path_ref);
                        entry.open_paths_len = entry.open_paths_len.saturating_add(1);
                        bucket.push((path_ref, self.proc_seq));
                    }
                }
                Ok(())
            }
            other => Err(AppError::ProcessSnapshot(format!(
                "unexpected lsof record prefix `{}`",
                char::from(other)
            ))),
        }
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[inline]
fn split_next_nul(bytes: &[u8]) -> (&[u8], Option<&[u8]>) {
    match memchr::memchr(0, bytes) {
        Some(pos) => (&bytes[..pos], Some(&bytes[pos + 1..])),
        None => (bytes, None),
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[inline]
fn fnv1a_bytes(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Validate lsof escape sequences in-place with zero heap allocations.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn validate_lsof_escapes(raw: &[u8]) -> Result<(), AppError> {
    let mut idx = 0;
    while let Some(rel) = memchr::memchr(b'\\', &raw[idx..]) {
        idx += rel + 1;
        let Some(&next) = raw.get(idx) else {
            return Err(AppError::ProcessSnapshot(
                "truncated escape sequence in lsof field".to_owned(),
            ));
        };
        match next {
            b'\\' | b'n' | b'r' | b't' | b'b' | b'f' | b'a' => idx += 1,
            b'x' => {
                let Some(hex_slice) = raw.get(idx + 1..idx + 3) else {
                    return Err(AppError::ProcessSnapshot(
                        "truncated \\xHH escape in lsof field".to_owned(),
                    ));
                };
                let _ = hex_nibble(hex_slice[0])?;
                let _ = hex_nibble(hex_slice[1])?;
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
    Ok(())
}

/// Decode lsof escape sequences, borrowing `raw` directly when no backslash is present,
/// or decoding into the reusable `scratch` buffer.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn decode_lsof_cow<'a>(raw: &'a [u8], scratch: &'a mut Vec<u8>) -> Result<&'a [u8], AppError> {
    let Some(first_bs) = memchr::memchr(b'\\', raw) else {
        return Ok(raw);
    };
    scratch.clear();
    scratch.reserve(raw.len());
    scratch.extend_from_slice(&raw[..first_bs]);
    let mut idx = first_bs;
    while idx < raw.len() {
        let Some(rel) = memchr::memchr(b'\\', &raw[idx..]) else {
            scratch.extend_from_slice(&raw[idx..]);
            break;
        };
        scratch.extend_from_slice(&raw[idx..idx + rel]);
        idx += rel + 1;
        let Some(&next) = raw.get(idx) else {
            return Err(AppError::ProcessSnapshot(
                "truncated escape sequence in lsof field".to_owned(),
            ));
        };
        match next {
            b'\\' => {
                scratch.push(b'\\');
                idx += 1;
            }
            b'n' => {
                scratch.push(b'\n');
                idx += 1;
            }
            b'r' => {
                scratch.push(b'\r');
                idx += 1;
            }
            b't' => {
                scratch.push(b'\t');
                idx += 1;
            }
            b'b' => {
                scratch.push(0x08);
                idx += 1;
            }
            b'f' => {
                scratch.push(0x0c);
                idx += 1;
            }
            b'a' => {
                scratch.push(0x07);
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
                scratch.push((hi << 4) | lo);
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
    Ok(scratch.as_slice())
}

/// Decode lsof escape sequences (`\\`, `\n`, `\r`, `\t`, `\b`, `\f`, `\a`, `\xHH`).
/// Fails closed on any unrecognized or truncated escape.
#[cfg(test)]
pub(crate) fn decode_lsof_bytes(raw: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut scratch = Vec::new();
    Ok(decode_lsof_cow(raw, &mut scratch)?.to_vec())
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

/// Strictly parse macOS `/sbin/mount` lines (`<source> on <mount_point> (<fstype>, ...)`).
/// Fails closed on empty output, missing parentheses, or ambiguous ` on ` separators.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

/// Normalize macOS firmlink/symlink system prefixes (`/var`, `/tmp`, `/etc` -> `/private/...`),
/// borrowing when no rewrite is required.
pub(crate) fn normalize_macos_system_symlinks_cow(path: &Path) -> Cow<'_, Path> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(rest) = path.strip_prefix("/var") {
            return Cow::Owned(Path::new("/private/var").join(rest));
        }
        if let Ok(rest) = path.strip_prefix("/tmp") {
            return Cow::Owned(Path::new("/private/tmp").join(rest));
        }
        if let Ok(rest) = path.strip_prefix("/etc") {
            return Cow::Owned(Path::new("/private/etc").join(rest));
        }
    }
    Cow::Borrowed(path)
}

/// Normalize macOS firmlink/symlink system prefixes (`/var`, `/tmp`, `/etc` -> `/private/...`).
pub(crate) fn normalize_macos_system_symlinks(path: &Path) -> PathBuf {
    normalize_macos_system_symlinks_cow(path).into_owned()
}

/// Return `true` if `path` or any ancestor component is a non-system symlink (fail-closed on error).
pub(crate) fn has_symlink_boundary(path: &Path) -> bool {
    let Ok(canon) = std::fs::canonicalize(path) else {
        return true;
    };
    let normalized = normalize_macos_system_symlinks_cow(path);
    canon.as_path() != normalized.as_ref()
}

/// Single-owner mount-boundary validator shared by `discover` and post-lock `execute` revalidation.
/// Checks parent-vs-target `st_dev` mismatch, mount points at/under `target_root`, and non-local
/// (NFS/SMB/FUSE/OrbStack) mounts at any ancestor of `target_root`.
pub(crate) fn crosses_mount_boundary(
    target_root: &Path,
    target_dev: u64,
    mounts: Option<&[MountEntry]>,
) -> bool {
    if let Some(parent) = target_root.parent() {
        let Ok(parent_meta) = std::fs::symlink_metadata(parent) else {
            return true;
        };
        if metadata_dev(&parent_meta) != target_dev {
            return true;
        }
    }

    let Some(entries) = mounts else {
        return false;
    };

    let norm_target = normalize_mount_path_cow(target_root);
    let norm_target_ref = norm_target.as_ref();
    for entry in entries {
        let mp = entry.mount_point.as_path();
        if mp == Path::new("/") || mp == Path::new(DEFAULT_VOLUME_MOUNT) {
            continue;
        }
        let norm_mp = normalize_mount_path_cow(mp);
        let norm_mp_ref = norm_mp.as_ref();
        if norm_mp_ref == Path::new("/") {
            continue;
        }
        if norm_mp_ref == norm_target_ref || norm_mp_ref.starts_with(norm_target_ref) {
            return true;
        }
        if norm_target_ref.starts_with(norm_mp_ref) && is_non_local_fstype(&entry.fstype) {
            return true;
        }
    }
    false
}

fn normalize_mount_path_cow(path: &Path) -> Cow<'_, Path> {
    if let Ok(rest) = path.strip_prefix(DEFAULT_VOLUME_MOUNT) {
        if rest.as_os_str().is_empty() {
            return Cow::Borrowed(Path::new("/"));
        }
        let joined = Path::new("/").join(rest);
        return Cow::Owned(normalize_macos_system_symlinks_cow(&joined).into_owned());
    }
    normalize_macos_system_symlinks_cow(path)
}

fn is_non_local_fstype(fstype: &str) -> bool {
    fstype.eq_ignore_ascii_case("nfs")
        || fstype.eq_ignore_ascii_case("smbfs")
        || fstype.eq_ignore_ascii_case("afpfs")
        || fstype.eq_ignore_ascii_case("webdav")
        || fstype.eq_ignore_ascii_case("autofs")
        || fstype.eq_ignore_ascii_case("devfs")
        || fstype.eq_ignore_ascii_case("nullfs")
        || fstype.eq_ignore_ascii_case("macfuse")
        || fstype.eq_ignore_ascii_case("osxfuse")
        || fstype
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("fuse"))
}

#[cfg(unix)]
fn metadata_dev(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.dev()
}

#[cfg(not(unix))]
fn metadata_dev(_meta: &std::fs::Metadata) -> u64 {
    0
}

/// Non-blocking self-pipe `SIGTERM`/`SIGINT` watcher backed by `signal-hook` + `rustix::event::poll`.
#[cfg(unix)]
pub(crate) struct SignalWatcher {
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    read_end: std::os::unix::net::UnixStream,
    sig_ids: Vec<signal_hook::SigId>,
}

#[cfg(unix)]
impl SignalWatcher {
    pub(crate) fn install() -> Result<Self, AppError> {
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        use signal_hook::consts::signal::{SIGINT, SIGTERM};
        use signal_hook::flag;
        use signal_hook::low_level::{pipe, unregister};

        let (read_end, write_term) = UnixStream::pair().map_err(|error| {
            AppError::Signal(format!("cannot create signal self-pipe: {error}"))
        })?;
        read_end
            .set_nonblocking(true)
            .map_err(|error| AppError::Signal(format!("cannot configure self-pipe: {error}")))?;
        write_term
            .set_nonblocking(true)
            .map_err(|error| AppError::Signal(format!("cannot configure self-pipe: {error}")))?;
        let write_int = write_term
            .try_clone()
            .map_err(|error| AppError::Signal(format!("cannot clone self-pipe: {error}")))?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let mut sig_ids = Vec::with_capacity(4);

        let register_result: std::io::Result<()> = (|| {
            // Set flag FIRST, then write pipe so waking reader always sees `stop_flag == true`.
            sig_ids.push(flag::register(SIGTERM, Arc::clone(&stop_flag))?);
            sig_ids.push(flag::register(SIGINT, Arc::clone(&stop_flag))?);
            sig_ids.push(pipe::register(SIGTERM, write_term)?);
            sig_ids.push(pipe::register(SIGINT, write_int)?);
            Ok(())
        })();

        if let Err(error) = register_result {
            for id in sig_ids {
                unregister(id);
            }
            return Err(AppError::Signal(format!(
                "cannot register SIGTERM/SIGINT handlers: {error}"
            )));
        }

        Ok(Self {
            stop_flag,
            read_end,
            sig_ids,
        })
    }

    pub(crate) fn stop_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.stop_flag)
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.stop_flag.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Block via `rustix::event::poll` until `timeout` elapses or `SIGTERM`/`SIGINT` arrives.
    /// Returns `Ok(true)` if a shutdown signal was received, `Ok(false)` on timeout.
    pub(crate) fn wait_for_stop_or_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<bool, AppError> {
        use std::time::{Duration, Instant};

        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        use rustix::io::Errno;

        let deadline = Instant::now() + timeout;
        let max_slice = Duration::from_secs(3600);
        let mut drain_buf = [0u8; 64];

        loop {
            if self.is_stopped() {
                drain_nonblocking(&mut self.read_end, &mut drain_buf);
                return Ok(true);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            let slice = deadline.saturating_duration_since(now).min(max_slice);
            let ts = Timespec {
                tv_sec: i64::try_from(slice.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(slice.subsec_nanos()),
            };
            let mut poll_fds = [PollFd::new(&self.read_end, PollFlags::IN)];
            match poll(&mut poll_fds, Some(&ts)) {
                Ok(0) => {
                    if self.is_stopped() {
                        drain_nonblocking(&mut self.read_end, &mut drain_buf);
                        return Ok(true);
                    }
                }
                Ok(_) => {
                    drain_nonblocking(&mut self.read_end, &mut drain_buf);
                    if self.is_stopped() {
                        return Ok(true);
                    }
                }
                Err(Errno::INTR) => continue,
                Err(error) => {
                    return Err(AppError::Signal(format!("signal poll failed: {error}")));
                }
            }
        }
    }
}

#[cfg(unix)]
fn drain_nonblocking(stream: &mut std::os::unix::net::UnixStream, buf: &mut [u8]) {
    use std::io::Read;
    loop {
        match stream.read(buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

#[cfg(unix)]
impl Drop for SignalWatcher {
    fn drop(&mut self) {
        for id in self.sig_ids.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

#[cfg(not(unix))]
pub(crate) struct SignalWatcher;

#[cfg(not(unix))]
impl SignalWatcher {
    pub(crate) fn install() -> Result<Self, AppError> {
        Err(AppError::UnsupportedPlatform)
    }

    pub(crate) fn stop_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true))
    }

    pub(crate) fn wait_for_stop_or_timeout(
        &mut self,
        _timeout: std::time::Duration,
    ) -> Result<bool, AppError> {
        Err(AppError::UnsupportedPlatform)
    }
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
            "f15\0nvnode: FD unavailable\0\n",
            "f2774\0npipe: FD unavailable\0\n",
        );

        let snap = parse_lsof_output(sample.as_bytes(), 1234, 9999).unwrap();
        assert_eq!(snap.captured_at_unix, 1234);
        assert_eq!(snap.processes.len(), 1);
        let p = &snap.processes[0];
        assert_eq!(p.pid, 41797);
        assert_eq!(p.comm.as_str(), "Antigravity Helper (Plugin)");
        assert_eq!(
            snap.exe_path(p),
            Some(std::path::Path::new(
                "/Applications/Antigravity.app/Contents/MacOS/Antigravity Helper"
            ))
        );
        assert_eq!(
            snap.cwd(p),
            Some(std::path::Path::new("/Users/dev/Projects/тест\\repo"))
        );
        assert!(snap.open_path_refs(p).iter().any(|&r| {
            snap.path(r)
                == std::path::Path::new("/Users/dev/Projects/repo/target/debug/deps/libmacro.dylib")
        }));
        assert!(
            !snap
                .open_path_refs(p)
                .iter()
                .any(|&r| snap.path(r).to_string_lossy().contains("netsrc"))
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

        let missing_type_unexpected = b"p10\0ccargo\0\nf3\0n/tmp/a\0\n";
        assert!(parse_lsof_output(missing_type_unexpected, 1, 0).is_err());

        // `FD unavailable` on non-numeric special FDs (`cwd`, `txt`) MUST still fail closed!
        let cwd_unavailable = b"p10\0ccargo\0\nfcwd\0nvnode: FD unavailable\0\n";
        assert!(parse_lsof_output(cwd_unavailable, 1, 0).is_err());

        let txt_unavailable = b"p10\0ccargo\0\nftxt\0nvnode: FD unavailable\0\n";
        assert!(parse_lsof_output(txt_unavailable, 1, 0).is_err());

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
        holder.unlock().unwrap();
        drop(holder);

        assert!(matches!(
            platform.try_lock_readonly(&lock_path).unwrap(),
            LockProbe::Acquired(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn signal_watcher_times_out_cleanly_without_signals() {
        let mut watcher = super::SignalWatcher::install().unwrap();
        assert!(!watcher.is_stopped());
        let stopped = watcher
            .wait_for_stop_or_timeout(std::time::Duration::from_millis(20))
            .unwrap();
        assert!(!stopped);
        assert!(!watcher.is_stopped());
    }

    #[test]
    fn lsof_stream_parser_matches_across_arbitrary_chunk_sizes_and_dedups_open_paths() {
        use super::LsofStreamParser;

        // Includes `\x2f` leading slash, spaces, duplicate open REG/DIR paths on same PID,
        // non-kept IPv4/PIPE records, and a final line without a trailing `\n`.
        let sample = concat!(
            "p101\0ccargo\0\n",
            "fcwd\0tDIR\0n\\x2fUsers/dev/repo\0\n",
            "ftxt\0tREG\0n/usr/bin/cargo\0\n",
            "f3\0tREG\0n/Users/dev/repo/target/a\\x20b.o\0\n",
            "f4\0tREG\0n/Users/dev/repo/target/a\\x20b.o\0\n",
            "f5\0tIPv4\0n127.0.0.1:8080->127.0.0.1:50000\0\n",
            "f6\0tDIR\0n/Users/dev/repo/target\0\n",
            "f7\0tDIR\0n/Users/dev/repo/target\0\n",
            "p202\0crust-analyzer\0\n",
            "f3\0tREG\0n/Users/dev/repo/target/a\\x20b.o\0"
        )
        .as_bytes();

        let reference = parse_lsof_output(sample, 1234, 999).unwrap();
        assert_eq!(reference.processes.len(), 2);
        let p0 = &reference.processes[0];
        assert_eq!(p0.pid, 101);
        assert_eq!(
            reference.cwd(p0),
            Some(std::path::Path::new("/Users/dev/repo"))
        );
        assert_eq!(
            reference.exe_path(p0),
            Some(std::path::Path::new("/usr/bin/cargo"))
        );
        // Duplicates on f4 and f7 must be deduplicated per-PID.
        let p0_opens: Vec<&std::path::Path> = reference
            .open_path_refs(p0)
            .iter()
            .map(|&r| reference.path(r))
            .collect();
        assert_eq!(
            p0_opens,
            vec![
                std::path::Path::new("/usr/bin/cargo"),
                std::path::Path::new("/Users/dev/repo/target/a b.o"),
                std::path::Path::new("/Users/dev/repo/target"),
            ]
        );
        // Same path on a DIFFERENT PID (202) must still be recorded AND interned to the exact
        // same `PathRef` in `path_pool` (zero duplicate bytes across PIDs).
        let p1 = &reference.processes[1];
        assert_eq!(p1.pid, 202);
        assert_eq!(reference.open_path_refs(p1).len(), 1);
        assert_eq!(
            reference.open_path_refs(p1)[0],
            reference.open_path_refs(p0)[1]
        );
        assert_eq!(
            reference.path(reference.open_path_refs(p1)[0]),
            std::path::Path::new("/Users/dev/repo/target/a b.o")
        );

        // Feeding 1, 2, 3, 7, 17 bytes at a time (splitting across `\0`, `\n`, `\x20`, `\x2f`)
        // must produce the exact same snapshot.
        for chunk_size in [1usize, 2, 3, 7, 17, 64] {
            let mut parser = LsofStreamParser::new();
            for chunk in sample.chunks(chunk_size) {
                parser.feed(chunk);
            }
            let streamed = parser.finish(1234, 999).unwrap();
            assert_eq!(streamed, reference, "chunk_size={chunk_size} diverged");
        }

        // Malformed escape inside a NON-kept record (e.g. `tIPv4` / `tPIPE`) MUST still fail closed!
        let bad_non_kept = b"p10\0ccargo\0\nf5\0tIPv4\0n/bad\\xZZ\0\n";
        assert!(parse_lsof_output(bad_non_kept, 1, 0).is_err());

        let bad_non_kept_trunc = b"p10\0ccargo\0\nf5\0tPIPE\0n/bad\\\0\n";
        assert!(parse_lsof_output(bad_non_kept_trunc, 1, 0).is_err());
    }

    #[test]
    fn normalize_macos_system_symlinks_cow_borrows_clean_paths_and_rewrites_aliases() {
        use std::borrow::Cow;
        use std::path::Path;

        use super::normalize_macos_system_symlinks_cow;

        let clean = normalize_macos_system_symlinks_cow(Path::new("/Users/dev/repo/target"));
        assert!(matches!(clean, Cow::Borrowed(_)));
        assert_eq!(clean.as_ref(), Path::new("/Users/dev/repo/target"));

        let already_private = normalize_macos_system_symlinks_cow(Path::new("/private/tmp/a"));
        assert!(matches!(already_private, Cow::Borrowed(_)));
        assert_eq!(already_private.as_ref(), Path::new("/private/tmp/a"));

        let tmp = normalize_macos_system_symlinks_cow(Path::new("/tmp/a/b"));
        #[cfg(target_os = "macos")]
        {
            assert!(matches!(tmp, Cow::Owned(_)));
            assert_eq!(tmp.as_ref(), Path::new("/private/tmp/a/b"));

            let var_root = normalize_macos_system_symlinks_cow(Path::new("/var"));
            assert_eq!(var_root.as_ref(), Path::new("/private/var"));

            let etc_file = normalize_macos_system_symlinks_cow(Path::new("/etc/hosts"));
            assert_eq!(etc_file.as_ref(), Path::new("/private/etc/hosts"));
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert!(matches!(tmp, Cow::Borrowed(_)));
            assert_eq!(tmp.as_ref(), Path::new("/tmp/a/b"));
        }

        // Must NOT rewrite lookalike prefixes like `/tmpfoo` or `/variable`.
        let lookalike = normalize_macos_system_symlinks_cow(Path::new("/tmpfoo/bar"));
        assert!(matches!(lookalike, Cow::Borrowed(_)));
        assert_eq!(lookalike.as_ref(), Path::new("/tmpfoo/bar"));
    }
}
