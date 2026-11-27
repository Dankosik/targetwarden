//! `targetwarden` keeps Cargo `target/` directories bounded safely on macOS.

mod cli;
mod config;
mod discover;
mod error;
mod execute;
mod install;
mod model;
mod platform;
mod pressure;
mod report;
mod rules;
mod safety;
mod state;
mod store;
mod sweep;

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::discover::{ScanDetail, ScanRequest, ScanRoot};
use crate::error::AppError;
use crate::model::{ActionOutcome, DiskPressure, PinScope, PlanMode, ReclaimProfile};
use crate::platform::{DEFAULT_VOLUME_MOUNT, Platform, SignalWatcher, default_platform};
use crate::state::State;
use crate::store::{CLI_RUN_LOCK_RETRY_TIMEOUT, StateCache};

const EXIT_PARTIAL: u8 = 3;
const WATCH_CALM_INTERVAL: Duration = Duration::from_secs(180);
const WATCH_PRESSURE_INTERVAL: Duration = Duration::from_secs(60);
const WATCH_FULL_WALK_TTL_SECS: u64 = 10 * 60;

/// Parse CLI arguments, run the requested command once (or loop in `watch`), and map exit status.
pub fn run() -> ExitCode {
    // Bare `targetwarden watch` skips `clap` and `stdout` locking (~2-5 MiB RSS).
    if is_bare_watch_invocation() {
        return map_exit_result(run_watch_command(None, &[], false));
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_parser_error(error),
    };

    let result = match cli.command {
        Command::Watch { dry_run } => run_watch_command(cli.config.as_deref(), &cli.roots, dry_run),
        command => {
            let mut stdout = io::stdout().lock();
            dispatch(
                Cli {
                    format: cli.format,
                    config: cli.config,
                    roots: cli.roots,
                    command,
                },
                &mut stdout,
            )
        }
    };
    map_exit_result(result)
}

fn is_bare_watch_invocation() -> bool {
    let mut args = std::env::args_os();
    let _exe = args.next();
    let Some(first) = args.next() else {
        return false;
    };
    first == OsStr::new("watch")
        && args.next().is_none()
        && std::env::var_os("TARGETWARDEN_FORMAT").is_none()
        && std::env::var_os("TARGETWARDEN_CONFIG").is_none()
}

fn map_exit_result(result: Result<ExitCode, AppError>) -> ExitCode {
    match result {
        Ok(code) => code,
        Err(error) if error.is_stdout_closed() => ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {}", error::diagnostic(&error));
            let _ = stderr.flush();
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli, stdout: &mut impl Write) -> Result<ExitCode, AppError> {
    match cli.command {
        Command::Completions { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_owned();
            let mut bytes = Vec::new();
            clap_complete::generate(shell, &mut command, name, &mut bytes);
            stdout.write_all(&bytes).map_err(AppError::Output)?;
            stdout.flush().map_err(AppError::Output)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Status => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            let home = resolve_home()?;
            let config = Config::load(cli.config.as_deref(), &home)?;
            let state_dir = store::resolve_state_dir(&home);
            let state = store::load_state_readonly(&state_dir);
            let cargo_target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
            let roots = discover::build_default_scan_roots(
                &home,
                &config,
                &cli.roots,
                cargo_target_dir.as_deref(),
            )?;
            let known: Vec<PathBuf> = state.known_targets.keys().cloned().collect();
            let req = ScanRequest::with_default_volume(roots, known, true, ScanDetail::Inventory);
            let snapshot = discover::scan(&platform, &config, &req)?;
            let current_pressure = pressure::evaluate_pressure(
                state.pressure,
                snapshot.disk.free_bytes,
                &config.pressure,
            );
            let effective_state =
                apply_readonly_hold_check(&state, &snapshot, current_pressure, &config);
            let verdicts = safety::evaluate_all(
                &snapshot,
                &effective_state,
                &config,
                current_pressure,
                false,
            );
            report::write_inventory_report(
                "status",
                &snapshot,
                &verdicts,
                current_pressure,
                &effective_state,
                cli.format,
                stdout,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Scan { paths } => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            let home = resolve_home()?;
            let config = Config::load(cli.config.as_deref(), &home)?;
            let state_dir = store::resolve_state_dir(&home);
            let state = store::load_state_readonly(&state_dir);
            let roots = if paths.is_empty() {
                let cargo_target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
                discover::build_default_scan_roots(
                    &home,
                    &config,
                    &cli.roots,
                    cargo_target_dir.as_deref(),
                )?
            } else {
                let mut explicit = Vec::with_capacity(paths.len());
                for path in paths {
                    if !path.exists() {
                        return Err(AppError::InvalidPath {
                            path,
                            message: "scan path does not exist".to_owned(),
                        });
                    }
                    explicit.push(ScanRoot {
                        path,
                        max_depth: config.discovery.explicit_max_depth,
                        explicit: true,
                    });
                }
                explicit
            };
            let req = ScanRequest::with_default_volume(roots, vec![], true, ScanDetail::Inventory);
            let snapshot = discover::scan(&platform, &config, &req)?;
            let current_pressure = pressure::evaluate_pressure(
                state.pressure,
                snapshot.disk.free_bytes,
                &config.pressure,
            );
            let effective_state =
                apply_readonly_hold_check(&state, &snapshot, current_pressure, &config);
            let verdicts = safety::evaluate_all(
                &snapshot,
                &effective_state,
                &config,
                current_pressure,
                false,
            );
            report::write_inventory_report(
                "scan",
                &snapshot,
                &verdicts,
                current_pressure,
                &effective_state,
                cli.format,
                stdout,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Reclaim {
            dry_run,
            profile,
            ignore_snapshot_hold,
        } => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            let home = resolve_home()?;
            let config = Config::load(cli.config.as_deref(), &home)?;
            let state_dir = store::resolve_state_dir(&home);

            let _run_lock = if dry_run {
                None
            } else {
                Some(store::acquire_run_lock(
                    &state_dir,
                    CLI_RUN_LOCK_RETRY_TIMEOUT,
                )?)
            };

            let mut state_cache = StateCache::new(state_dir.clone());
            let mut state = if dry_run {
                store::load_state_readonly(&state_dir)
            } else {
                state_cache.load()?
            };

            let cargo_target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
            let roots = discover::build_default_scan_roots(
                &home,
                &config,
                &cli.roots,
                cargo_target_dir.as_deref(),
            )?;
            let known: Vec<PathBuf> = state.known_targets.keys().cloned().collect();
            let req = ScanRequest::with_default_volume(roots, known, true, ScanDetail::Full);
            let snapshot = discover::scan(&platform, &config, &req)?;

            if snapshot.processes.is_none() {
                let detail = snapshot.process_snapshot_error.unwrap_or_else(|| {
                    "lsof process snapshot unavailable; refusing all mutations".to_owned()
                });
                return Err(AppError::ProcessSnapshot(detail));
            }
            if !snapshot.mount_table_available {
                let detail = snapshot.mount_table_error.unwrap_or_else(|| {
                    "mount table unavailable; refusing all mutations".to_owned()
                });
                return Err(AppError::MountTable(detail));
            }

            let current_pressure = pressure::evaluate_pressure(
                state.pressure,
                snapshot.disk.free_bytes,
                &config.pressure,
            );
            if let Some(hold) = &state.reclaim_hold
                && pressure::check_hold_reset(
                    hold,
                    &snapshot.disk,
                    current_pressure,
                    snapshot.captured_at_unix,
                    &config.reclaim_hold,
                )
                .is_some()
            {
                state.reclaim_hold = None;
            }

            let verdicts = safety::evaluate_all(
                &snapshot,
                &state,
                &config,
                current_pressure,
                ignore_snapshot_hold,
            );
            let mode = PlanMode {
                profile,
                ignore_snapshot_hold,
            };
            let mut plan = rules::plan(
                &snapshot,
                &verdicts,
                &state,
                &config,
                current_pressure,
                mode,
            );
            let r5_target = rules::r5_headroom_target(current_pressure, &config);
            let exec = execute::execute_plan(
                &plan,
                &platform,
                dry_run,
                r5_target,
                |reclaimed, gain| {
                    pressure::should_trigger_hold(reclaimed, gain, &config.reclaim_hold)
                },
                None,
            );

            if !dry_run {
                state.pressure = current_pressure;
                if let Some(hold) = exec.triggered_hold {
                    plan.hold_active = true;
                    state.reclaim_hold = Some(hold);
                }
                state.record_scan_targets(
                    &snapshot.targets,
                    snapshot.captured_at_unix,
                    true,
                    snapshot.walk_partial,
                );
                state.apply_receipts(&exec.receipts);
                store::append_receipts(&state_dir, &exec.receipts)?;
                state_cache.save(&state)?;
            }

            report::write_reclaim_report(&plan, &exec.receipts, dry_run, cli.format, stdout)?;

            let any_failed = exec
                .receipts
                .iter()
                .any(|r| matches!(r.outcome, ActionOutcome::Failed { .. }));
            if any_failed {
                Ok(ExitCode::from(EXIT_PARTIAL))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        Command::History { limit } => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            let home = resolve_home()?;
            let state_dir = store::resolve_state_dir(&home);
            let receipts = store::read_recent_receipts(&state_dir, limit)?;
            report::write_history_report(&receipts, cli.format, stdout)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Pin {
            path,
            allow_sweep,
            note,
        } => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            if !path.exists() {
                return Err(AppError::InvalidPath {
                    path,
                    message: "path to pin does not exist".to_owned(),
                });
            }
            let canonical =
                std::fs::canonicalize(&path).map_err(|error| AppError::InvalidPath {
                    path: path.clone(),
                    message: format!("cannot resolve path: {error}"),
                })?;
            let home = resolve_home()?;
            let state_dir = store::resolve_state_dir(&home);
            let _run_lock = store::acquire_run_lock(&state_dir, CLI_RUN_LOCK_RETRY_TIMEOUT)?;
            let mut state_cache = StateCache::new(state_dir);
            let mut state = state_cache.load()?;
            let scope = if allow_sweep {
                PinScope::AllowSweep
            } else {
                PinScope::Full
            };
            state.add_pin(canonical.clone(), scope, note.clone(), platform.now_unix());
            state_cache.save(&state)?;
            report::write_pin_report(&canonical, scope, note.as_deref(), cli.format, stdout)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Unpin { path } => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            let normalized = platform::normalize_macos_system_symlinks(&path);
            let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| normalized.clone());
            let home = resolve_home()?;
            let state_dir = store::resolve_state_dir(&home);
            let _run_lock = store::acquire_run_lock(&state_dir, CLI_RUN_LOCK_RETRY_TIMEOUT)?;
            let mut state_cache = StateCache::new(state_dir);
            let mut state = state_cache.load()?;
            let removed = state.remove_pin(&canonical)
                || state.remove_pin(&normalized)
                || state.remove_pin(&path);
            if removed {
                state_cache.save(&state)?;
            }
            report::write_unpin_report(&canonical, removed, cli.format, stdout)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Watch { dry_run } => run_watch_command(cli.config.as_deref(), &cli.roots, dry_run),
        Command::Install { dry_run } => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            let home = resolve_home()?;
            let exe_raw = std::env::current_exe().map_err(|error| AppError::InvalidPath {
                path: PathBuf::from("targetwarden"),
                message: format!("cannot resolve current executable path: {error}"),
            })?;
            let exe = std::fs::canonicalize(&exe_raw).unwrap_or(exe_raw);
            let outcome = install::install(&exe, &home, dry_run, &platform)?;
            report::write_install_report(
                outcome.label,
                &outcome.domain,
                &outcome.plist_path,
                &outcome.log_path,
                &outcome.plist_xml,
                &outcome.launchctl_actions,
                dry_run,
                cli.format,
                stdout,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Uninstall => {
            let platform = default_platform();
            ensure_non_root(&platform)?;
            let home = resolve_home()?;
            let outcome = install::uninstall(&home, &platform)?;
            report::write_uninstall_report(
                outcome.label,
                &outcome.domain,
                &outcome.plist_path,
                outcome.removed_plist,
                outcome.booted_out,
                cli.format,
                stdout,
            )?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_watch_command(
    config_path: Option<&Path>,
    cli_roots: &[PathBuf],
    dry_run: bool,
) -> Result<ExitCode, AppError> {
    let platform = default_platform();
    ensure_non_root(&platform)?;
    let home = resolve_home()?;
    let config = Config::load(config_path, &home)?;
    let state_dir = store::resolve_state_dir(&home);
    let cargo_target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
    let mut signals = SignalWatcher::install()?;
    let stop_flag = signals.stop_flag();
    let mut stderr = io::stderr();

    run_watch_loop(
        &platform,
        &home,
        &config,
        cli_roots,
        cargo_target_dir.as_deref(),
        dry_run,
        &state_dir,
        &stop_flag,
        |dur| signals.wait_for_stop_or_timeout(dur),
        None,
        &mut stderr,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_watch_loop<P, W>(
    platform: &P,
    home: &Path,
    config: &Config,
    cli_roots: &[PathBuf],
    cargo_target_dir: Option<&Path>,
    dry_run: bool,
    state_dir: &Path,
    stop_flag: &AtomicBool,
    mut wait_next: W,
    max_ticks: Option<usize>,
    stderr: &mut impl Write,
) -> Result<ExitCode, AppError>
where
    P: Platform + Sync,
    W: FnMut(Duration) -> Result<bool, AppError>,
{
    let _watch_lock = store::acquire_watch_lock(state_dir)?;
    let mut state_cache = StateCache::new(state_dir.to_path_buf());
    let mut last_pressure = DiskPressure::Calm;
    let mut tick_index: usize = 0;

    loop {
        if stop_flag.load(Ordering::Acquire) {
            break;
        }

        // First tick fails immediately with `RunLockBusy` if another command holds `run.lock`;
        // subsequent ticks skip cleanly if a CLI `pin`/`unpin`/`reclaim` is briefly active.
        let run_lock = match store::acquire_run_lock(state_dir, Duration::ZERO) {
            Ok(guard) => guard,
            Err(AppError::RunLockBusy) if tick_index == 0 => return Err(AppError::RunLockBusy),
            Err(error) => {
                log_watch_warning(stderr, &error::diagnostic(&error));
                tick_index = tick_index.saturating_add(1);
                if max_ticks.is_some_and(|max| tick_index >= max)
                    || wait_next(watch_sleep_interval(last_pressure))?
                {
                    break;
                }
                continue;
            }
        };

        let (mut state, recovery_diag) = state_cache.load_or_recover();
        if let Some(diag) = recovery_diag {
            log_watch_warning(
                stderr,
                &format!(
                    "state.json recovery (starting cleanly): {}",
                    error::sanitize_terminal_text(&diag)
                ),
            );
        }

        let volume_mount = default_volume_mount();
        match platform.free_bytes(&volume_mount) {
            Ok(probe_free_bytes) => {
                let probe_pressure =
                    pressure::evaluate_pressure(state.pressure, probe_free_bytes, &config.pressure);
                let entered_high =
                    state.pressure < DiskPressure::High && probe_pressure >= DiskPressure::High;
                let full_walk = should_run_full_walk(&state, platform.now_unix(), entered_high);

                let roots_res = if full_walk {
                    discover::build_default_scan_roots(home, config, cli_roots, cargo_target_dir)
                } else {
                    Ok(Vec::new())
                };
                match roots_res {
                    Ok(roots) => {
                        let known: Vec<PathBuf> = state.known_targets.keys().cloned().collect();
                        let req = ScanRequest {
                            roots,
                            known_targets: known,
                            full_walk,
                            detail: ScanDetail::Full,
                            volume_mount,
                        };
                        match discover::scan(platform, config, &req) {
                            Ok(snapshot) => {
                                if snapshot.processes.is_none() || !snapshot.mount_table_available {
                                    let reason = snapshot
                                        .process_snapshot_error
                                        .or(snapshot.mount_table_error)
                                        .unwrap_or_else(|| {
                                            "process or mount probe unavailable".to_owned()
                                        });
                                    log_watch_warning(
                                        stderr,
                                        &format!(
                                            "skipping tick (fail-closed): {}",
                                            error::sanitize_terminal_text(&reason)
                                        ),
                                    );
                                } else {
                                    let current_pressure = pressure::evaluate_pressure(
                                        state.pressure,
                                        snapshot.disk.free_bytes,
                                        &config.pressure,
                                    );
                                    last_pressure = current_pressure;

                                    if let Some(hold) = &state.reclaim_hold
                                        && pressure::check_hold_reset(
                                            hold,
                                            &snapshot.disk,
                                            current_pressure,
                                            snapshot.captured_at_unix,
                                            &config.reclaim_hold,
                                        )
                                        .is_some()
                                    {
                                        state.reclaim_hold = None;
                                    }

                                    let verdicts = safety::evaluate_all(
                                        &snapshot,
                                        &state,
                                        config,
                                        current_pressure,
                                        false,
                                    );
                                    let mode = PlanMode {
                                        profile: ReclaimProfile::Full,
                                        ignore_snapshot_hold: false,
                                    };
                                    let plan = rules::plan(
                                        &snapshot,
                                        &verdicts,
                                        &state,
                                        config,
                                        current_pressure,
                                        mode,
                                    );
                                    let r5_target =
                                        rules::r5_headroom_target(current_pressure, config);
                                    let exec = execute::execute_plan(
                                        &plan,
                                        platform,
                                        dry_run,
                                        r5_target,
                                        |reclaimed, gain| {
                                            pressure::should_trigger_hold(
                                                reclaimed,
                                                gain,
                                                &config.reclaim_hold,
                                            )
                                        },
                                        Some(stop_flag),
                                    );

                                    state.pressure = current_pressure;
                                    if !dry_run && let Some(hold) = exec.triggered_hold {
                                        state.reclaim_hold = Some(hold);
                                    }
                                    state.record_scan_targets(
                                        &snapshot.targets,
                                        snapshot.captured_at_unix,
                                        full_walk,
                                        snapshot.walk_partial,
                                    );
                                    state.apply_receipts(&exec.receipts);

                                    if let Err(error) =
                                        store::append_receipts(state_dir, &exec.receipts)
                                    {
                                        log_watch_warning(stderr, &error::diagnostic(&error));
                                    }
                                    if let Err(error) = state_cache.save(&state) {
                                        log_watch_warning(stderr, &error::diagnostic(&error));
                                    }
                                }
                            }
                            Err(error) => log_watch_warning(stderr, &error::diagnostic(&error)),
                        }
                    }
                    Err(error) => log_watch_warning(stderr, &error::diagnostic(&error)),
                }
            }
            Err(error) => log_watch_warning(stderr, &error::diagnostic(&error)),
        }

        // Release `run.lock` before sleeping so interactive `pin`/`unpin`/`reclaim` succeed.
        drop(run_lock);

        tick_index = tick_index.saturating_add(1);
        if max_ticks.is_some_and(|max| tick_index >= max) || stop_flag.load(Ordering::Acquire) {
            break;
        }
        if wait_next(watch_sleep_interval(last_pressure))? {
            break;
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn watch_sleep_interval(pressure: DiskPressure) -> Duration {
    match pressure {
        DiskPressure::Calm | DiskPressure::Elevated => WATCH_CALM_INTERVAL,
        DiskPressure::High | DiskPressure::Critical => WATCH_PRESSURE_INTERVAL,
    }
}

fn should_run_full_walk(state: &State, now_unix: u64, entered_high: bool) -> bool {
    entered_high
        || state
            .last_full_walk_unix
            .is_none_or(|last| now_unix.saturating_sub(last) >= WATCH_FULL_WALK_TTL_SECS)
}

fn default_volume_mount() -> PathBuf {
    if Path::new(DEFAULT_VOLUME_MOUNT).exists() {
        PathBuf::from(DEFAULT_VOLUME_MOUNT)
    } else {
        PathBuf::from("/")
    }
}

fn log_watch_warning(stderr: &mut impl Write, message: &str) {
    let _ = writeln!(stderr, "warning: {message}");
    let _ = stderr.flush();
}

fn ensure_non_root(platform: &impl Platform) -> Result<(), AppError> {
    if platform.euid()? == 0 {
        return Err(AppError::RunningAsRoot);
    }
    Ok(())
}

fn resolve_home() -> Result<PathBuf, AppError> {
    std::env::var_os("HOME")
        .filter(|val| !val.is_empty())
        .map(PathBuf::from)
        .ok_or(AppError::HomeUnavailable)
}

fn apply_readonly_hold_check(
    state: &State,
    snapshot: &model::ScanSnapshot,
    current_pressure: DiskPressure,
    config: &Config,
) -> State {
    let mut effective = state.clone();
    if let Some(hold) = &effective.reclaim_hold
        && pressure::check_hold_reset(
            hold,
            &snapshot.disk,
            current_pressure,
            snapshot.captured_at_unix,
            &config.reclaim_hold,
        )
        .is_some()
    {
        effective.reclaim_hold = None;
    }
    effective
}

fn report_parser_error(error: clap::Error) -> ExitCode {
    let code = u8::try_from(error.exit_code()).unwrap_or(2);
    let _ = error.print();
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use compact_str::CompactString;

    use super::{
        WATCH_CALM_INTERVAL, WATCH_PRESSURE_INTERVAL, run_watch_loop, should_run_full_walk,
        watch_sleep_interval,
    };
    use crate::config::Config;
    use crate::error::AppError;
    use crate::model::{DiskPressure, DiskStats, GIB, MountEntry, ProcessSnapshot};
    use crate::platform::{CommandOutput, LockProbe, Platform};
    use crate::state::State;
    use crate::store::StateCache;

    struct WatchTestPlatform {
        now: AtomicU64,
        free_bytes: AtomicU64,
    }

    impl Platform for WatchTestPlatform {
        fn euid(&self) -> Result<u32, AppError> {
            Ok(501)
        }
        fn now_unix(&self) -> u64 {
            self.now.load(Ordering::Relaxed)
        }
        fn disk_stats(&self, volume: &Path) -> Result<DiskStats, AppError> {
            Ok(DiskStats {
                mount: volume.to_path_buf(),
                total_bytes: 460 * GIB,
                free_bytes: self.free_bytes.load(Ordering::Relaxed),
                local_snapshots: Some(vec![]),
            })
        }
        fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
            Ok(ProcessSnapshot {
                captured_at_unix: self.now.load(Ordering::Relaxed),
                self_pid: std::process::id(),
                processes: vec![],
            })
        }
        fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
            Ok(vec![MountEntry {
                source: CompactString::new("/dev/disk3s5"),
                mount_point: PathBuf::from("/"),
                fstype: CompactString::new("apfs"),
            }])
        }
        fn run_git(&self, _cwd: &Path, _args: &[&str]) -> Result<CommandOutput, AppError> {
            Err(AppError::CommandFailed {
                program: "git",
                message: "unused".to_owned(),
            })
        }
        fn try_lock_readonly(&self, _path: &Path) -> Result<LockProbe, AppError> {
            Ok(LockProbe::NotFound)
        }
        fn run_launchctl(&self, _args: &[&str]) -> Result<CommandOutput, AppError> {
            Err(AppError::CommandFailed {
                program: "launchctl",
                message: "unused".to_owned(),
            })
        }
    }

    fn create_target_dir(dir: &Path) {
        fs::create_dir_all(dir.join("debug/build/demo/1111111111111111/fingerprint")).unwrap();
        fs::write(
            dir.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# Created by cargo.\n",
        )
        .unwrap();
        fs::write(
            dir.join("debug/build/demo/1111111111111111/fingerprint/bin-demo.json"),
            r#"{"rustc":42,"deps":[]}"#,
        )
        .unwrap();
    }

    #[test]
    fn watch_loop_caches_roots_for_10m_adapts_interval_and_recovers_corrupt_state() {
        assert_eq!(
            watch_sleep_interval(DiskPressure::Calm),
            WATCH_CALM_INTERVAL
        );
        assert_eq!(
            watch_sleep_interval(DiskPressure::Elevated),
            WATCH_CALM_INTERVAL
        );
        assert_eq!(
            watch_sleep_interval(DiskPressure::High),
            WATCH_PRESSURE_INTERVAL
        );
        assert_eq!(
            watch_sleep_interval(DiskPressure::Critical),
            WATCH_PRESSURE_INTERVAL
        );

        let mut st = State::new_default();
        assert!(should_run_full_walk(&st, 1000, false));
        st.last_full_walk_unix = Some(1000);
        assert!(!should_run_full_walk(&st, 1300, false));
        assert!(should_run_full_walk(&st, 1300, true));
        assert!(should_run_full_walk(&st, 1600, false));

        let tmp = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(tmp.path()).unwrap();
        let state_dir = home.join("state");
        let target_a = home.join("Projects/app_a/target");
        let target_b = home.join("Projects/app_b/target");
        create_target_dir(&target_a);

        // Corrupt state.json before tick 1: watch must log diagnostic to stderr and recover cleanly!
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("state.json"), b"{corrupt json").unwrap();

        let platform = WatchTestPlatform {
            now: AtomicU64::new(1_900_000_000),
            free_bytes: AtomicU64::new(100 * GIB),
        };
        let cfg = Config::default();
        let stop = AtomicBool::new(false);
        let mut sleeps: Vec<Duration> = Vec::new();
        let mut stderr_buf: Vec<u8> = Vec::new();
        let mut pass = 0usize;

        let code = run_watch_loop(
            &platform,
            &home,
            &cfg,
            &[],
            None,
            true,
            &state_dir,
            &stop,
            |dur| {
                sleeps.push(dur);
                pass += 1;
                match pass {
                    1 => {
                        // After tick 1 (full walk discovered app_a): add app_b and advance only 180s (< 600s).
                        create_target_dir(&target_b);
                        platform.now.fetch_add(180, Ordering::Relaxed);
                        // Verify tick 1 cached only app_a.
                        let mut c = StateCache::new(state_dir.clone());
                        let s = c.load().unwrap();
                        assert_eq!(s.known_targets.len(), 1);
                    }
                    2 => {
                        // After tick 2 (cached walk only): app_b must NOT have been discovered yet!
                        let mut c = StateCache::new(state_dir.clone());
                        let s = c.load().unwrap();
                        assert_eq!(s.known_targets.len(), 1);
                        // Now drop free space to 40 GiB (enter High pressure -> must force full_walk & 60s sleep!).
                        platform.free_bytes.store(40 * GIB, Ordering::Relaxed);
                        platform.now.fetch_add(180, Ordering::Relaxed);
                    }
                    3 => {
                        // After tick 3 (entered High -> forced full_walk): app_b discovered and sleep dropped to 60s!
                        platform.now.fetch_add(60, Ordering::Relaxed);
                    }
                    _ => {}
                }
                Ok(false)
            },
            Some(4),
            &mut stderr_buf,
        )
        .unwrap();

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            sleeps,
            vec![
                WATCH_CALM_INTERVAL,
                WATCH_CALM_INTERVAL,
                WATCH_PRESSURE_INTERVAL,
            ]
        );
        let stderr_text = String::from_utf8(stderr_buf).unwrap();
        assert!(stderr_text.contains("state.json recovery"));

        let mut cache = StateCache::new(state_dir);
        let final_state = cache.load().unwrap();
        assert_eq!(final_state.pressure, DiskPressure::High);
        assert_eq!(final_state.known_targets.len(), 2);
    }
}
