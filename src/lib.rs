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

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::discover::{ScanDetail, ScanRequest, ScanRoot};
use crate::error::AppError;
use crate::platform::{Platform, default_platform};
use crate::state::State;

/// Parse CLI arguments, run the requested command once (or loop in `watch`), and map exit status.
pub fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_parser_error(error),
    };

    let result = dispatch(cli, &mut io::stdout().lock());
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
            let state = load_state_readonly(&home);
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
            let state = load_state_readonly(&home);
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
        Command::Reclaim { .. } => Err(AppError::NotImplemented {
            command: "reclaim",
            stage: "Stage 2",
        }),
        Command::History { .. } => Err(AppError::NotImplemented {
            command: "history",
            stage: "Stage 2",
        }),
        Command::Pin { .. } => Err(AppError::NotImplemented {
            command: "pin",
            stage: "Stage 3",
        }),
        Command::Unpin { .. } => Err(AppError::NotImplemented {
            command: "unpin",
            stage: "Stage 3",
        }),
        Command::Watch { .. } => Err(AppError::NotImplemented {
            command: "watch",
            stage: "Stage 4",
        }),
        Command::Install { .. } => Err(AppError::NotImplemented {
            command: "install",
            stage: "Stage 4",
        }),
        Command::Uninstall => Err(AppError::NotImplemented {
            command: "uninstall",
            stage: "Stage 4",
        }),
    }
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

fn resolve_state_dir(home: &Path) -> PathBuf {
    if let Some(override_dir) = std::env::var_os("TARGETWARDEN_STATE_DIR")
        && !override_dir.is_empty()
    {
        return PathBuf::from(override_dir);
    }
    home.join("Library")
        .join("Application Support")
        .join("targetwarden")
}

/// Read `state.json` strictly read-only without creating files or acquiring `run.lock`.
fn load_state_readonly(home: &Path) -> State {
    let state_path = resolve_state_dir(home).join("state.json");
    let Ok(bytes) = std::fs::read(&state_path) else {
        return State::new_default();
    };
    match serde_json::from_slice::<State>(&bytes) {
        Ok(state) if state.schema_version == model::SCHEMA_VERSION => state,
        Ok(_) | Err(_) => State::new_default(),
    }
}

fn apply_readonly_hold_check(
    state: &State,
    snapshot: &model::ScanSnapshot,
    current_pressure: model::DiskPressure,
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
