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
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};
use crate::error::AppError;

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
        Command::Status => Err(AppError::NotImplemented {
            command: "status",
            stage: "Stage 1",
        }),
        Command::Scan { .. } => Err(AppError::NotImplemented {
            command: "scan",
            stage: "Stage 1",
        }),
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

fn report_parser_error(error: clap::Error) -> ExitCode {
    let code = u8::try_from(error.exit_code()).unwrap_or(2);
    let _ = error.print();
    ExitCode::from(code)
}
