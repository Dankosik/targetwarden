use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};
use clap_complete::Shell;

use crate::model::{OutputFormat, ReclaimProfile};

#[derive(Debug, Parser)]
#[command(version, about, arg_required_else_help = true)]
pub(crate) struct Cli {
    /// Output format (precedence: flag, TARGETWARDEN_FORMAT, text)
    #[arg(
        long,
        global = true,
        env = "TARGETWARDEN_FORMAT",
        hide_env_values = true,
        value_enum,
        default_value_t = OutputFormat::Text
    )]
    pub format: OutputFormat,

    /// Optional TOML configuration file path (precedence: flag, TARGETWARDEN_CONFIG)
    #[arg(
        long,
        global = true,
        env = "TARGETWARDEN_CONFIG",
        hide_env_values = true,
        value_name = "PATH"
    )]
    pub config: Option<PathBuf>,

    /// Additional root directories to scan for Cargo target/ directories (repeatable)
    #[arg(
        long = "root",
        global = true,
        action = ArgAction::Append,
        value_name = "PATH"
    )]
    pub roots: Vec<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Show disk pressure, discovered Cargo target/ directories, protection reasons, and totals
    Status,
    /// Perform a read-only discovery scan without writing state or deleting anything
    Scan {
        /// Directories to inspect instead of default development roots
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,
    },
    /// Plan or execute one reclamation pass according to the current policy
    Reclaim {
        /// Print the reclamation plan without modifying any files or state
        #[arg(long)]
        dry_run: bool,
        /// Limit reclamation scope (sweep-only runs R2+R3 only; full runs R1-R5)
        #[arg(long, value_enum, default_value_t = ReclaimProfile::Full)]
        profile: ReclaimProfile,
        /// Bypass an active APFS snapshot ReclaimHoldState circuit breaker for this pass
        #[arg(long)]
        ignore_snapshot_hold: bool,
    },
    /// Run the adaptive background reclamation loop (invoked by the LaunchAgent)
    Watch {
        /// Plan actions on each tick without mutating Cargo target/ directories
        #[arg(long)]
        dry_run: bool,
    },
    /// Protect a project or Cargo target/ directory from eviction (or all cleanup)
    Pin {
        /// Project, worktree, or Cargo target/ path to protect
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Allow intra-target surgical sweep (R2+R3) while blocking full eviction (R1/R4/R5)
        #[arg(long)]
        allow_sweep: bool,
        /// Optional human or agent note stored alongside the pin
        #[arg(long, value_name = "TEXT")]
        note: Option<String>,
    },
    /// Remove protection previously added with `pin`
    Unpin {
        /// Previously pinned project, worktree, or Cargo target/ path
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Show recent entries from the bounded actions.jsonl journal
    History {
        /// Maximum number of recent actions to display
        #[arg(long, default_value_t = 20, value_name = "N")]
        limit: usize,
    },
    /// Install and bootstrap the per-user LaunchAgent running `targetwarden watch`
    Install {
        /// Print the generated LaunchAgent plist and launchctl actions without writing files
        #[arg(long)]
        dry_run: bool,
        /// Configure the LaunchAgent daemon to run `watch --dry-run` (for initial field soak)
        #[arg(long)]
        watch_dry_run: bool,
    },
    /// Bootout and remove the per-user LaunchAgent while keeping state and history
    Uninstall,
    /// Write a shell completion script to stdout
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::{CommandFactory, Parser};

    use super::{Cli, Command};
    use crate::model::{OutputFormat, ReclaimProfile};

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn global_flags_and_subcommands_parse() {
        let cli = Cli::try_parse_from([
            "targetwarden",
            "--format",
            "json",
            "--root",
            "/tmp/a",
            "--root",
            "/tmp/b",
            "reclaim",
            "--dry-run",
            "--profile",
            "sweep-only",
            "--ignore-snapshot-hold",
        ])
        .unwrap();
        assert_eq!(cli.format, OutputFormat::Json);
        assert_eq!(
            cli.roots,
            vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]
        );
        assert!(matches!(
            cli.command,
            Command::Reclaim {
                dry_run: true,
                profile: ReclaimProfile::SweepOnly,
                ignore_snapshot_hold: true,
            }
        ));
    }

    #[test]
    fn invalid_profile_is_rejected() {
        assert!(Cli::try_parse_from(["targetwarden", "reclaim", "--profile", "unsafe"]).is_err());
    }
}
