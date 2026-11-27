//! Core zero-I/O domain types for `targetwarden`.
//!
//! Stage 0 defines the CLI value enums used by `cli` and `lib`. Stage 1 expands
//! this module with the full domain model specified in `specs/targetwarden/README.md`
//! (`CargoTarget`, `ProfileDir`, `BuildUnit`, `IncrementalDir`, `SafetyVerdict`,
//! `DiskPressure`, `ReclaimPlan`, `ReclaimAction`, `ActionReceipt`).

use clap::ValueEnum;

/// Output framing selected on the command line or via `TARGETWARDEN_FORMAT`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Scope selector for `targetwarden reclaim --profile`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReclaimProfile {
    /// Surgical intra-target sweep only (`R2` + `R3`).
    SweepOnly,
    /// Full rule set (`R1`–`R5`).
    #[default]
    Full,
}
