//! Functional Core (Layer 2): pure text (GiB) and `schema_version = 1` JSON formatter.
//!
//! Allowed dependencies: `model`, `state`, `config`, `error`. Must never depend on
//! `discover`, `execute`, or `platform`.

use std::io::{BufWriter, Write};
use std::path::PathBuf;

use serde::Serialize;

use crate::error::{AppError, sanitize_terminal_text};
use crate::model::{
    ActionOutcome, ActionReceipt, CargoTarget, DiskPressure, OutputFormat, PinScope,
    ProtectedReason, ReclaimHoldState, ReclaimPlan, RuleId, SCHEMA_VERSION, SafetyVerdict,
    ScanSnapshot, SweepOnlyReason, TargetLayout, TargetOrigin, WorktreeKind, bytes_to_gib,
};
use crate::state::State;

#[derive(Serialize)]
struct DiskReport<'a> {
    mount: &'a std::path::Path,
    total_bytes: u64,
    free_bytes: u64,
    total_gib: f64,
    free_gib: f64,
    local_snapshots: Option<&'a [compact_str::CompactString]>,
}

#[derive(Serialize)]
struct TotalsReport {
    target_count: usize,
    eligible_count: usize,
    sweep_only_count: usize,
    protected_count: usize,
    allocated_bytes: u64,
    allocated_gib: f64,
    v2_units: usize,
    v1_units: usize,
    incremental_dirs: usize,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ReasonReport<'a> {
    Protected(&'a ProtectedReason),
    SweepOnly(&'a SweepOnlyReason),
}

#[derive(Serialize)]
struct TargetReport<'a> {
    root: &'a std::path::Path,
    origin: TargetOrigin,
    layout: TargetLayout,
    worktree_kind: WorktreeKind,
    allocated_bytes: u64,
    allocated_gib: f64,
    last_activity_unix: u64,
    age_secs: u64,
    profile_count: usize,
    v2_unit_count: usize,
    v1_unit_count: usize,
    incremental_dir_count: usize,
    has_doc_dir: bool,
    nested_target_roots: &'a [PathBuf],
    verdict: &'static str,
    reasons: Vec<ReasonReport<'a>>,
}

#[derive(Serialize)]
struct StatusJsonReport<'a> {
    schema_version: u32,
    command: &'static str,
    captured_at_unix: u64,
    disk: DiskReport<'a>,
    pressure: DiskPressure,
    hold_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reclaim_hold: Option<&'a ReclaimHoldState>,
    walk_partial: bool,
    scanned_roots: &'a [PathBuf],
    totals: TotalsReport,
    targets: Vec<TargetReport<'a>>,
}

/// Format read-only `status` or `scan` results into `out`.
pub(crate) fn write_inventory_report(
    command: &'static str,
    snapshot: &ScanSnapshot,
    verdicts: &[SafetyVerdict],
    pressure: DiskPressure,
    state: &State,
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<(), AppError> {
    let mut order: Vec<usize> = (0..snapshot.targets.len()).collect();
    order.sort_by(|&a, &b| {
        snapshot.targets[b]
            .allocated_bytes
            .cmp(&snapshot.targets[a].allocated_bytes)
            .then_with(|| snapshot.targets[a].root.cmp(&snapshot.targets[b].root))
    });

    let mut totals = TotalsReport {
        target_count: snapshot.targets.len(),
        eligible_count: 0,
        sweep_only_count: 0,
        protected_count: 0,
        allocated_bytes: 0,
        allocated_gib: 0.0,
        v2_units: 0,
        v1_units: 0,
        incremental_dirs: 0,
    };

    let build_json_reports = matches!(format, OutputFormat::Json);
    let mut target_reports = if build_json_reports {
        Vec::with_capacity(snapshot.targets.len())
    } else {
        Vec::new()
    };
    for &idx in &order {
        let target = &snapshot.targets[idx];
        let verdict = &verdicts[idx];
        let v2_count: usize = target.profiles.iter().map(|p| p.v2_unit_count).sum();
        let v1_count: usize = target.profiles.iter().map(|p| p.v1_unit_count).sum();
        let inc_count: usize = target
            .profiles
            .iter()
            .map(|p| p.incremental_dir_count)
            .sum();

        totals.allocated_bytes = totals
            .allocated_bytes
            .saturating_add(target.allocated_bytes);
        totals.v2_units = totals.v2_units.saturating_add(v2_count);
        totals.v1_units = totals.v1_units.saturating_add(v1_count);
        totals.incremental_dirs = totals.incremental_dirs.saturating_add(inc_count);

        match verdict {
            SafetyVerdict::Eligible => totals.eligible_count += 1,
            SafetyVerdict::SweepOnly { .. } => totals.sweep_only_count += 1,
            SafetyVerdict::Protected(_) => totals.protected_count += 1,
        }

        if build_json_reports {
            let (verdict_label, reasons) = match verdict {
                SafetyVerdict::Eligible => ("eligible", Vec::new()),
                SafetyVerdict::SweepOnly { reasons, .. } => (
                    "sweep_only",
                    reasons.iter().map(ReasonReport::SweepOnly).collect(),
                ),
                SafetyVerdict::Protected(reasons) => (
                    "protected",
                    reasons.iter().map(ReasonReport::Protected).collect(),
                ),
            };
            target_reports.push(TargetReport {
                root: &target.root,
                origin: target.origin,
                layout: target.layout,
                worktree_kind: target.worktree_kind,
                allocated_bytes: target.allocated_bytes,
                allocated_gib: round2(bytes_to_gib(target.allocated_bytes)),
                last_activity_unix: target.last_activity_unix,
                age_secs: snapshot
                    .captured_at_unix
                    .saturating_sub(target.last_activity_unix),
                profile_count: target.profiles.len(),
                v2_unit_count: v2_count,
                v1_unit_count: v1_count,
                incremental_dir_count: inc_count,
                has_doc_dir: target.doc_dir.is_some(),
                nested_target_roots: &target.nested_target_roots,
                verdict: verdict_label,
                reasons,
            });
        }
    }
    totals.allocated_gib = round2(bytes_to_gib(totals.allocated_bytes));

    match format {
        OutputFormat::Json => {
            let report = StatusJsonReport {
                schema_version: SCHEMA_VERSION,
                command,
                captured_at_unix: snapshot.captured_at_unix,
                disk: DiskReport {
                    mount: &snapshot.disk.mount,
                    total_bytes: snapshot.disk.total_bytes,
                    free_bytes: snapshot.disk.free_bytes,
                    total_gib: round2(bytes_to_gib(snapshot.disk.total_bytes)),
                    free_gib: round2(bytes_to_gib(snapshot.disk.free_bytes)),
                    local_snapshots: snapshot.disk.local_snapshots.as_deref(),
                },
                pressure,
                hold_active: state.reclaim_hold.is_some(),
                reclaim_hold: state.reclaim_hold.as_ref(),
                walk_partial: snapshot.walk_partial,
                scanned_roots: &snapshot.scanned_roots,
                totals,
                targets: target_reports,
            };
            write_json_line(&report, out)?;
        }
        OutputFormat::Text => {
            let mut buf = BufWriter::new(out);
            write_inventory_text(
                snapshot, &order, verdicts, pressure, state, &totals, &mut buf,
            )?;
        }
    }
    Ok(())
}

fn write_json_line<T: Serialize>(value: &T, out: &mut impl Write) -> Result<(), AppError> {
    let mut buf = BufWriter::new(out);
    serde_json::to_writer(&mut buf, value).map_err(|error| {
        if error.is_io() {
            AppError::Output(std::io::Error::from(error))
        } else {
            AppError::Output(std::io::Error::other(error))
        }
    })?;
    buf.write_all(b"\n").map_err(AppError::Output)?;
    buf.flush().map_err(AppError::Output)?;
    Ok(())
}

fn write_inventory_text(
    snapshot: &ScanSnapshot,
    order: &[usize],
    verdicts: &[SafetyVerdict],
    pressure: DiskPressure,
    state: &State,
    totals: &TotalsReport,
    out: &mut impl Write,
) -> Result<(), AppError> {
    let snap_label = match &snapshot.disk.local_snapshots {
        Some(list) => format!("{} local snapshots", list.len()),
        None => "local snapshots unavailable".to_owned(),
    };
    writeln!(
        out,
        "Volume: {}  Free: {:.2} / {:.2} GiB  Pressure: {}  ({})",
        sanitize_terminal_text(&snapshot.disk.mount.to_string_lossy()),
        bytes_to_gib(snapshot.disk.free_bytes),
        bytes_to_gib(snapshot.disk.total_bytes),
        pressure_label(pressure),
        snap_label,
    )
    .map_err(AppError::Output)?;

    if state.reclaim_hold.is_some() {
        writeln!(
            out,
            "APFS Hold: active (R5 paused until snapshots release or reset condition triggers)"
        )
        .map_err(AppError::Output)?;
    }
    if snapshot.walk_partial {
        writeln!(
            out,
            "Warning: discovery hit traversal budget; cached known_targets preserved"
        )
        .map_err(AppError::Output)?;
    }

    writeln!(
        out,
        "Targets: {} ({:.2} GiB total | {} eligible, {} sweep-only, {} protected | {} V2 units, {} V1 units, {} incremental dirs)",
        totals.target_count,
        bytes_to_gib(totals.allocated_bytes),
        totals.eligible_count,
        totals.sweep_only_count,
        totals.protected_count,
        totals.v2_units,
        totals.v1_units,
        totals.incremental_dirs,
    )
    .map_err(AppError::Output)?;

    if !order.is_empty() {
        writeln!(out).map_err(AppError::Output)?;
        writeln!(
            out,
            "{:>9}  {:<13}  {:<10}  {:<28}  PATH",
            "SIZE", "LAYOUT", "VERDICT", "REASON"
        )
        .map_err(AppError::Output)?;
        for &idx in order {
            let target = &snapshot.targets[idx];
            let verdict = &verdicts[idx];
            writeln!(
                out,
                "{:>6.2} GiB  {:<13}  {:<10}  {:<28}  {}",
                bytes_to_gib(target.allocated_bytes),
                layout_label(target.layout),
                verdict_label(verdict),
                summarize_verdict_reason(target, verdict),
                sanitize_terminal_text(&target.root.to_string_lossy()),
            )
            .map_err(AppError::Output)?;
        }
    }

    out.flush().map_err(AppError::Output)?;
    Ok(())
}

fn round2(val: f64) -> f64 {
    (val * 100.0).round() / 100.0
}

fn pressure_label(pressure: DiskPressure) -> &'static str {
    match pressure {
        DiskPressure::Calm => "calm",
        DiskPressure::Elevated => "elevated",
        DiskPressure::High => "high",
        DiskPressure::Critical => "critical",
    }
}

fn layout_label(layout: TargetLayout) -> &'static str {
    match layout {
        TargetLayout::BuildDirV2 => "build_dir_v2",
        TargetLayout::LegacyV1 => "legacy_v1",
        TargetLayout::MixedV1V2 => "mixed_v1_v2",
        TargetLayout::ArtifactsOnly => "artifacts",
    }
}

fn verdict_label(verdict: &SafetyVerdict) -> &'static str {
    match verdict {
        SafetyVerdict::Eligible => "eligible",
        SafetyVerdict::SweepOnly { .. } => "sweep_only",
        SafetyVerdict::Protected(_) => "protected",
    }
}

fn summarize_verdict_reason(_target: &CargoTarget, verdict: &SafetyVerdict) -> String {
    match verdict {
        SafetyVerdict::Eligible => "-".to_owned(),
        SafetyVerdict::SweepOnly { reasons, .. } => reasons
            .first()
            .map_or_else(|| "-".to_owned(), format_sweep_only_reason),
        SafetyVerdict::Protected(reasons) => reasons
            .first()
            .map_or_else(|| "-".to_owned(), format_protected_reason),
    }
}

fn format_sweep_only_reason(reason: &SweepOnlyReason) -> String {
    match reason {
        SweepOnlyReason::OpenInteractiveSession { comm, .. } => {
            format!("session({})", sanitize_terminal_text(comm))
        }
        SweepOnlyReason::IdleRustAnalyzer { .. } => "idle_rust_analyzer".to_owned(),
        SweepOnlyReason::PinnedAllowSweep => "pinned(allow_sweep)".to_owned(),
        SweepOnlyReason::DirtyOrUnmergedWorktree => "dirty_or_unmerged".to_owned(),
        SweepOnlyReason::MainCheckoutProtected => "main_checkout".to_owned(),
        SweepOnlyReason::EvictionCooling { remaining_secs } => {
            format!("evict_cool({}m)", remaining_secs.div_ceil(60))
        }
        SweepOnlyReason::SnapshotHoldActive => "snapshot_hold".to_owned(),
    }
}

fn format_protected_reason(reason: &ProtectedReason) -> String {
    match reason {
        ProtectedReason::ActiveCargoLock { profile } => {
            format!("lock({})", sanitize_terminal_text(profile))
        }
        ProtectedReason::ActiveDocLock => "doc_lock".to_owned(),
        ProtectedReason::HardBlockedProcess { comm, .. } => {
            format!("proc({})", sanitize_terminal_text(comm))
        }
        ProtectedReason::GitOperationInProgress => "git_op".to_owned(),
        ProtectedReason::TrackedFilesInTarget => "tracked_files".to_owned(),
        ProtectedReason::SymlinkOrMountBoundary => "symlink_or_mount".to_owned(),
        ProtectedReason::UnverifiedNonCargoEntries => "unverified_entries".to_owned(),
        ProtectedReason::NestedTargetProtected { .. } => "nested_protected".to_owned(),
        ProtectedReason::PinnedFull => "pinned_full".to_owned(),
        ProtectedReason::PinMarkerFile => "pin_marker".to_owned(),
        ProtectedReason::Cooling { remaining_secs } => format!("cooling({remaining_secs}s)"),
        ProtectedReason::ProcessSnapshotUnavailable => "lsof_unavailable".to_owned(),
        ProtectedReason::MountTableUnavailable => "mount_unavailable".to_owned(),
        ProtectedReason::GitInspectionFailed => "git_failed".to_owned(),
    }
}

#[derive(Serialize)]
struct ReclaimSummary {
    planned_actions: usize,
    applied_actions: usize,
    dry_run_actions: usize,
    skipped_actions: usize,
    failed_actions: usize,
    estimated_allocated_bytes: u64,
    estimated_allocated_gib: f64,
    reclaimed_allocated_bytes: u64,
    reclaimed_allocated_gib: f64,
}

#[derive(Serialize)]
struct ReclaimJsonReport<'a> {
    schema_version: u32,
    command: &'static str,
    dry_run: bool,
    generated_at_unix: u64,
    disk: DiskReport<'a>,
    pressure: DiskPressure,
    hold_active: bool,
    summary: ReclaimSummary,
    receipts: &'a [ActionReceipt],
}

/// Format `reclaim` results (`--dry-run` or live execution) as GiB text or `schema_version = 1` JSON.
pub(crate) fn write_reclaim_report(
    plan: &ReclaimPlan,
    receipts: &[ActionReceipt],
    dry_run: bool,
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<(), AppError> {
    let mut applied = 0usize;
    let mut dry_runs = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut reclaimed_bytes = 0u64;

    for r in receipts {
        match &r.outcome {
            ActionOutcome::Applied => {
                applied += 1;
                reclaimed_bytes = reclaimed_bytes.saturating_add(r.allocated_bytes);
            }
            ActionOutcome::DryRun => dry_runs += 1,
            ActionOutcome::SkippedContested { .. }
            | ActionOutcome::SkippedRevalidateChanged { .. } => skipped += 1,
            ActionOutcome::Failed { .. } => failed += 1,
        }
    }

    let summary = ReclaimSummary {
        planned_actions: plan.actions.len(),
        applied_actions: applied,
        dry_run_actions: dry_runs,
        skipped_actions: skipped,
        failed_actions: failed,
        estimated_allocated_bytes: plan.estimated_allocated_bytes,
        estimated_allocated_gib: round2(bytes_to_gib(plan.estimated_allocated_bytes)),
        reclaimed_allocated_bytes: reclaimed_bytes,
        reclaimed_allocated_gib: round2(bytes_to_gib(reclaimed_bytes)),
    };

    match format {
        OutputFormat::Json => {
            let report = ReclaimJsonReport {
                schema_version: SCHEMA_VERSION,
                command: "reclaim",
                dry_run,
                generated_at_unix: plan.generated_at_unix,
                disk: DiskReport {
                    mount: &plan.disk.mount,
                    total_bytes: plan.disk.total_bytes,
                    free_bytes: plan.disk.free_bytes,
                    total_gib: round2(bytes_to_gib(plan.disk.total_bytes)),
                    free_gib: round2(bytes_to_gib(plan.disk.free_bytes)),
                    local_snapshots: plan.disk.local_snapshots.as_deref(),
                },
                pressure: plan.pressure,
                hold_active: plan.hold_active,
                summary,
                receipts,
            };
            write_json_line(&report, out)?;
        }
        OutputFormat::Text => {
            let mut out = BufWriter::new(out);
            writeln!(
                out,
                "Reclaim ({})  Free: {:.2} / {:.2} GiB  Pressure: {}  Hold: {}",
                if dry_run { "dry-run" } else { "apply" },
                bytes_to_gib(plan.disk.free_bytes),
                bytes_to_gib(plan.disk.total_bytes),
                pressure_label(plan.pressure),
                if plan.hold_active { "active" } else { "off" },
            )
            .map_err(AppError::Output)?;
            writeln!(
                out,
                "Actions: {} planned ({:.2} GiB est.) | {} applied ({:.2} GiB), {} skipped, {} failed",
                summary.planned_actions,
                bytes_to_gib(summary.estimated_allocated_bytes),
                summary.applied_actions,
                bytes_to_gib(summary.reclaimed_allocated_bytes),
                summary.skipped_actions,
                summary.failed_actions,
            )
            .map_err(AppError::Output)?;

            if !receipts.is_empty() {
                writeln!(out).map_err(AppError::Output)?;
                writeln!(
                    out,
                    "{:<18}  {:<12}  {:>9}  {:>6}  PATH",
                    "RULE", "OUTCOME", "SIZE", "UNITS"
                )
                .map_err(AppError::Output)?;
                for receipt in receipts {
                    write_receipt_row(receipt, &mut out)?;
                }
            }
            out.flush().map_err(AppError::Output)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct HistoryJsonReport<'a> {
    schema_version: u32,
    command: &'static str,
    count: usize,
    entries: &'a [ActionReceipt],
}

/// Format recent `actions.jsonl` entries for `targetwarden history`.
pub(crate) fn write_history_report(
    receipts: &[ActionReceipt],
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<(), AppError> {
    match format {
        OutputFormat::Json => {
            let report = HistoryJsonReport {
                schema_version: SCHEMA_VERSION,
                command: "history",
                count: receipts.len(),
                entries: receipts,
            };
            write_json_line(&report, out)?;
        }
        OutputFormat::Text => {
            let mut out = BufWriter::new(out);
            if receipts.is_empty() {
                writeln!(out, "No reclamation actions recorded yet.").map_err(AppError::Output)?;
            } else {
                writeln!(
                    out,
                    "{:<12}  {:<18}  {:<12}  {:>9}  {:>6}  PATH",
                    "TS_UNIX", "RULE", "OUTCOME", "SIZE", "UNITS"
                )
                .map_err(AppError::Output)?;
                for receipt in receipts {
                    let path_display = match &receipt.profile_rel {
                        Some(rel) => format!("{}/{}", receipt.target_root.display(), rel.display()),
                        None => receipt.target_root.display().to_string(),
                    };
                    writeln!(
                        out,
                        "{:<12}  {:<18}  {:<12}  {:>6.2} GiB  {:>6}  {}",
                        receipt.ts_unix,
                        rule_label(receipt.rule),
                        outcome_label(&receipt.outcome),
                        bytes_to_gib(receipt.allocated_bytes),
                        receipt.units_removed,
                        sanitize_terminal_text(&path_display),
                    )
                    .map_err(AppError::Output)?;
                }
            }
            out.flush().map_err(AppError::Output)?;
        }
    }
    Ok(())
}

fn write_receipt_row(receipt: &ActionReceipt, out: &mut impl Write) -> Result<(), AppError> {
    let path_display = match &receipt.profile_rel {
        Some(rel) => format!("{}/{}", receipt.target_root.display(), rel.display()),
        None => receipt.target_root.display().to_string(),
    };
    writeln!(
        out,
        "{:<18}  {:<12}  {:>6.2} GiB  {:>6}  {}",
        rule_label(receipt.rule),
        outcome_label(&receipt.outcome),
        bytes_to_gib(receipt.allocated_bytes),
        receipt.units_removed,
        sanitize_terminal_text(&path_display),
    )
    .map_err(AppError::Output)
}

fn rule_label(rule: RuleId) -> &'static str {
    match rule {
        RuleId::CrashRecovery => "crash_recovery",
        RuleId::R1DeadWorktree => "r1_dead_worktree",
        RuleId::R2BuildSweep => "r2_build_sweep",
        RuleId::R2DocPrune => "r2_doc_prune",
        RuleId::R3IncrementalPrune => "r3_inc_prune",
        RuleId::R4CooledWorktree => "r4_cooled_wt",
        RuleId::R5PressureLru => "r5_pressure_lru",
    }
}

fn outcome_label(outcome: &ActionOutcome) -> &'static str {
    match outcome {
        ActionOutcome::Applied => "applied",
        ActionOutcome::DryRun => "dry_run",
        ActionOutcome::SkippedContested { .. } => "contested",
        ActionOutcome::SkippedRevalidateChanged { .. } => "revalidated",
        ActionOutcome::Failed { .. } => "failed",
    }
}

#[derive(Serialize)]
struct PinJsonReport<'a> {
    schema_version: u32,
    command: &'static str,
    path: &'a std::path::Path,
    scope: PinScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

/// Format `targetwarden pin` output.
pub(crate) fn write_pin_report(
    path: &std::path::Path,
    scope: PinScope,
    note: Option<&str>,
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<(), AppError> {
    match format {
        OutputFormat::Json => {
            let report = PinJsonReport {
                schema_version: SCHEMA_VERSION,
                command: "pin",
                path,
                scope,
                note,
            };
            write_json_line(&report, out)?;
        }
        OutputFormat::Text => {
            let scope_str = match scope {
                PinScope::Full => "full",
                PinScope::AllowSweep => "allow_sweep",
            };
            writeln!(
                out,
                "Pinned ({scope_str}): {}",
                sanitize_terminal_text(&path.to_string_lossy())
            )
            .map_err(AppError::Output)?;
            out.flush().map_err(AppError::Output)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct UnpinJsonReport<'a> {
    schema_version: u32,
    command: &'static str,
    path: &'a std::path::Path,
    removed: bool,
}

/// Format `targetwarden unpin` output.
pub(crate) fn write_unpin_report(
    path: &std::path::Path,
    removed: bool,
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<(), AppError> {
    match format {
        OutputFormat::Json => {
            let report = UnpinJsonReport {
                schema_version: SCHEMA_VERSION,
                command: "unpin",
                path,
                removed,
            };
            write_json_line(&report, out)?;
        }
        OutputFormat::Text => {
            if removed {
                writeln!(
                    out,
                    "Unpinned: {}",
                    sanitize_terminal_text(&path.to_string_lossy())
                )
                .map_err(AppError::Output)?;
            } else {
                writeln!(
                    out,
                    "Not pinned: {}",
                    sanitize_terminal_text(&path.to_string_lossy())
                )
                .map_err(AppError::Output)?;
            }
            out.flush().map_err(AppError::Output)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct InstallJsonReport<'a> {
    schema_version: u32,
    command: &'static str,
    dry_run: bool,
    label: &'a str,
    domain: &'a str,
    plist_path: &'a std::path::Path,
    log_path: &'a std::path::Path,
    plist_xml: &'a str,
    launchctl_actions: &'a [String],
}

/// Format `targetwarden install` output (`--dry-run` or applied).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_install_report(
    label: &str,
    domain: &str,
    plist_path: &std::path::Path,
    log_path: &std::path::Path,
    plist_xml: &str,
    launchctl_actions: &[String],
    dry_run: bool,
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<(), AppError> {
    match format {
        OutputFormat::Json => {
            let report = InstallJsonReport {
                schema_version: SCHEMA_VERSION,
                command: "install",
                dry_run,
                label,
                domain,
                plist_path,
                log_path,
                plist_xml,
                launchctl_actions,
            };
            write_json_line(&report, out)?;
        }
        OutputFormat::Text => {
            let mode = if dry_run { "dry-run" } else { "installed" };
            writeln!(
                out,
                "LaunchAgent ({mode}): {} ({})",
                sanitize_terminal_text(label),
                sanitize_terminal_text(domain),
            )
            .map_err(AppError::Output)?;
            writeln!(
                out,
                "Plist: {}",
                sanitize_terminal_text(&plist_path.to_string_lossy())
            )
            .map_err(AppError::Output)?;
            writeln!(
                out,
                "Log:   {}",
                sanitize_terminal_text(&log_path.to_string_lossy())
            )
            .map_err(AppError::Output)?;
            if dry_run {
                writeln!(out, "\nLaunchctl commands:").map_err(AppError::Output)?;
                for cmd in launchctl_actions {
                    writeln!(out, "  {}", sanitize_terminal_text(cmd)).map_err(AppError::Output)?;
                }
                writeln!(out, "\nGenerated plist:\n{plist_xml}").map_err(AppError::Output)?;
            }
            out.flush().map_err(AppError::Output)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct UninstallJsonReport<'a> {
    schema_version: u32,
    command: &'static str,
    label: &'a str,
    domain: &'a str,
    plist_path: &'a std::path::Path,
    removed_plist: bool,
    booted_out: bool,
}

/// Format `targetwarden uninstall` output.
pub(crate) fn write_uninstall_report(
    label: &str,
    domain: &str,
    plist_path: &std::path::Path,
    removed_plist: bool,
    booted_out: bool,
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<(), AppError> {
    match format {
        OutputFormat::Json => {
            let report = UninstallJsonReport {
                schema_version: SCHEMA_VERSION,
                command: "uninstall",
                label,
                domain,
                plist_path,
                removed_plist,
                booted_out,
            };
            write_json_line(&report, out)?;
        }
        OutputFormat::Text => {
            writeln!(
                out,
                "LaunchAgent uninstalled: {} ({}) [booted_out={}, removed_plist={}]",
                sanitize_terminal_text(label),
                sanitize_terminal_text(domain),
                booted_out,
                removed_plist,
            )
            .map_err(AppError::Output)?;
            writeln!(
                out,
                "Plist: {}",
                sanitize_terminal_text(&plist_path.to_string_lossy())
            )
            .map_err(AppError::Output)?;
            out.flush().map_err(AppError::Output)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use compact_str::CompactString;
    use smallvec::SmallVec;

    use super::write_inventory_report;
    use crate::model::{
        CargoTarget, DiskPressure, DiskStats, GIB, GitDiscovery, OutputFormat, ProtectedReason,
        SafetyVerdict, ScanSnapshot, TargetLayout, TargetOrigin, WorktreeKind,
    };
    use crate::state::State;

    #[test]
    fn status_json_has_schema_version_1_and_text_escapes_control_chars() {
        let target = CargoTarget {
            root: PathBuf::from("/tmp/evil\u{1b}[31m/target"),
            dev_id: 1,
            ino: 2,
            origin: TargetOrigin::VerifiedCargoTag,
            layout: TargetLayout::BuildDirV2,
            symlink_or_mount_boundary: false,
            has_unverified_top_entries: false,
            has_pin_marker: false,
            parent_target: None,
            nested_target_roots: vec![],
            worktree_kind: WorktreeKind::NonGit,
            git: GitDiscovery::NotInGitRepo,
            project_dir: None,
            profiles: vec![],
            doc_dir: None,
            root_lock_file: None,
            root_locked_now: false,
            root_mtime_unix: 1000,
            allocated_bytes: 2 * GIB,
            last_activity_unix: 1000,
            inventory_stamp: 0,
            inventory_computed_at_unix: 0,
        };
        let snapshot = ScanSnapshot {
            captured_at_unix: 5000,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 100 * GIB,
                local_snapshots: Some(vec![CompactString::new("snap-1")]),
            },
            processes: None,
            process_snapshot_error: None,
            mount_table_available: true,
            mount_table_error: None,
            targets: vec![target],
            walk_partial: false,
            leftover_staging: vec![],
            scanned_roots: vec![PathBuf::from("/tmp")],
        };
        let mut protected = SmallVec::new();
        protected.push(ProtectedReason::ProcessSnapshotUnavailable);
        let verdicts = vec![SafetyVerdict::Protected(protected)];

        let mut json_out = Vec::new();
        write_inventory_report(
            "status",
            &snapshot,
            &verdicts,
            DiskPressure::Calm,
            &State::new_default(),
            OutputFormat::Json,
            &mut json_out,
        )
        .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
        assert_eq!(val["schema_version"], 1);
        assert_eq!(val["command"], "status");
        assert_eq!(val["totals"]["target_count"], 1);
        assert_eq!(val["targets"][0]["verdict"], "protected");

        let mut text_out = Vec::new();
        write_inventory_report(
            "status",
            &snapshot,
            &verdicts,
            DiskPressure::Calm,
            &State::new_default(),
            OutputFormat::Text,
            &mut text_out,
        )
        .unwrap();
        let text = String::from_utf8(text_out).unwrap();
        assert!(text.contains("2.00 GiB"));
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("\\u{1b}"));

        // BrokenPipe on JSON output MUST preserve ErrorKind::BrokenPipe so CLI exits 0!
        struct BrokenPipeWriter;
        impl std::io::Write for BrokenPipeWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let err = write_inventory_report(
            "status",
            &snapshot,
            &verdicts,
            DiskPressure::Calm,
            &State::new_default(),
            OutputFormat::Json,
            &mut BrokenPipeWriter,
        )
        .unwrap_err();
        assert!(err.is_stdout_closed());
    }
}
