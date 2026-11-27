//! Functional Core (Layer 2): pure evaluator for all 6 safety barriers,
//! nested `--target-dir` protection propagation, and idle proc-macro `.dylib` auto-pinning.
//!
//! Allowed dependencies: `model`, `config`, `state`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use compact_str::CompactString;
use smallvec::SmallVec;

use crate::config::Config;
use crate::model::{
    CargoTarget, DiskPressure, GitDiscovery, PinScope, ProcessEntry, ProtectedReason,
    SafetyVerdict, ScanSnapshot, SweepOnlyReason, WorktreeKind,
};
use crate::state::State;

/// Evaluate all 6 safety barriers plus bottom-up nested target propagation.
/// Returns one `SafetyVerdict` per target in `snapshot.targets` (matching indices).
pub(crate) fn evaluate_all(
    snapshot: &ScanSnapshot,
    state: &State,
    config: &Config,
    pressure: DiskPressure,
    ignore_snapshot_hold: bool,
) -> Vec<SafetyVerdict> {
    let hold_active = state.reclaim_hold.is_some() && !ignore_snapshot_hold;
    let mut verdicts: Vec<SafetyVerdict> = snapshot
        .targets
        .iter()
        .map(|target| evaluate_single(target, snapshot, state, config, pressure, hold_active))
        .collect();

    propagate_nested_verdicts(&snapshot.targets, &mut verdicts);
    verdicts
}

/// Pure helper shared with `rules.rs`: whether `target` qualifies structurally as a dead
/// worktree under `R1` (worktree dir missing, or clean merged unlocked `LinkedWorktree`).
pub(crate) fn is_r1_dead_worktree_candidate(target: &CargoTarget) -> bool {
    match &target.git {
        GitDiscovery::Inspected(git) => {
            !git.worktree_locked
                && !git.git_op_in_progress
                && (git.worktree_dir_missing
                    || (git.worktree_kind == WorktreeKind::LinkedWorktree
                        && !git.is_dirty
                        && git.branch_merged_into_default == Some(true)))
        }
        GitDiscovery::NotInGitRepo | GitDiscovery::Failed(_) => false,
    }
}

fn evaluate_single(
    target: &CargoTarget,
    snapshot: &ScanSnapshot,
    state: &State,
    config: &Config,
    pressure: DiskPressure,
    hold_active: bool,
) -> SafetyVerdict {
    let mut protected: SmallVec<[ProtectedReason; 4]> = SmallVec::new();
    let mut sweep_only: SmallVec<[SweepOnlyReason; 2]> = SmallVec::new();
    let mut pinned_unit_paths: Vec<PathBuf> = Vec::new();

    // Barrier 1: global infrastructure fail-closed checks
    if snapshot.processes.is_none() {
        protected.push(ProtectedReason::ProcessSnapshotUnavailable);
    }
    if !snapshot.mount_table_available {
        protected.push(ProtectedReason::MountTableUnavailable);
    }

    // Barrier 2: target boundary & origin integrity
    if target.symlink_or_mount_boundary {
        protected.push(ProtectedReason::SymlinkOrMountBoundary);
    }
    if target.has_unverified_top_entries {
        protected.push(ProtectedReason::UnverifiedNonCargoEntries);
    }

    // Barrier 3: active Cargo / rustdoc file locks
    if target.root_locked_now {
        protected.push(ProtectedReason::ActiveCargoLock {
            profile: CompactString::new("target"),
        });
    }
    for profile in &target.profiles {
        if profile.locked_now {
            protected.push(ProtectedReason::ActiveCargoLock {
                profile: profile.name.clone(),
            });
        }
    }
    if target.doc_dir.as_ref().is_some_and(|doc| doc.locked_now) {
        protected.push(ProtectedReason::ActiveDocLock);
    }

    let age_secs = snapshot
        .captured_at_unix
        .saturating_sub(target.last_activity_unix);

    // Barrier 4: Git integrity & worktree protection
    match &target.git {
        GitDiscovery::Failed(_) => {
            protected.push(ProtectedReason::GitInspectionFailed);
        }
        GitDiscovery::Inspected(git) => {
            if git.has_tracked_files_in_target {
                protected.push(ProtectedReason::TrackedFilesInTarget);
            }
            if git.git_op_in_progress {
                protected.push(ProtectedReason::GitOperationInProgress);
            }
            match git.worktree_kind {
                WorktreeKind::MainCheckout => {
                    let allowed_by_pressure = config
                        .cooling
                        .r5_main_age_secs(pressure)
                        .is_some_and(|min_age| age_secs >= min_age);
                    if !allowed_by_pressure {
                        sweep_only.push(SweepOnlyReason::MainCheckoutProtected);
                    }
                }
                WorktreeKind::LinkedWorktree => {
                    if git.worktree_locked {
                        sweep_only.push(SweepOnlyReason::DirtyOrUnmergedWorktree);
                    } else if !git.worktree_dir_missing {
                        let r4_cooled = age_secs >= config.cooling.r4_age_secs(pressure);
                        let r5_allowed = pressure >= DiskPressure::High && !hold_active;
                        let merged_and_clean =
                            !git.is_dirty && git.branch_merged_into_default == Some(true);
                        if !merged_and_clean && !r4_cooled && !r5_allowed {
                            sweep_only.push(SweepOnlyReason::DirtyOrUnmergedWorktree);
                        }
                    }
                }
                WorktreeKind::NonGit => {}
            }
        }
        GitDiscovery::NotInGitRepo => {}
    }

    // Barrier 5: active processes (`lsof` snapshot)
    let worktree_root = target.worktree_root();
    if let Some(proc_snap) = &snapshot.processes {
        for proc_entry in &proc_snap.processes {
            if proc_snap.self_pid != 0 && proc_entry.pid == proc_snap.self_pid {
                continue;
            }
            evaluate_process_against_target(
                proc_entry,
                &target.root,
                worktree_root,
                &mut protected,
                &mut sweep_only,
                &mut pinned_unit_paths,
            );
        }
    }

    // Barrier 6: pins, cooling (`mtime`-only), and APFS snapshot hold
    if target.has_pin_marker {
        protected.push(ProtectedReason::PinMarkerFile);
    }
    match state.matching_pin(&target.root, worktree_root) {
        Some(PinScope::Full) => protected.push(ProtectedReason::PinnedFull),
        Some(PinScope::AllowSweep) => sweep_only.push(SweepOnlyReason::PinnedAllowSweep),
        None => {}
    }

    if age_secs < config.cooling.sweep_cooling_secs {
        protected.push(ProtectedReason::Cooling {
            remaining_secs: config.cooling.sweep_cooling_secs - age_secs,
        });
    } else if age_secs < config.cooling.eviction_cooling_secs {
        sweep_only.push(SweepOnlyReason::EvictionCooling {
            remaining_secs: config.cooling.eviction_cooling_secs - age_secs,
        });
    }

    if hold_active && pressure >= DiskPressure::High && !is_r1_dead_worktree_candidate(target) {
        sweep_only.push(SweepOnlyReason::SnapshotHoldActive);
    }

    if !protected.is_empty() {
        SafetyVerdict::Protected(protected)
    } else if !sweep_only.is_empty() {
        pinned_unit_paths.sort();
        pinned_unit_paths.dedup();
        SafetyVerdict::SweepOnly {
            reasons: sweep_only,
            pinned_unit_paths,
        }
    } else {
        SafetyVerdict::Eligible
    }
}

fn evaluate_process_against_target(
    proc_entry: &ProcessEntry,
    target_root: &Path,
    worktree_root: Option<&Path>,
    protected: &mut SmallVec<[ProtectedReason; 4]>,
    sweep_only: &mut SmallVec<[SweepOnlyReason; 2]>,
    pinned_unit_paths: &mut Vec<PathBuf>,
) {
    let cwd_in_target = proc_entry
        .cwd
        .as_deref()
        .is_some_and(|cwd| cwd.starts_with(target_root));
    let open_in_target: SmallVec<[&PathBuf; 4]> = proc_entry
        .open_paths
        .iter()
        .filter(|path| path.starts_with(target_root))
        .collect();

    let is_proc_macro_srv = proc_entry.is_rust_analyzer_proc_macro_srv();
    let is_ra = proc_entry.is_rust_analyzer();

    if is_proc_macro_srv {
        let mut has_non_dylib_target_path = cwd_in_target;
        let mut mapped_dylib = false;
        for path in open_in_target {
            if is_dylib_path(path) {
                mapped_dylib = true;
                pinned_unit_paths.push(path.clone());
            } else {
                has_non_dylib_target_path = true;
            }
        }
        if has_non_dylib_target_path {
            protected.push(ProtectedReason::HardBlockedProcess {
                pid: proc_entry.pid,
                comm: proc_entry.comm.clone(),
                detail: CompactString::new("open_in_target"),
            });
            return;
        }
        let cwd_in_worktree = worktree_root.is_some_and(|wt| {
            proc_entry
                .cwd
                .as_deref()
                .is_some_and(|cwd| cwd.starts_with(wt))
        });
        if mapped_dylib || cwd_in_worktree {
            push_unique_sweep(
                sweep_only,
                SweepOnlyReason::IdleRustAnalyzer {
                    pid: proc_entry.pid,
                },
            );
        }
        return;
    }

    // Any other process touching `target_root` directly is an unconditional Hard Block.
    if cwd_in_target || !open_in_target.is_empty() {
        protected.push(ProtectedReason::HardBlockedProcess {
            pid: proc_entry.pid,
            comm: proc_entry.comm.clone(),
            detail: CompactString::new("open_in_target"),
        });
        return;
    }

    let Some(wt_root) = worktree_root else {
        return;
    };

    let cwd_in_worktree = proc_entry
        .cwd
        .as_deref()
        .is_some_and(|cwd| cwd.starts_with(wt_root));

    if is_ra {
        let open_in_worktree = proc_entry
            .open_paths
            .iter()
            .any(|path| path.starts_with(wt_root));
        if cwd_in_worktree || open_in_worktree {
            push_unique_sweep(
                sweep_only,
                SweepOnlyReason::IdleRustAnalyzer {
                    pid: proc_entry.pid,
                },
            );
        }
        return;
    }

    if proc_entry.is_active_compiler_or_tool() {
        let open_in_worktree = proc_entry
            .open_paths
            .iter()
            .any(|path| path.starts_with(wt_root));
        if cwd_in_worktree || open_in_worktree {
            protected.push(ProtectedReason::HardBlockedProcess {
                pid: proc_entry.pid,
                comm: proc_entry.comm.clone(),
                detail: CompactString::new("compiler_in_worktree"),
            });
        }
        return;
    }

    if cwd_in_worktree {
        push_unique_sweep(
            sweep_only,
            SweepOnlyReason::OpenInteractiveSession {
                pid: proc_entry.pid,
                comm: proc_entry.comm.clone(),
            },
        );
    }
}

fn push_unique_sweep(reasons: &mut SmallVec<[SweepOnlyReason; 2]>, reason: SweepOnlyReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn propagate_nested_verdicts(targets: &[CargoTarget], verdicts: &mut [SafetyVerdict]) {
    let index_by_root: HashMap<&Path, usize> = targets
        .iter()
        .enumerate()
        .map(|(idx, target)| (target.root.as_path(), idx))
        .collect();

    let mut order: Vec<usize> = (0..targets.len()).collect();
    order.sort_by_key(|&idx| std::cmp::Reverse(targets[idx].root.components().count()));

    for idx in order {
        if targets[idx].nested_target_roots.is_empty() {
            continue;
        }
        let mut child_protected: SmallVec<[PathBuf; 2]> = SmallVec::new();
        let mut child_sweep_reasons: SmallVec<[SweepOnlyReason; 2]> = SmallVec::new();

        for child_root in &targets[idx].nested_target_roots {
            match index_by_root
                .get(child_root.as_path())
                .and_then(|&cidx| verdicts.get(cidx))
            {
                Some(SafetyVerdict::Eligible) => {}
                Some(SafetyVerdict::SweepOnly { reasons, .. }) => {
                    for reason in reasons {
                        push_unique_sweep(&mut child_sweep_reasons, reason.clone());
                    }
                }
                Some(SafetyVerdict::Protected(_)) | None => {
                    child_protected.push(child_root.clone());
                }
            }
        }

        if !child_protected.is_empty() {
            match &mut verdicts[idx] {
                SafetyVerdict::Protected(reasons) => {
                    for child in child_protected {
                        let r = ProtectedReason::NestedTargetProtected { child };
                        if !reasons.contains(&r) {
                            reasons.push(r);
                        }
                    }
                }
                SafetyVerdict::Eligible | SafetyVerdict::SweepOnly { .. } => {
                    let reasons = child_protected
                        .into_iter()
                        .map(|child| ProtectedReason::NestedTargetProtected { child })
                        .collect();
                    verdicts[idx] = SafetyVerdict::Protected(reasons);
                }
            }
        } else if !child_sweep_reasons.is_empty()
            && matches!(verdicts[idx], SafetyVerdict::Eligible)
        {
            // Prevent full eviction of parent when a nested child is only `SweepOnly`,
            // while still allowing intra-target surgical sweep of parent's own profiles.
            verdicts[idx] = SafetyVerdict::SweepOnly {
                reasons: child_sweep_reasons,
                pinned_unit_paths: Vec::new(),
            };
        }
    }
}

fn is_dylib_path(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("dylib")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use compact_str::CompactString;
    use smallvec::SmallVec;

    use super::evaluate_all;
    use crate::config::Config;
    use crate::model::{
        CargoTarget, DiskPressure, DiskStats, DocDirInfo, GIB, GitDiscovery, GitInspection,
        PinEntry, PinScope, ProcessEntry, ProcessSnapshot, ProfileDir, ProtectedReason,
        ReclaimHoldState, SafetyVerdict, ScanSnapshot, SweepOnlyReason, TargetLayout, TargetOrigin,
        WorktreeKind,
    };
    use crate::state::State;

    const NOW: u64 = 1_800_000_000;

    fn base_target(root: &str, kind: WorktreeKind, age_secs: u64) -> CargoTarget {
        let root_path = PathBuf::from(root);
        let wt_root = root_path.parent().unwrap().to_path_buf();
        let git = match kind {
            WorktreeKind::NonGit => GitDiscovery::NotInGitRepo,
            WorktreeKind::MainCheckout | WorktreeKind::LinkedWorktree => {
                GitDiscovery::Inspected(GitInspection {
                    repo_common_dir: PathBuf::from("/Users/dev/Projects/repo/.git"),
                    worktree_root: wt_root.clone(),
                    worktree_kind: kind,
                    worktree_dir_missing: false,
                    is_dirty: false,
                    git_op_in_progress: false,
                    worktree_locked: false,
                    branch_merged_into_default: Some(true),
                    has_tracked_files_in_target: false,
                })
            }
        };
        CargoTarget {
            root: root_path,
            dev_id: 1,
            ino: 100,
            origin: TargetOrigin::VerifiedCargoTag,
            layout: TargetLayout::BuildDirV2,
            symlink_or_mount_boundary: false,
            has_unverified_top_entries: false,
            has_pin_marker: false,
            parent_target: None,
            nested_target_roots: vec![],
            worktree_kind: kind,
            git,
            project_dir: Some(wt_root),
            profiles: vec![ProfileDir {
                name: CompactString::new("debug"),
                rel_path: PathBuf::from("debug"),
                layout: TargetLayout::BuildDirV2,
                lock_files: SmallVec::new(),
                locked_now: false,
                fingerprint_corrupt: false,
                v2_unit_count: 0,
                v1_unit_count: 0,
                incremental_dir_count: 0,
                v2_units: vec![],
                v1_units: vec![],
                incremental_dirs: vec![],
                profile_mtime_unix: NOW - age_secs,
                inc_root_mtime_unix: NOW - age_secs,
                allocated_bytes: GIB,
                last_activity_unix: NOW - age_secs,
            }],
            doc_dir: None,
            root_lock_file: None,
            root_locked_now: false,
            root_mtime_unix: NOW - age_secs,
            allocated_bytes: GIB,
            last_activity_unix: NOW - age_secs,
        }
    }

    fn base_snapshot(
        targets: Vec<CargoTarget>,
        processes: Option<Vec<ProcessEntry>>,
    ) -> ScanSnapshot {
        ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 100 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: processes.map(|list| ProcessSnapshot {
                captured_at_unix: NOW,
                self_pid: 99999,
                processes: list,
            }),
            process_snapshot_error: None,
            mount_table_available: true,
            mount_table_error: None,
            targets,
            walk_partial: false,
            leftover_staging: vec![],
            scanned_roots: vec![],
        }
    }

    #[test]
    fn clean_merged_cooled_linked_worktree_is_eligible() {
        let target = base_target("/Users/dev/wt1/target", WorktreeKind::LinkedWorktree, 3600);
        let snap = base_snapshot(vec![target], Some(vec![]));
        let verdicts = evaluate_all(
            &snap,
            &State::new_default(),
            &Config::default(),
            DiskPressure::Calm,
            false,
        );
        assert_eq!(verdicts, vec![SafetyVerdict::Eligible]);
    }

    #[test]
    fn hard_barriers_trigger_every_protected_reason() {
        let cfg = Config::default();

        // Fail-closed missing process snapshot & mount table
        let mut snap = base_snapshot(
            vec![base_target(
                "/Users/dev/wt/target",
                WorktreeKind::LinkedWorktree,
                3600,
            )],
            None,
        );
        snap.mount_table_available = false;
        let v = evaluate_all(
            &snap,
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        let SafetyVerdict::Protected(reasons) = &v[0] else {
            panic!("expected Protected");
        };
        assert!(reasons.contains(&ProtectedReason::ProcessSnapshotUnavailable));
        assert!(reasons.contains(&ProtectedReason::MountTableUnavailable));

        // Active cargo lock + doc lock + symlink + unverified + pin marker + cooling
        let mut t = base_target("/Users/dev/wt/target", WorktreeKind::LinkedWorktree, 60);
        t.profiles[0].locked_now = true;
        t.doc_dir = Some(DocDirInfo {
            path: t.root.join("doc"),
            lock_file: Some(t.root.join("doc/.lock")),
            locked_now: true,
            last_activity_unix: NOW - 60,
            allocated_bytes: 1024,
        });
        t.symlink_or_mount_boundary = true;
        t.has_unverified_top_entries = true;
        t.has_pin_marker = true;
        if let GitDiscovery::Inspected(git) = &mut t.git {
            git.git_op_in_progress = true;
            git.has_tracked_files_in_target = true;
        }
        let mut state = State::new_default();
        state.pins.insert(
            PathBuf::from("/Users/dev/wt"),
            PinEntry {
                pinned_at_unix: NOW - 100,
                scope: PinScope::Full,
                note: None,
            },
        );
        let snap2 = base_snapshot(vec![t], Some(vec![]));
        let v2 = evaluate_all(&snap2, &state, &cfg, DiskPressure::Calm, false);
        let SafetyVerdict::Protected(reasons2) = &v2[0] else {
            panic!("expected Protected");
        };
        assert!(reasons2.contains(&ProtectedReason::ActiveCargoLock {
            profile: CompactString::new("debug")
        }));
        assert!(reasons2.contains(&ProtectedReason::ActiveDocLock));
        assert!(reasons2.contains(&ProtectedReason::SymlinkOrMountBoundary));
        assert!(reasons2.contains(&ProtectedReason::UnverifiedNonCargoEntries));
        assert!(reasons2.contains(&ProtectedReason::PinMarkerFile));
        assert!(reasons2.contains(&ProtectedReason::PinnedFull));
        assert!(reasons2.contains(&ProtectedReason::GitOperationInProgress));
        assert!(reasons2.contains(&ProtectedReason::TrackedFilesInTarget));
        assert!(reasons2.contains(&ProtectedReason::Cooling {
            remaining_secs: 240
        }));

        // Git inspection failure -> fail closed
        let mut t_git_fail = base_target("/Users/dev/wt/target", WorktreeKind::NonGit, 3600);
        t_git_fail.git = GitDiscovery::Failed(CompactString::new("git timeout"));
        let v3 = evaluate_all(
            &base_snapshot(vec![t_git_fail], Some(vec![])),
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        assert!(matches!(
            &v3[0],
            SafetyVerdict::Protected(r) if r.contains(&ProtectedReason::GitInspectionFailed)
        ));
    }

    #[test]
    fn proc_macro_dylib_auto_pins_while_compiler_hard_blocks_and_sccache_at_root_is_ignored() {
        let cfg = Config::default();
        let target = base_target("/Users/dev/wt/target", WorktreeKind::LinkedWorktree, 3600);
        let dylib = PathBuf::from("/Users/dev/wt/target/debug/deps/libserde_derive-abc.dylib");

        let procs = vec![
            ProcessEntry {
                pid: 100,
                comm: CompactString::new("rust-analyzer-proc-macro-srv"),
                exe_path: Some(PathBuf::from("/usr/local/bin/rust-analyzer-proc-macro-srv")),
                cwd: Some(PathBuf::from("/Users/dev/wt")),
                open_paths: vec![dylib.clone()],
            },
            // Idle sccache server with cwd=/ must NOT block
            ProcessEntry {
                pid: 101,
                comm: CompactString::new("sccache"),
                exe_path: Some(PathBuf::from("/opt/homebrew/bin/sccache")),
                cwd: Some(PathBuf::from("/")),
                open_paths: vec![],
            },
        ];
        let snap = base_snapshot(vec![target.clone()], Some(procs));
        let v = evaluate_all(
            &snap,
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        match &v[0] {
            SafetyVerdict::SweepOnly {
                reasons,
                pinned_unit_paths,
            } => {
                assert!(reasons.contains(&SweepOnlyReason::IdleRustAnalyzer { pid: 100 }));
                assert_eq!(pinned_unit_paths, &vec![dylib]);
            }
            other => panic!("expected SweepOnly with auto-pinned dylib, got {other:?}"),
        }

        // Active cargo in worktree hard-blocks
        let cargo_proc = vec![ProcessEntry {
            pid: 200,
            comm: CompactString::new("cargo-nextest"),
            exe_path: None,
            cwd: Some(PathBuf::from("/Users/dev/wt")),
            open_paths: vec![],
        }];
        let snap_cargo = base_snapshot(vec![target], Some(cargo_proc));
        let v_cargo = evaluate_all(
            &snap_cargo,
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        assert!(matches!(
            &v_cargo[0],
            SafetyVerdict::Protected(r)
                if r.iter().any(|x| matches!(x, ProtectedReason::HardBlockedProcess { pid: 200, .. }))
        ));
    }

    #[test]
    fn sweep_only_reasons_and_nested_propagation_behave_accurately() {
        let cfg = Config::default();

        // Main checkout protected in Calm, eligible in High after 24h (unless snapshot hold active)
        let main_t = base_target(
            "/Users/dev/main/target",
            WorktreeKind::MainCheckout,
            30 * 3600,
        );
        let snap_main = base_snapshot(vec![main_t], Some(vec![]));
        let v_calm = evaluate_all(
            &snap_main,
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        assert!(matches!(
            &v_calm[0],
            SafetyVerdict::SweepOnly { reasons, .. }
                if reasons.contains(&SweepOnlyReason::MainCheckoutProtected)
        ));
        let v_high = evaluate_all(
            &snap_main,
            &State::new_default(),
            &cfg,
            DiskPressure::High,
            false,
        );
        assert_eq!(v_high[0], SafetyVerdict::Eligible);

        // Snapshot hold blocks R5 main checkout in High unless ignored
        let mut hold_state = State::new_default();
        hold_state.reclaim_hold = Some(ReclaimHoldState {
            detected_at_unix: NOW - 100,
            reclaimed_allocated_bytes: 6 * GIB,
            observed_free_gain_bytes: 0,
            free_bytes_at_detection: 40 * GIB,
            pressure_at_detection: DiskPressure::High,
            snapshots_at_detection: vec![],
        });
        let v_hold = evaluate_all(&snap_main, &hold_state, &cfg, DiskPressure::High, false);
        assert!(matches!(
            &v_hold[0],
            SafetyVerdict::SweepOnly { reasons, .. }
                if reasons.contains(&SweepOnlyReason::SnapshotHoldActive)
        ));
        let v_hold_ignored = evaluate_all(&snap_main, &hold_state, &cfg, DiskPressure::High, true);
        assert_eq!(v_hold_ignored[0], SafetyVerdict::Eligible);

        // Nested propagation: child Protected -> parent Protected(NestedTargetProtected)
        let mut parent = base_target("/Users/dev/wt/target", WorktreeKind::LinkedWorktree, 3600);
        let mut child = base_target(
            "/Users/dev/wt/target/grpc-codegen",
            WorktreeKind::LinkedWorktree,
            3600,
        );
        parent.nested_target_roots = vec![child.root.clone()];
        child.parent_target = Some(parent.root.clone());
        child.profiles[0].locked_now = true;
        let snap_nested = base_snapshot(vec![parent, child], Some(vec![]));
        let v_nested = evaluate_all(
            &snap_nested,
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        assert!(matches!(
            &v_nested[0],
            SafetyVerdict::Protected(r)
                if r.contains(&ProtectedReason::NestedTargetProtected {
                    child: PathBuf::from("/Users/dev/wt/target/grpc-codegen")
                })
        ));
    }

    #[test]
    fn eviction_cooling_and_allow_sweep_pin_emit_sweep_only() {
        let cfg = Config::default();
        let target = base_target("/Users/dev/wt/target", WorktreeKind::LinkedWorktree, 1200);
        let mut state = State::new_default();
        state.pins.insert(
            PathBuf::from("/Users/dev/wt"),
            PinEntry {
                pinned_at_unix: NOW - 2000,
                scope: PinScope::AllowSweep,
                note: None,
            },
        );
        let snap = base_snapshot(vec![target], Some(vec![]));
        let v = evaluate_all(&snap, &state, &cfg, DiskPressure::Calm, false);
        let SafetyVerdict::SweepOnly { reasons, .. } = &v[0] else {
            panic!("expected SweepOnly");
        };
        assert!(reasons.contains(&SweepOnlyReason::PinnedAllowSweep));
        assert!(reasons.contains(&SweepOnlyReason::EvictionCooling {
            remaining_secs: 600
        }));
    }

    #[test]
    fn unmerged_linked_worktree_becomes_eligible_for_r5_in_high_unless_locked_or_held() {
        let cfg = Config::default();
        let mut wt = base_target(
            "/Users/dev/wt_wip/target",
            WorktreeKind::LinkedWorktree,
            3600,
        );
        if let GitDiscovery::Inspected(git) = &mut wt.git {
            git.branch_merged_into_default = Some(false);
        }

        let snap = base_snapshot(vec![wt.clone()], Some(vec![]));
        let v_calm = evaluate_all(
            &snap,
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        assert!(matches!(
            &v_calm[0],
            SafetyVerdict::SweepOnly { reasons, .. }
                if reasons.contains(&SweepOnlyReason::DirtyOrUnmergedWorktree)
        ));

        let v_high = evaluate_all(
            &snap,
            &State::new_default(),
            &cfg,
            DiskPressure::High,
            false,
        );
        assert_eq!(v_high[0], SafetyVerdict::Eligible);

        // Locked worktree stays SweepOnly even in High pressure or when worktree_dir_missing.
        let mut locked_wt = wt;
        if let GitDiscovery::Inspected(git) = &mut locked_wt.git {
            git.worktree_locked = true;
            git.worktree_dir_missing = true;
        }
        assert!(!super::is_r1_dead_worktree_candidate(&locked_wt));
        let v_locked = evaluate_all(
            &base_snapshot(vec![locked_wt], Some(vec![])),
            &State::new_default(),
            &cfg,
            DiskPressure::High,
            false,
        );
        assert!(matches!(
            &v_locked[0],
            SafetyVerdict::SweepOnly { reasons, .. }
                if reasons.contains(&SweepOnlyReason::DirtyOrUnmergedWorktree)
        ));

        // rust-analyzer with cwd outside worktree but an open file inside worktree -> SweepOnly
        let ra_target = base_target(
            "/Users/dev/ws/wt_ra/target",
            WorktreeKind::LinkedWorktree,
            3600,
        );
        let ra_proc = vec![ProcessEntry {
            pid: 555,
            comm: CompactString::new("rust-analyzer"),
            exe_path: Some(PathBuf::from("/usr/local/bin/rust-analyzer")),
            cwd: Some(PathBuf::from("/Users/dev/ws")),
            open_paths: vec![PathBuf::from("/Users/dev/ws/wt_ra/src/lib.rs")],
        }];
        let v_ra = evaluate_all(
            &base_snapshot(vec![ra_target], Some(ra_proc)),
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            false,
        );
        assert!(matches!(
            &v_ra[0],
            SafetyVerdict::SweepOnly { reasons, .. }
                if reasons.contains(&SweepOnlyReason::IdleRustAnalyzer { pid: 555 })
        ));
    }
}
