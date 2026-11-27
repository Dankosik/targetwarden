//! Functional Core (Layer 1): persistent `State` schema (`KnownTargetEntry`,
//! `PinEntry`, `ReclaimHoldState`, `DiskPressure`) and pure transitions.
//!
//! Allowed dependencies: `model`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::{
    ActionOutcome, ActionReceipt, CargoTarget, DiskPressure, KnownTargetEntry, PinEntry, PinScope,
    ReclaimHoldState, SCHEMA_VERSION, TargetLayout,
};

/// Compact per-target summary extracted before dropping `ScanSnapshot` ahead of plan execution.
#[derive(Clone, Debug)]
pub(crate) struct TargetScanSummary {
    pub root: PathBuf,
    pub layout: TargetLayout,
    pub allocated_bytes: u64,
    pub last_activity_unix: u64,
}

impl From<&CargoTarget> for TargetScanSummary {
    fn from(target: &CargoTarget) -> Self {
        Self {
            root: target.root.clone(),
            layout: target.layout,
            allocated_bytes: target.allocated_bytes,
            last_activity_unix: target.last_activity_unix,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct State {
    pub schema_version: u32,
    pub pressure: DiskPressure,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_full_walk_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclaim_hold: Option<ReclaimHoldState>,
    #[serde(default)]
    pub known_targets: BTreeMap<PathBuf, KnownTargetEntry>,
    #[serde(default)]
    pub pins: BTreeMap<PathBuf, PinEntry>,
    #[serde(default)]
    pub cumulative_reclaimed_allocated_bytes: u64,
}

impl Default for State {
    fn default() -> Self {
        Self::new_default()
    }
}

impl State {
    pub(crate) fn new_default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            pressure: DiskPressure::Calm,
            last_full_walk_unix: None,
            reclaim_hold: None,
            known_targets: BTreeMap::new(),
            pins: BTreeMap::new(),
            cumulative_reclaimed_allocated_bytes: 0,
        }
    }

    /// Resolve any active pin matching `target_root` or its `worktree_root`.
    /// Fails closed: if any matching pin is `PinScope::Full`, `Full` takes precedence.
    pub(crate) fn matching_pin(
        &self,
        target_root: &Path,
        worktree_root: Option<&Path>,
    ) -> Option<PinScope> {
        let mut matched: Option<PinScope> = None;
        for (pin_path, entry) in &self.pins {
            let matches_target = target_root.starts_with(pin_path);
            let matches_worktree = worktree_root.is_some_and(|root| root.starts_with(pin_path));
            if matches_target || matches_worktree {
                match entry.scope {
                    PinScope::Full => return Some(PinScope::Full),
                    PinScope::AllowSweep => matched = Some(PinScope::AllowSweep),
                }
            }
        }
        matched
    }

    /// Update `known_targets` from compact target summaries extracted from a completed scan.
    /// If `full_walk && !walk_partial`, unseen targets are retired and `last_full_walk_unix` advances.
    /// If `walk_partial`, unseen `known_targets` are preserved without eviction.
    pub(crate) fn record_scan_summaries(
        &mut self,
        targets: &[TargetScanSummary],
        now_unix: u64,
        full_walk: bool,
        walk_partial: bool,
    ) {
        let mut seen: HashSet<&Path> = HashSet::with_capacity(targets.len());
        for target in targets {
            seen.insert(target.root.as_path());
            let first_seen = self
                .known_targets
                .get(&target.root)
                .map_or(now_unix, |entry| entry.first_seen_unix);
            self.known_targets.insert(
                target.root.clone(),
                KnownTargetEntry {
                    first_seen_unix: first_seen,
                    last_seen_unix: now_unix,
                    last_layout: target.layout,
                    last_allocated_bytes: target.allocated_bytes,
                    last_activity_unix: target.last_activity_unix,
                },
            );
        }

        if full_walk && !walk_partial {
            self.last_full_walk_unix = Some(now_unix);
            self.known_targets
                .retain(|path, _| seen.contains(path.as_path()));
        }
    }

    /// Update `known_targets` from a completed scan snapshot.
    #[cfg(test)]
    pub(crate) fn record_scan_targets(
        &mut self,
        targets: &[CargoTarget],
        now_unix: u64,
        full_walk: bool,
        walk_partial: bool,
    ) {
        let summaries: Vec<TargetScanSummary> =
            targets.iter().map(TargetScanSummary::from).collect();
        self.record_scan_summaries(&summaries, now_unix, full_walk, walk_partial);
    }

    /// Accumulate reclaimed allocated bytes from applied action receipts and retire evicted targets.
    pub(crate) fn apply_receipts(&mut self, receipts: &[ActionReceipt]) {
        for receipt in receipts {
            if matches!(receipt.outcome, ActionOutcome::Applied) {
                self.cumulative_reclaimed_allocated_bytes = self
                    .cumulative_reclaimed_allocated_bytes
                    .saturating_add(receipt.allocated_bytes);
                if matches!(
                    receipt.rule,
                    crate::model::RuleId::R1DeadWorktree
                        | crate::model::RuleId::R4CooledWorktree
                        | crate::model::RuleId::R5PressureLru
                ) {
                    self.known_targets
                        .retain(|path, _| !path.starts_with(&receipt.target_root));
                }
            }
        }
    }

    pub(crate) fn add_pin(
        &mut self,
        path: PathBuf,
        scope: PinScope,
        note: Option<String>,
        now_unix: u64,
    ) {
        self.pins.insert(
            path,
            PinEntry {
                pinned_at_unix: now_unix,
                scope,
                note,
            },
        );
    }

    pub(crate) fn remove_pin(&mut self, path: &Path) -> bool {
        self.pins.remove(path).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::State;
    use crate::model::{
        CargoTarget, DiskPressure, GitDiscovery, PinEntry, PinScope, SCHEMA_VERSION, TargetLayout,
        TargetOrigin, WorktreeKind,
    };

    #[test]
    fn default_state_serializes_with_schema_version_1() {
        let state = State::new_default();
        assert_eq!(state.schema_version, SCHEMA_VERSION);
        assert_eq!(state.pressure, DiskPressure::Calm);

        let json = serde_json::to_string(&state).unwrap();
        let parsed: State = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn matching_pin_handles_worktree_ancestor_and_full_precedence() {
        let mut state = State::new_default();
        state.pins.insert(
            PathBuf::from("/Users/dev/Projects"),
            PinEntry {
                pinned_at_unix: 100,
                scope: PinScope::AllowSweep,
                note: None,
            },
        );
        state.pins.insert(
            PathBuf::from("/Users/dev/Projects/critical-app"),
            PinEntry {
                pinned_at_unix: 200,
                scope: PinScope::Full,
                note: Some("release".to_owned()),
            },
        );

        assert_eq!(
            state.matching_pin(
                Path::new("/Users/dev/Projects/other-app/target"),
                Some(Path::new("/Users/dev/Projects/other-app")),
            ),
            Some(PinScope::AllowSweep)
        );
        assert_eq!(
            state.matching_pin(
                Path::new("/Users/dev/Projects/critical-app/target"),
                Some(Path::new("/Users/dev/Projects/critical-app")),
            ),
            Some(PinScope::Full)
        );
        assert_eq!(
            state.matching_pin(
                Path::new("/tmp/external-target"),
                Some(Path::new("/Users/dev/Projects/critical-app")),
            ),
            Some(PinScope::Full)
        );
        assert_eq!(
            state.matching_pin(Path::new("/Users/dev/Other/target"), None),
            None
        );
    }

    #[test]
    fn record_scan_targets_preserves_unseen_when_walk_partial_and_retires_when_complete() {
        let mk_target = |root: &str| CargoTarget {
            root: PathBuf::from(root),
            dev_id: 1,
            ino: 1,
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
            root_mtime_unix: 500,
            allocated_bytes: 1024,
            last_activity_unix: 500,
        };

        let mut state = State::new_default();
        state.record_scan_targets(
            &[mk_target("/a/target"), mk_target("/b/target")],
            1000,
            true,
            false,
        );
        assert_eq!(state.known_targets.len(), 2);
        assert_eq!(state.last_full_walk_unix, Some(1000));

        // Partial walk only saw /a/target -> must keep /b/target and not advance last_full_walk
        state.record_scan_targets(&[mk_target("/a/target")], 1100, true, true);
        assert_eq!(state.known_targets.len(), 2);
        assert_eq!(state.last_full_walk_unix, Some(1000));

        // Complete full walk only saw /a/target -> retires /b/target and advances last_full_walk
        state.record_scan_targets(&[mk_target("/a/target")], 1200, true, false);
        assert_eq!(state.known_targets.len(), 1);
        assert_eq!(
            state.known_targets[Path::new("/a/target")].first_seen_unix,
            1000
        );
        assert_eq!(state.last_full_walk_unix, Some(1200));
    }
}
