//! Functional Core (Layer 1): persistent `State` schema (`KnownTargetEntry`,
//! `PinEntry`, `ReclaimHoldState`, `DiskPressure`) and pure transitions.
//!
//! Allowed dependencies: `model`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::{
    DiskPressure, KnownTargetEntry, PinEntry, PinScope, ReclaimHoldState, SCHEMA_VERSION,
};

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
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::State;
    use crate::model::{DiskPressure, PinEntry, PinScope, SCHEMA_VERSION};

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
}
