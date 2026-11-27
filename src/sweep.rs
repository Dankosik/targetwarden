//! Functional Core (Layer 2): surgical build-unit reachability graph (`V2` and `V1`
//! independently in `MixedV1V2`), multi-JSON anchoring, active `rustc_hash`,
//! two-level `incremental/` (`Finalized` vs `WorkingOnly`), and `target/doc/` pruning.
//!
//! Allowed dependencies: `model`, `config`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use smallvec::SmallVec;

use crate::config::Config;
use crate::model::{
    BuildUnit, BuildUnitId, CargoTarget, DiskPressure, FastU64BuildHasher, IncrementalDir,
    IncrementalRemoval, ProfileDir, ReclaimAction, SessionState, SweepOps, SweepUnitReason,
    TargetLayout, UnitMetadata, UnitTargetKind, V1UnitRemoval, V2UnitRemoval,
};

/// Plan all `R2` (`SweepBuildUnits` + `RemoveDoc`) and `R3` (`PruneIncremental`) actions
/// for a single non-protected target.
pub(crate) fn plan_target_sweeps(
    target: &CargoTarget,
    pinned_unit_paths: &[PathBuf],
    now_unix: u64,
    pressure: DiskPressure,
    config: &Config,
) -> Vec<ReclaimAction> {
    let mut actions = Vec::new();

    for profile in &target.profiles {
        if profile.layout == TargetLayout::ArtifactsOnly || profile.locked_now {
            continue;
        }
        if let Some(build_action) = plan_profile_build_sweep(
            target,
            profile,
            pinned_unit_paths,
            now_unix,
            pressure,
            config,
        ) {
            actions.push(build_action);
        }
        if let Some(inc_action) =
            plan_profile_incremental_prune(target, profile, now_unix, pressure, config)
        {
            actions.push(inc_action);
        }
    }

    if let Some(doc_action) = plan_doc_prune(target, now_unix, pressure, config) {
        actions.push(doc_action);
    }

    actions
}

/// Plan `R2` build-unit sweep for one profile (`V2` and `V1` analyzed independently).
pub(crate) fn plan_profile_build_sweep(
    target: &CargoTarget,
    profile: &ProfileDir,
    pinned_unit_paths: &[PathBuf],
    now_unix: u64,
    pressure: DiskPressure,
    config: &Config,
) -> Option<ReclaimAction> {
    if profile.layout == TargetLayout::ArtifactsOnly || profile.fingerprint_corrupt {
        return None;
    }

    let profile_path = target.root.join(&profile.rel_path);
    let stale_gap = config.sweep.mixed_stale_layer_secs(pressure);

    let v2_max = max_complete_mtime(&profile.v2_units);
    let v1_max = max_complete_mtime(&profile.v1_units);

    let (drop_v2_anchors, drop_v1_anchors) = match (v2_max, v1_max) {
        (Some(t2), Some(t1)) => (
            t1 > t2.saturating_add(stale_gap),
            t2 > t1.saturating_add(stale_gap),
        ),
        _ => (false, false),
    };

    let v2_removals = sweep_v2_layer(
        &profile.v2_units,
        &profile.dep_fp_pool,
        drop_v2_anchors,
        &profile_path,
        pinned_unit_paths,
        now_unix,
        pressure,
        config,
    );
    let v1_removals = sweep_v1_layer(
        profile,
        drop_v1_anchors,
        &profile_path,
        pinned_unit_paths,
        now_unix,
        pressure,
        config,
    );

    if v2_removals.is_empty() && v1_removals.is_empty() {
        return None;
    }

    let v2_bytes: u64 = v2_removals
        .iter()
        .map(|u| u.allocated_bytes)
        .fold(0u64, u64::saturating_add);
    let v1_bytes: u64 = v1_removals
        .iter()
        .map(|u| u.allocated_bytes)
        .fold(0u64, u64::saturating_add);
    let estimated_allocated_bytes = v2_bytes.saturating_add(v1_bytes);

    let ops = match (v2_removals.is_empty(), v1_removals.is_empty()) {
        (false, true) => SweepOps::V2(v2_removals),
        (true, false) => SweepOps::V1(v1_removals),
        (false, false) => SweepOps::Mixed {
            v2: v2_removals,
            v1: v1_removals,
        },
        (true, true) => return None,
    };

    Some(ReclaimAction::SweepBuildUnits {
        target_root: target.root.clone(),
        target_dev: target.dev_id,
        target_ino: target.ino,
        expected_profile_mtime_unix: profile.profile_mtime_unix,
        expected_activity_unix: profile.last_activity_unix,
        expected_target_activity_unix: target.last_activity_unix,
        worktree_root: target.worktree_root().map(Path::to_path_buf),
        profile_rel: profile.rel_path.clone(),
        profile_locks: profile.lock_files.clone(),
        ops,
        estimated_allocated_bytes,
    })
}

fn max_complete_mtime(units: &[BuildUnit]) -> Option<u64> {
    units
        .iter()
        .filter_map(|u| match &u.metadata {
            UnitMetadata::Complete { mtime_unix, .. } => Some(*mtime_unix),
            UnitMetadata::Incomplete { .. } => None,
        })
        .max()
}

#[allow(clippy::too_many_arguments)]
fn sweep_v2_layer(
    units: &[BuildUnit],
    dep_fp_pool: &[u64],
    drop_anchors: bool,
    profile_path: &Path,
    pinned_unit_paths: &[PathBuf],
    now_unix: u64,
    pressure: DiskPressure,
    config: &Config,
) -> Vec<V2UnitRemoval> {
    let selected = select_swept_units(
        units,
        dep_fp_pool,
        drop_anchors,
        profile_path,
        pinned_unit_paths,
        now_unix,
        pressure,
        config,
    );
    let mut removals: Vec<V2UnitRemoval> = selected
        .into_iter()
        .filter_map(|(idx, reason)| match &units[idx].id {
            BuildUnitId::V2 { pkg, unit_hash } => Some(V2UnitRemoval {
                pkg: pkg.clone(),
                unit_hash: unit_hash.clone(),
                allocated_bytes: units[idx].allocated_bytes,
                reason,
            }),
            BuildUnitId::V1 { .. } => None,
        })
        .collect();
    removals.sort_by(|a, b| {
        a.pkg
            .cmp(&b.pkg)
            .then_with(|| a.unit_hash.cmp(&b.unit_hash))
    });
    removals
}

#[allow(clippy::too_many_arguments)]
fn sweep_v1_layer(
    profile: &ProfileDir,
    drop_anchors: bool,
    profile_path: &Path,
    pinned_unit_paths: &[PathBuf],
    now_unix: u64,
    pressure: DiskPressure,
    config: &Config,
) -> Vec<V1UnitRemoval> {
    let units = &profile.v1_units;
    let selected = select_swept_units(
        units,
        &profile.dep_fp_pool,
        drop_anchors,
        profile_path,
        pinned_unit_paths,
        now_unix,
        pressure,
        config,
    );
    let mut removals: Vec<V1UnitRemoval> = selected
        .into_iter()
        .filter_map(|(idx, reason)| match &units[idx].id {
            BuildUnitId::V1 {
                fingerprint_dir,
                unit_hash,
            } => Some(V1UnitRemoval {
                fingerprint_dir: fingerprint_dir.clone(),
                unit_hash: unit_hash.clone(),
                build_dir: units[idx].v1_build_dir().cloned(),
                dep_entries: Vec::new(),
                sweep_deps_by_hash: units[idx].v1_dep_entry_count() > 0,
                allocated_bytes: units[idx].allocated_bytes,
                reason,
            }),
            BuildUnitId::V2 { .. } => None,
        })
        .collect();
    removals.sort_by(|a, b| {
        a.fingerprint_dir
            .cmp(&b.fingerprint_dir)
            .then_with(|| a.unit_hash.cmp(&b.unit_hash))
            .then_with(|| a.build_dir.cmp(&b.build_dir))
            .then_with(|| a.dep_entries.cmp(&b.dep_entries))
    });
    removals
}

/// Core R2 reachability engine over one homogeneous build-unit layer (V2 or V1).
#[allow(clippy::too_many_arguments)]
fn select_swept_units(
    units: &[BuildUnit],
    dep_fp_pool: &[u64],
    drop_anchors: bool,
    profile_path: &Path,
    pinned_unit_paths: &[PathBuf],
    now_unix: u64,
    pressure: DiskPressure,
    config: &Config,
) -> Vec<(usize, SweepUnitReason)> {
    if units.is_empty() {
        return Vec::new();
    }

    let dup_cooldown = config.sweep.dup_cooldown_secs(pressure);
    let mut keep = vec![false; units.len()];
    let mut stack: Vec<usize> = Vec::with_capacity(units.len().min(64));

    // 1. Derive active `rustc_hash` set strictly from Complete units within `max_mtime - 24h`.
    let max_mtime = max_complete_mtime(units);
    let mut active_rustc_hashes: SmallVec<[u64; 4]> = SmallVec::new();
    if let Some(max_t) = max_mtime {
        let cutoff = max_t.saturating_sub(config.sweep.active_rustc_window_secs);
        for unit in units {
            if let UnitMetadata::Complete {
                rustc_hash,
                mtime_unix,
                ..
            } = &unit.metadata
                && *mtime_unix >= cutoff
                && !active_rustc_hashes.contains(rustc_hash)
            {
                active_rustc_hashes.push(*rustc_hash);
            }
        }
    }

    // 2. Index every companion fingerprint hash -> unit indices (handles multi-JSON & collisions).
    let mut by_fp_hash: HashMap<u64, SmallVec<[usize; 2]>, FastU64BuildHasher> =
        HashMap::with_capacity_and_hasher(units.len(), FastU64BuildHasher);
    for (idx, unit) in units.iter().enumerate() {
        if let UnitMetadata::Complete { targets, .. } = &unit.metadata {
            for anchor in targets {
                if let Some(fp_hash) = anchor.fingerprint_hash {
                    by_fp_hash.entry(fp_hash).or_default().push(idx);
                }
            }
        }
    }

    let mark_keep = |idx: usize, keep: &mut [bool], stack: &mut Vec<usize>| {
        if !keep[idx] {
            keep[idx] = true;
            stack.push(idx);
        }
    };

    // 3. Seed: auto-pinned proc-macro `.dylib` paths and units inside `dup_cooldown`.
    let pinned_rel: SmallVec<[&Path; 4]> = pinned_unit_paths
        .iter()
        .filter_map(|p| p.strip_prefix(profile_path).ok())
        .collect();
    for (idx, unit) in units.iter().enumerate() {
        let age = now_unix.saturating_sub(unit.metadata.mtime_unix());
        if age < dup_cooldown || unit_matches_pinned_rel(unit, &pinned_rel) {
            mark_keep(idx, &mut keep, &mut stack);
        }
    }

    // 4. Seed: top-K active units per `(pkg_group, target_kind, target_name)` across all JSON anchors,
    //    skipping anchors that are stale relative to the profile's latest build (`max_t`).
    //    Live dependencies of any age remain 100% protected via reachability traversal in step 5.
    if !drop_anchors
        && !active_rustc_hashes.is_empty()
        && let Some(max_t) = max_mtime
    {
        type GroupKey<'a> = (&'a str, UnitTargetKind, &'a str);
        let mut groups: HashMap<GroupKey<'_>, SmallVec<[(u64, usize); 2]>> =
            HashMap::with_capacity(units.len());

        for (idx, unit) in units.iter().enumerate() {
            if let UnitMetadata::Complete {
                targets,
                rustc_hash,
                mtime_unix,
                ..
            } = &unit.metadata
                && active_rustc_hashes.contains(rustc_hash)
            {
                let lag_secs = max_t.saturating_sub(*mtime_unix);
                for anchor in targets {
                    if lag_secs > config.sweep.stale_anchor_secs(anchor.target_kind, pressure) {
                        continue;
                    }
                    groups
                        .entry((
                            unit.pkg_group(),
                            anchor.target_kind,
                            anchor.target_name.as_str(),
                        ))
                        .or_default()
                        .push((*mtime_unix, idx));
                }
            }
        }

        let default_k = config.sweep.anchor_slots_k(pressure);
        for ((_, kind, _), mut members) in groups {
            if members.len() > 1 {
                members.sort_by(|a, b| {
                    b.0.cmp(&a.0).then_with(|| {
                        unit_sort_key(&units[a.1].id).cmp(&unit_sort_key(&units[b.1].id))
                    })
                });
            }
            let k = if kind == UnitTargetKind::Test {
                1
            } else {
                default_k
            };
            for &(_, idx) in members.iter().take(k) {
                mark_keep(idx, &mut keep, &mut stack);
            }
        }
    }

    // 5. Graph reachability over `dep_fp_pool` protects live dependencies regardless of `mtime`.
    while let Some(idx) = stack.pop() {
        if let UnitMetadata::Complete {
            dep_fp_start,
            dep_fp_len,
            ..
        } = &units[idx].metadata
        {
            let start = *dep_fp_start as usize;
            let end = start.saturating_add(*dep_fp_len as usize);
            if let Some(dep_fp_hashes) = dep_fp_pool.get(start..end) {
                for &dep_hash in dep_fp_hashes {
                    if let Some(dep_indices) = by_fp_hash.get(&dep_hash) {
                        for &dep_idx in dep_indices {
                            if !keep[dep_idx] {
                                keep[dep_idx] = true;
                                stack.push(dep_idx);
                            }
                        }
                    }
                }
            }
        }
    }

    // 6. Emit swept units with explicit reason.
    let mut swept = Vec::new();
    for (idx, unit) in units.iter().enumerate() {
        if keep[idx] {
            continue;
        }
        let reason = match &unit.metadata {
            UnitMetadata::Incomplete { .. } => SweepUnitReason::IncompleteAbortedUnit,
            UnitMetadata::Complete { rustc_hash, .. } => {
                if active_rustc_hashes.contains(rustc_hash) {
                    SweepUnitReason::UnreachableDuplicate
                } else {
                    SweepUnitReason::StaleRustcHash
                }
            }
        };
        swept.push((idx, reason));
    }
    swept
}

fn unit_sort_key(id: &BuildUnitId) -> (&str, &str) {
    match id {
        BuildUnitId::V2 { pkg, unit_hash } => (pkg.as_str(), unit_hash.as_str()),
        BuildUnitId::V1 {
            fingerprint_dir,
            unit_hash,
        } => (fingerprint_dir.as_deref().unwrap_or(""), unit_hash.as_str()),
    }
}

fn unit_matches_pinned_rel(unit: &BuildUnit, pinned_rel: &[&Path]) -> bool {
    if pinned_rel.is_empty() {
        return false;
    }
    match &unit.id {
        BuildUnitId::V2 { pkg, unit_hash } => pinned_rel.iter().any(|rel| {
            let mut comps = rel.components();
            comps.next().and_then(|c| c.as_os_str().to_str()) == Some("build")
                && comps.next().and_then(|c| c.as_os_str().to_str()) == Some(pkg.as_str())
                && comps.next().and_then(|c| c.as_os_str().to_str()) == Some(unit_hash.as_str())
        }),
        BuildUnitId::V1 {
            fingerprint_dir,
            unit_hash,
        } => pinned_rel.iter().any(|rel| {
            let mut comps = rel.components();
            let Some(first) = comps.next().and_then(|c| c.as_os_str().to_str()) else {
                return false;
            };
            match first {
                ".fingerprint" => fingerprint_dir.as_deref().is_some_and(|fp| {
                    comps.next().and_then(|c| c.as_os_str().to_str()) == Some(fp)
                }),
                "build" => unit.v1_build_dir().is_some_and(|bd| {
                    comps.next().and_then(|c| c.as_os_str().to_str()) == Some(bd.as_str())
                }),
                "deps" => rel
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name.contains(unit_hash.as_str())),
                _ => false,
            }
        }),
    }
}

/// Plan `R2-doc` pruning of `target/doc/` when unlocked and older than threshold.
pub(crate) fn plan_doc_prune(
    target: &CargoTarget,
    now_unix: u64,
    pressure: DiskPressure,
    config: &Config,
) -> Option<ReclaimAction> {
    let doc = target.doc_dir.as_ref()?;
    if doc.locked_now {
        return None;
    }
    let age = now_unix.saturating_sub(doc.last_activity_unix);
    if age < config.sweep.doc_prune_age_secs(pressure) {
        return None;
    }
    let mut locks: SmallVec<[PathBuf; 5]> = SmallVec::new();
    for profile in &target.profiles {
        for lock in &profile.lock_files {
            locks.push(lock.clone());
        }
    }
    if let Some(root_lock) = &target.root_lock_file {
        locks.push(root_lock.clone());
    }
    if let Some(doc_lock) = &doc.lock_file {
        locks.push(doc_lock.clone());
    }
    locks.sort();
    locks.dedup();

    Some(ReclaimAction::RemoveDoc {
        target_root: target.root.clone(),
        target_dev: target.dev_id,
        target_ino: target.ino,
        expected_doc_mtime_unix: doc.last_activity_unix,
        worktree_root: target.worktree_root().map(Path::to_path_buf),
        locks,
        estimated_allocated_bytes: doc.allocated_bytes,
    })
}

/// Plan two-level `R3` `incremental/` pruning for one profile.
/// Level 1 partitions `<crate>-<base36>/` into `Finalized` vs `WorkingOnly` (`WorkingOnly`
/// never consumes `M` finalized slots). Level 2 prunes stale sessions inside kept dirs.
pub(crate) fn plan_profile_incremental_prune(
    target: &CargoTarget,
    profile: &ProfileDir,
    now_unix: u64,
    pressure: DiskPressure,
    config: &Config,
) -> Option<ReclaimAction> {
    if profile.layout == TargetLayout::ArtifactsOnly || profile.incremental_dirs.is_empty() {
        return None;
    }

    let inc_cooldown = config.sweep.inc_cooldown_secs(pressure);
    let keep_m = config.sweep.inc_finalized_keep_m(pressure);
    let stale_crate_window = config.sweep.inc_stale_crate_secs(pressure);
    let max_inc_mtime = profile
        .incremental_dirs
        .iter()
        .map(|d| d.latest_mtime_unix)
        .max()
        .unwrap_or(0);

    let mut groups: BTreeMap<&str, SmallVec<[&IncrementalDir; 4]>> = BTreeMap::new();
    for dir in &profile.incremental_dirs {
        groups.entry(dir.crate_name.as_str()).or_default().push(dir);
    }

    let mut removals: Vec<IncrementalRemoval> = Vec::new();
    let mut finalized: SmallVec<[&IncrementalDir; 4]> = SmallVec::new();
    let mut working_only: SmallVec<[&IncrementalDir; 4]> = SmallVec::new();
    let mut sorted_sessions: SmallVec<[&crate::model::IncrementalSession; 4]> = SmallVec::new();

    for (_, dirs) in groups {
        finalized.clear();
        working_only.clear();

        for dir in dirs {
            if dir.has_finalized() {
                finalized.push(dir);
            } else {
                working_only.push(dir);
            }
        }

        // Level 1a: unlocked `WorkingOnly` dirs older than `inc_cooldown` are removed without
        // consuming finalized `M` slots.
        working_only.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
        for &dir in &working_only {
            let age = now_unix.saturating_sub(dir.latest_mtime_unix);
            if !dir.any_locked && age >= inc_cooldown {
                removals.push(IncrementalRemoval::WholeCrateDir {
                    dir_name: dir.dir_name.clone(),
                    expected_dir_mtime_unix: dir.dir_mtime_unix,
                    allocated_bytes: dir.allocated_bytes,
                });
            }
        }

        // Level 1b: keep top `M` non-stale finalized dirs (+ any locked or cooling dir).
        // Crates/tests untouched for > `stale_crate_window` behind the profile's latest
        // incremental compile drop their `M` slot so deleted tests/crates do not linger forever.
        finalized.sort_by(|a, b| {
            b.latest_mtime_unix
                .cmp(&a.latest_mtime_unix)
                .then_with(|| a.dir_name.cmp(&b.dir_name))
        });

        for (rank, &dir) in finalized.iter().enumerate() {
            let age = now_unix.saturating_sub(dir.latest_mtime_unix);
            let stale_crate =
                max_inc_mtime.saturating_sub(dir.latest_mtime_unix) > stale_crate_window;
            let keep_dir = (!stale_crate && rank < keep_m) || dir.any_locked || age < inc_cooldown;
            if !keep_dir {
                removals.push(IncrementalRemoval::WholeCrateDir {
                    dir_name: dir.dir_name.clone(),
                    expected_dir_mtime_unix: dir.dir_mtime_unix,
                    allocated_bytes: dir.allocated_bytes,
                });
                continue;
            }

            // Level 2: inside kept finalized dir, retain newest `Finalized` session (+ locked/cooling).
            let newest_finalized = dir
                .sessions
                .iter()
                .filter(|s| s.state == SessionState::Finalized)
                .max_by(|a, b| {
                    a.mtime_unix
                        .cmp(&b.mtime_unix)
                        .then_with(|| b.dir_name.cmp(&a.dir_name))
                })
                .map(|s| s.dir_name.as_str());

            sorted_sessions.clear();
            sorted_sessions.extend(dir.sessions.iter());
            sorted_sessions.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
            for &session in &sorted_sessions {
                if newest_finalized == Some(session.dir_name.as_str()) {
                    continue;
                }
                let sess_age = now_unix.saturating_sub(session.mtime_unix);
                if !session.locked && sess_age >= inc_cooldown {
                    removals.push(IncrementalRemoval::SingleSession {
                        crate_dir: dir.dir_name.clone(),
                        session_dir: session.dir_name.clone(),
                        lock_file: session.lock_file.clone(),
                        allocated_bytes: session.allocated_bytes,
                    });
                }
            }
        }
    }

    if removals.is_empty() {
        return None;
    }

    let estimated_allocated_bytes = removals
        .iter()
        .map(|r| match r {
            IncrementalRemoval::WholeCrateDir {
                allocated_bytes, ..
            }
            | IncrementalRemoval::SingleSession {
                allocated_bytes, ..
            } => *allocated_bytes,
        })
        .fold(0u64, u64::saturating_add);

    Some(ReclaimAction::PruneIncremental {
        target_root: target.root.clone(),
        target_dev: target.dev_id,
        target_ino: target.ino,
        expected_inc_root_mtime_unix: profile.inc_root_mtime_unix,
        expected_activity_unix: profile.last_activity_unix,
        expected_target_activity_unix: target.last_activity_unix,
        worktree_root: target.worktree_root().map(Path::to_path_buf),
        profile_rel: profile.rel_path.clone(),
        profile_locks: profile.lock_files.clone(),
        removals,
        estimated_allocated_bytes,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use compact_str::CompactString;
    use smallvec::SmallVec;

    use super::{plan_doc_prune, plan_profile_build_sweep, plan_profile_incremental_prune};
    use crate::config::Config;
    use crate::model::{
        BuildUnit, BuildUnitId, CargoTarget, DiskPressure, DocDirInfo, GitDiscovery,
        IncrementalDir, IncrementalRemoval, IncrementalSession, ProfileDir, ReclaimAction,
        SessionState, SweepOps, SweepUnitReason, TargetLayout, TargetOrigin, UnitMetadata,
        UnitTargetAnchor, UnitTargetKind, V1UnitExtras, WorktreeKind,
    };

    const NOW: u64 = 1_800_000_000;
    const HOUR: u64 = 3600;
    const DAY: u64 = 86_400;

    fn mk_target(profile: ProfileDir, doc_dir: Option<DocDirInfo>) -> CargoTarget {
        CargoTarget {
            root: PathBuf::from("/Users/dev/repo/target"),
            dev_id: 1,
            ino: 2,
            origin: TargetOrigin::VerifiedCargoTag,
            layout: profile.layout,
            symlink_or_mount_boundary: false,
            has_unverified_top_entries: false,
            has_pin_marker: false,
            parent_target: None,
            nested_target_roots: vec![],
            worktree_kind: WorktreeKind::MainCheckout,
            git: GitDiscovery::NotInGitRepo,
            project_dir: Some(PathBuf::from("/Users/dev/repo")),
            profiles: vec![profile],
            doc_dir,
            root_lock_file: None,
            root_locked_now: false,
            root_mtime_unix: NOW - 3 * HOUR,
            allocated_bytes: 10_000_000,
            last_activity_unix: NOW - 3 * HOUR,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_v2_unit(
        profile: &mut ProfileDir,
        pkg: &str,
        hash: &str,
        kind: UnitTargetKind,
        target_name: &str,
        fp_hash: Option<u64>,
        rustc: u64,
        deps: &[u64],
        mtime: u64,
        bytes: u64,
    ) {
        let mut targets = SmallVec::new();
        targets.push(UnitTargetAnchor {
            target_kind: kind,
            target_name: CompactString::from(target_name),
            fingerprint_hash: fp_hash,
        });
        let dep_fp_start = u32::try_from(profile.dep_fp_pool.len()).unwrap();
        profile.dep_fp_pool.extend_from_slice(deps);
        let dep_fp_len = u32::try_from(deps.len()).unwrap();
        profile.v2_units.push(BuildUnit {
            id: BuildUnitId::V2 {
                pkg: CompactString::from(pkg),
                unit_hash: CompactString::from(hash),
            },
            metadata: UnitMetadata::Complete {
                targets,
                rustc_hash: rustc,
                dep_fp_start,
                dep_fp_len,
                mtime_unix: mtime,
            },
            v1: None,
            allocated_bytes: bytes,
        });
    }

    fn base_profile(layout: TargetLayout) -> ProfileDir {
        ProfileDir {
            name: CompactString::new("debug"),
            rel_path: PathBuf::from("debug"),
            layout,
            lock_files: SmallVec::new(),
            locked_now: false,
            fingerprint_corrupt: false,
            v2_unit_count: 0,
            v1_unit_count: 0,
            incremental_dir_count: 0,
            v2_units: vec![],
            v1_units: vec![],
            dep_fp_pool: vec![],
            incremental_dirs: vec![],
            profile_mtime_unix: NOW - 3 * HOUR,
            inc_root_mtime_unix: NOW - 3 * HOUR,
            allocated_bytes: 0,
            last_activity_unix: NOW - 3 * HOUR,
        }
    }

    #[test]
    fn bfs_protects_5_day_live_dependency_while_sweeping_stale_rustc_duplicates_and_incomplete() {
        let cfg = Config::default();
        let active_rustc = 4_106_920_547_260_086_991;
        let old_rustc = 1_111_111_111_111_111_111;

        let mut profile = base_profile(TargetLayout::BuildDirV2);
        // Active bin built 3h ago depends on 5-day-old dep_lib (fp=100) which depends on 10-day-old build-script (fp=200)
        push_v2_unit(
            &mut profile,
            "app",
            "0000000000000001",
            UnitTargetKind::Bin,
            "app",
            Some(10),
            active_rustc,
            &[100],
            NOW - 3 * HOUR,
            500,
        );
        // 5-day-old live dependency (reachable via BFS) -> MUST SURVIVE!
        push_v2_unit(
            &mut profile,
            "dep_lib",
            "0000000000000002",
            UnitTargetKind::Lib,
            "dep_lib",
            Some(100),
            active_rustc,
            &[200],
            NOW - 5 * DAY,
            1000,
        );
        // 10-day-old transitive build script -> MUST SURVIVE!
        push_v2_unit(
            &mut profile,
            "dep_lib",
            "0000000000000003",
            UnitTargetKind::RunBuildScript,
            "build",
            Some(200),
            active_rustc,
            &[],
            NOW - 10 * DAY,
            400,
        );
        // Unreachable old duplicate of dep_lib (K=2 in Calm, so make 3 copies of dep_lib; wait: dep_lib #2 is active, add #4 newer & #5 older)
        push_v2_unit(
            &mut profile,
            "dep_lib",
            "0000000000000004",
            UnitTargetKind::Lib,
            "dep_lib",
            Some(101),
            active_rustc,
            &[],
            NOW - 4 * DAY,
            1000,
        );
        push_v2_unit(
            &mut profile,
            "dep_lib",
            "0000000000000005",
            UnitTargetKind::Lib,
            "dep_lib",
            Some(102),
            active_rustc,
            &[],
            NOW - 6 * DAY,
            1000,
        );
        // Stale rustc_hash unit -> MUST BE SWEPT with StaleRustcHash
        push_v2_unit(
            &mut profile,
            "old_crate",
            "0000000000000006",
            UnitTargetKind::Lib,
            "old_crate",
            Some(300),
            old_rustc,
            &[],
            NOW - 4 * DAY,
            2000,
        );
        // Incomplete aborted unit older than 2h -> MUST BE SWEPT with IncompleteAbortedUnit
        profile.v2_units.push(BuildUnit {
            id: BuildUnitId::V2 {
                pkg: CompactString::new("aborted"),
                unit_hash: CompactString::new("0000000000000007"),
            },
            metadata: UnitMetadata::Incomplete {
                mtime_unix: NOW - 3 * HOUR,
            },
            v1: None,
            allocated_bytes: 300,
        });
        // Incomplete unit within 2h cooldown (30m old) -> MUST SURVIVE
        profile.v2_units.push(BuildUnit {
            id: BuildUnitId::V2 {
                pkg: CompactString::new("fresh_aborted"),
                unit_hash: CompactString::new("0000000000000008"),
            },
            metadata: UnitMetadata::Incomplete {
                mtime_unix: NOW - 1800,
            },
            v1: None,
            allocated_bytes: 300,
        });

        let target = mk_target(profile, None);
        let action = plan_profile_build_sweep(
            &target,
            &target.profiles[0],
            &[],
            NOW,
            DiskPressure::Calm,
            &cfg,
        )
        .expect("expected sweep action");

        let ReclaimAction::SweepBuildUnits {
            ops: SweepOps::V2(removals),
            ..
        } = action
        else {
            panic!("expected V2 sweep ops");
        };

        let swept_hashes: Vec<(&str, SweepUnitReason)> = removals
            .iter()
            .map(|r| (r.unit_hash.as_str(), r.reason))
            .collect();
        // 5-day dep (0002), 10-day build script (0003), top-2 dep_lib (0004), fresh incomplete (0008) survive!
        assert!(!swept_hashes.iter().any(|(h, _)| *h == "0000000000000001"));
        assert!(!swept_hashes.iter().any(|(h, _)| *h == "0000000000000002"));
        assert!(!swept_hashes.iter().any(|(h, _)| *h == "0000000000000003"));
        assert!(!swept_hashes.iter().any(|(h, _)| *h == "0000000000000008"));

        assert!(
            swept_hashes.contains(&("0000000000000005", SweepUnitReason::UnreachableDuplicate))
        );
        assert!(swept_hashes.contains(&("0000000000000006", SweepUnitReason::StaleRustcHash)));
        assert!(
            swept_hashes.contains(&("0000000000000007", SweepUnitReason::IncompleteAbortedUnit))
        );
    }

    #[test]
    fn multi_json_anchoring_test_k1_and_proc_macro_pin_work() {
        let cfg = Config::default();
        let rustc = 999;
        let mut profile = base_profile(TargetLayout::BuildDirV2);

        // Two leaf test binaries: testK = 1 even in Calm -> older test swept
        push_v2_unit(
            &mut profile,
            "app",
            "aaaaaaaaaaaaaaaa",
            UnitTargetKind::Test,
            "it_cli",
            Some(1),
            rustc,
            &[],
            NOW - 3 * HOUR,
            100,
        );
        push_v2_unit(
            &mut profile,
            "app",
            "bbbbbbbbbbbbbbbb",
            UnitTargetKind::Test,
            "it_cli",
            Some(2),
            rustc,
            &[],
            NOW - 5 * HOUR,
            100,
        );
        // Proc-macro unit with stale rustc, but auto-pinned via `pinned_unit_paths` -> survives!
        push_v2_unit(
            &mut profile,
            "my_macro",
            "cccccccccccccccc",
            UnitTargetKind::Lib,
            "my_macro",
            Some(3),
            111,
            &[],
            NOW - 5 * DAY,
            100,
        );

        let target = mk_target(profile, None);
        let pin_path = target
            .root
            .join("debug/build/my_macro/cccccccccccccccc/out/libmy_macro.dylib");

        let action = plan_profile_build_sweep(
            &target,
            &target.profiles[0],
            &[pin_path],
            NOW,
            DiskPressure::Calm,
            &cfg,
        )
        .unwrap();
        let ReclaimAction::SweepBuildUnits {
            ops: SweepOps::V2(removals),
            ..
        } = action
        else {
            panic!("expected V2");
        };
        assert_eq!(removals.len(), 1);
        assert_eq!(removals[0].unit_hash.as_str(), "bbbbbbbbbbbbbbbb");
    }

    #[test]
    fn mixed_v1_v2_expires_stale_layer_and_corrupt_fingerprint_fails_closed() {
        let cfg = Config::default();
        let mut profile = base_profile(TargetLayout::MixedV1V2);
        push_v2_unit(
            &mut profile,
            "app",
            "1111111111111111",
            UnitTargetKind::Bin,
            "app",
            Some(1),
            200,
            &[],
            NOW - 3 * HOUR,
            100,
        );
        let mut v1_targets = SmallVec::new();
        v1_targets.push(UnitTargetAnchor {
            target_kind: UnitTargetKind::Bin,
            target_name: CompactString::new("app"),
            fingerprint_hash: Some(2),
        });
        profile.v1_units = vec![BuildUnit {
            id: BuildUnitId::V1 {
                fingerprint_dir: Some(CompactString::new("app-2222222222222222")),
                unit_hash: CompactString::new("2222222222222222"),
            },
            metadata: UnitMetadata::Complete {
                targets: v1_targets,
                rustc_hash: 100,
                dep_fp_start: 0,
                dep_fp_len: 0,
                mtime_unix: NOW - 10 * DAY, // > 7d older than V2 layer in Calm -> stale layer!
            },
            v1: Some(Box::new(V1UnitExtras {
                pkg_group: CompactString::new("app"),
                build_dir: None,
                dep_entry_count: 1,
            })),
            allocated_bytes: 500,
        }];

        let mut target = mk_target(profile, None);
        let action = plan_profile_build_sweep(
            &target,
            &target.profiles[0],
            &[],
            NOW,
            DiskPressure::Calm,
            &cfg,
        )
        .unwrap();
        assert!(matches!(
            action,
            ReclaimAction::SweepBuildUnits {
                ops: SweepOps::V1(ref v1),
                ..
            } if v1.len() == 1 && v1[0].fingerprint_dir.as_deref() == Some("app-2222222222222222")
        ));

        // Corrupt fingerprint -> profile-local fail-closed (None)
        target.profiles[0].fingerprint_corrupt = true;
        assert!(
            plan_profile_build_sweep(
                &target,
                &target.profiles[0],
                &[],
                NOW,
                DiskPressure::Calm,
                &cfg,
            )
            .is_none()
        );
    }

    #[test]
    fn incremental_working_only_never_evicts_finalized_and_level2_prunes_old_sessions() {
        let cfg = Config::default();
        let mut profile = base_profile(TargetLayout::BuildDirV2);

        // Two WorkingOnly dirs newer than Finalized dirs must NEVER consume Finalized M=2 slots!
        let working_only_new = IncrementalDir {
            dir_name: CompactString::new("app-work000000001"),
            crate_name: CompactString::new("app"),
            sessions: smallvec::smallvec![IncrementalSession {
                dir_name: CompactString::new("s-001-aaa-working"),
                lock_file: Some(CompactString::new("s-001-aaa.lock")),
                state: SessionState::Working,
                locked: false,
                mtime_unix: NOW - 3 * HOUR,
                allocated_bytes: 200,
            }],
            any_locked: false,
            dir_mtime_unix: NOW - 3 * HOUR,
            latest_mtime_unix: NOW - 3 * HOUR,
            allocated_bytes: 200,
        };
        let finalized_1 = IncrementalDir {
            dir_name: CompactString::new("app-fin0000000001"),
            crate_name: CompactString::new("app"),
            sessions: smallvec::smallvec![
                IncrementalSession {
                    dir_name: CompactString::new("s-002-bbb-finalnew"),
                    lock_file: Some(CompactString::new("s-002-bbb.lock")),
                    state: SessionState::Finalized,
                    locked: false,
                    mtime_unix: NOW - 4 * HOUR,
                    allocated_bytes: 1000,
                },
                IncrementalSession {
                    dir_name: CompactString::new("s-001-aaa-finalold"),
                    lock_file: Some(CompactString::new("s-001-aaa.lock")),
                    state: SessionState::Finalized,
                    locked: false,
                    mtime_unix: NOW - 10 * HOUR,
                    allocated_bytes: 600,
                },
                IncrementalSession {
                    dir_name: CompactString::new("s-000-zzz-working"),
                    lock_file: None,
                    state: SessionState::Working,
                    locked: false,
                    mtime_unix: NOW - 12 * HOUR,
                    allocated_bytes: 300,
                },
            ],
            any_locked: false,
            dir_mtime_unix: NOW - 4 * HOUR,
            latest_mtime_unix: NOW - 4 * HOUR,
            allocated_bytes: 1900,
        };
        let finalized_2 = IncrementalDir {
            dir_name: CompactString::new("app-fin0000000002"),
            crate_name: CompactString::new("app"),
            sessions: smallvec::smallvec![IncrementalSession {
                dir_name: CompactString::new("s-001-ccc-final"),
                lock_file: None,
                state: SessionState::Finalized,
                locked: false,
                mtime_unix: NOW - 20 * HOUR,
                allocated_bytes: 800,
            }],
            any_locked: false,
            dir_mtime_unix: NOW - 20 * HOUR,
            latest_mtime_unix: NOW - 20 * HOUR,
            allocated_bytes: 800,
        };
        let finalized_3_old = IncrementalDir {
            dir_name: CompactString::new("app-fin0000000003"),
            crate_name: CompactString::new("app"),
            sessions: smallvec::smallvec![IncrementalSession {
                dir_name: CompactString::new("s-001-ddd-final"),
                lock_file: None,
                state: SessionState::Finalized,
                locked: false,
                mtime_unix: NOW - 40 * HOUR,
                allocated_bytes: 900,
            }],
            any_locked: false,
            dir_mtime_unix: NOW - 40 * HOUR,
            latest_mtime_unix: NOW - 40 * HOUR,
            allocated_bytes: 900,
        };

        profile.incremental_dirs =
            vec![working_only_new, finalized_1, finalized_2, finalized_3_old];
        let target = mk_target(profile, None);

        let action = plan_profile_incremental_prune(
            &target,
            &target.profiles[0],
            NOW,
            DiskPressure::Calm,
            &cfg,
        )
        .unwrap();
        let ReclaimAction::PruneIncremental { removals, .. } = action else {
            panic!("expected PruneIncremental");
        };

        // WorkingOnly removed whole; finalized_1 & finalized_2 KEPT (M=2); finalized_3 removed whole;
        // inside finalized_1, older finalized + working sessions removed via SingleSession!
        assert!(removals.contains(&IncrementalRemoval::WholeCrateDir {
            dir_name: CompactString::new("app-work000000001"),
            expected_dir_mtime_unix: NOW - 3 * HOUR,
            allocated_bytes: 200,
        }));
        assert!(removals.contains(&IncrementalRemoval::WholeCrateDir {
            dir_name: CompactString::new("app-fin0000000003"),
            expected_dir_mtime_unix: NOW - 40 * HOUR,
            allocated_bytes: 900,
        }));
        assert!(!removals.iter().any(|r| matches!(
            r,
            IncrementalRemoval::WholeCrateDir { dir_name, .. }
                if dir_name == "app-fin0000000001" || dir_name == "app-fin0000000002"
        )));
        assert!(removals.contains(&IncrementalRemoval::SingleSession {
            crate_dir: CompactString::new("app-fin0000000001"),
            session_dir: CompactString::new("s-001-aaa-finalold"),
            lock_file: Some(CompactString::new("s-001-aaa.lock")),
            allocated_bytes: 600,
        }));
        assert!(removals.contains(&IncrementalRemoval::SingleSession {
            crate_dir: CompactString::new("app-fin0000000001"),
            session_dir: CompactString::new("s-000-zzz-working"),
            lock_file: None,
            allocated_bytes: 300,
        }));
    }

    #[test]
    fn doc_dir_prunes_after_7d_in_calm_or_24h_in_high_unless_locked() {
        let cfg = Config::default();
        let profile = base_profile(TargetLayout::BuildDirV2);

        let doc_2d = DocDirInfo {
            path: PathBuf::from("/Users/dev/repo/target/doc"),
            lock_file: Some(PathBuf::from("/Users/dev/repo/target/doc/.lock")),
            locked_now: false,
            last_activity_unix: NOW - 2 * DAY,
            allocated_bytes: 5_000,
        };
        let target = mk_target(profile.clone(), Some(doc_2d.clone()));
        assert!(plan_doc_prune(&target, NOW, DiskPressure::Calm, &cfg).is_none());
        assert!(plan_doc_prune(&target, NOW, DiskPressure::High, &cfg).is_some());

        let mut doc_locked = doc_2d;
        doc_locked.locked_now = true;
        let locked_target = mk_target(profile, Some(doc_locked));
        assert!(plan_doc_prune(&locked_target, NOW, DiskPressure::High, &cfg).is_none());
    }

    #[test]
    fn stale_deleted_tests_and_removed_crates_expire_while_reachable_old_deps_and_idle_repos_survive()
     {
        let cfg = Config::default();
        let rustc = 777;
        let mut profile = base_profile(TargetLayout::BuildDirV2);

        // Fresh active app depends on a 30-day-old live dep (MUST survive via BFS!)
        // Deleted test (10d behind max_t > 7d Calm leaf TTL) and removed crate (20d > 14d Calm core TTL)
        // have active rustc_hash but are unreachable -> MUST be swept!
        push_v2_unit(
            &mut profile,
            "app",
            "1111111111111111",
            UnitTargetKind::Bin,
            "app",
            Some(10),
            rustc,
            &[20],
            NOW - 3 * HOUR,
            1000,
        );
        push_v2_unit(
            &mut profile,
            "live_old_dep",
            "2222222222222222",
            UnitTargetKind::Lib,
            "live_old_dep",
            Some(20),
            rustc,
            &[],
            NOW - 30 * DAY,
            2000,
        );
        push_v2_unit(
            &mut profile,
            "app",
            "3333333333333333",
            UnitTargetKind::Test,
            "deleted_it_test",
            Some(30),
            rustc,
            &[],
            NOW - 10 * DAY,
            1500,
        );
        push_v2_unit(
            &mut profile,
            "removed_crate",
            "4444444444444444",
            UnitTargetKind::Lib,
            "removed_crate",
            Some(40),
            rustc,
            &[],
            NOW - 20 * DAY,
            3000,
        );

        let target = mk_target(profile, None);
        let action = plan_profile_build_sweep(
            &target,
            &target.profiles[0],
            &[],
            NOW,
            DiskPressure::Calm,
            &cfg,
        )
        .expect("expected stale unreachable units to sweep");
        let ReclaimAction::SweepBuildUnits {
            ops: SweepOps::V2(removals),
            ..
        } = action
        else {
            panic!("expected V2 sweep");
        };
        let hashes: Vec<&str> = removals.iter().map(|r| r.unit_hash.as_str()).collect();
        assert!(!hashes.contains(&"1111111111111111"));
        assert!(!hashes.contains(&"2222222222222222")); // 30d live dep protected by BFS!
        assert!(hashes.contains(&"3333333333333333")); // deleted test swept
        assert!(hashes.contains(&"4444444444444444")); // removed crate swept

        // R3 incremental: stale deleted crate (20d behind active app) is swept,
        // while an entirely idle repo (where all incremental dirs are 20d old) keeps its top-M!
        let mut inc_profile = base_profile(TargetLayout::BuildDirV2);
        let fresh_inc = IncrementalDir {
            dir_name: CompactString::new("app-1111111111111"),
            crate_name: CompactString::new("app"),
            sessions: smallvec::smallvec![IncrementalSession {
                dir_name: CompactString::new("s-001-aaa-fin"),
                lock_file: None,
                state: SessionState::Finalized,
                locked: false,
                mtime_unix: NOW - 3 * HOUR,
                allocated_bytes: 500,
            }],
            any_locked: false,
            dir_mtime_unix: NOW - 3 * HOUR,
            latest_mtime_unix: NOW - 3 * HOUR,
            allocated_bytes: 500,
        };
        let dead_inc = IncrementalDir {
            dir_name: CompactString::new("deleted_test-2222222222222"),
            crate_name: CompactString::new("deleted_test"),
            sessions: smallvec::smallvec![IncrementalSession {
                dir_name: CompactString::new("s-001-bbb-fin"),
                lock_file: None,
                state: SessionState::Finalized,
                locked: false,
                mtime_unix: NOW - 20 * DAY,
                allocated_bytes: 800,
            }],
            any_locked: false,
            dir_mtime_unix: NOW - 20 * DAY,
            latest_mtime_unix: NOW - 20 * DAY,
            allocated_bytes: 800,
        };

        inc_profile.incremental_dirs = vec![fresh_inc, dead_inc.clone()];
        let active_target = mk_target(inc_profile, None);
        let inc_action = plan_profile_incremental_prune(
            &active_target,
            &active_target.profiles[0],
            NOW,
            DiskPressure::Calm,
            &cfg,
        )
        .expect("expected dead incremental dir to prune");
        assert!(matches!(
            inc_action,
            ReclaimAction::PruneIncremental { ref removals, .. }
                if removals.len() == 1
                    && matches!(&removals[0], IncrementalRemoval::WholeCrateDir { dir_name, .. } if dir_name == "deleted_test-2222222222222")
        ));

        // Idle repo with only the 20d-old dir (0s behind max_inc_mtime) -> preserved!
        let mut idle_profile = base_profile(TargetLayout::BuildDirV2);
        idle_profile.incremental_dirs = vec![dead_inc];
        let idle_target = mk_target(idle_profile, None);
        assert!(
            plan_profile_incremental_prune(
                &idle_target,
                &idle_target.profiles[0],
                NOW,
                DiskPressure::Calm,
                &cfg,
            )
            .is_none()
        );
    }
}
