//! Functional Core (Layer 1): APFS GiB hysteresis automaton (`DiskPressure`)
//! and 4-condition `ReclaimHoldState` trigger/reset evaluation.
//!
//! Allowed dependencies: `model`, `config`, `state`.

use crate::config::{PressureThresholds, ReclaimHoldConfig};
use crate::model::{DiskPressure, DiskStats, ReclaimHoldState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HoldResetReason {
    SnapshotsChanged,
    FreeSpaceRecovered,
    PressureEscalated,
    TtlExpired,
}

/// Evaluate the next `DiskPressure` level with GiB hysteresis.
///
/// Escalation to higher pressure happens immediately when `free_bytes < enter`.
/// De-escalation requires crossing the corresponding `exit` threshold (`>= exit`).
pub(crate) fn evaluate_pressure(
    previous: DiskPressure,
    free_bytes: u64,
    thresholds: &PressureThresholds,
) -> DiskPressure {
    if free_bytes < thresholds.critical_enter_bytes {
        return DiskPressure::Critical;
    }
    if free_bytes < thresholds.high_enter_bytes {
        return if previous == DiskPressure::Critical && free_bytes < thresholds.critical_exit_bytes
        {
            DiskPressure::Critical
        } else {
            DiskPressure::High
        };
    }
    if free_bytes < thresholds.elevated_enter_bytes {
        return if previous >= DiskPressure::High && free_bytes < thresholds.high_exit_bytes {
            DiskPressure::High
        } else {
            DiskPressure::Elevated
        };
    }
    if previous == DiskPressure::Calm || free_bytes >= thresholds.elevated_exit_bytes {
        DiskPressure::Calm
    } else {
        DiskPressure::Elevated
    }
}

/// Decide whether APFS snapshot retention circuit breaker should trigger after `R5` eviction.
pub(crate) fn should_trigger_hold(
    reclaimed_allocated_bytes: u64,
    observed_free_gain_bytes: u64,
    cfg: &ReclaimHoldConfig,
) -> bool {
    if reclaimed_allocated_bytes < cfg.min_reclaimed_bytes {
        return false;
    }
    let lhs = u128::from(observed_free_gain_bytes) * 100;
    let rhs = u128::from(reclaimed_allocated_bytes) * u128::from(cfg.min_gain_ratio_pct);
    lhs < rhs
}

/// Evaluate the 4 deterministic reset conditions for `ReclaimHoldState`.
pub(crate) fn check_hold_reset(
    hold: &ReclaimHoldState,
    disk: &DiskStats,
    current_pressure: DiskPressure,
    now_unix: u64,
    cfg: &ReclaimHoldConfig,
) -> Option<HoldResetReason> {
    if let Some(current_snapshots) = &disk.local_snapshots
        && current_snapshots != &hold.snapshots_at_detection
    {
        return Some(HoldResetReason::SnapshotsChanged);
    }
    if disk.free_bytes
        >= hold
            .free_bytes_at_detection
            .saturating_add(cfg.free_recovery_bytes)
    {
        return Some(HoldResetReason::FreeSpaceRecovered);
    }
    if current_pressure > hold.pressure_at_detection {
        return Some(HoldResetReason::PressureEscalated);
    }
    if now_unix.saturating_sub(hold.detected_at_unix) >= cfg.ttl_secs {
        return Some(HoldResetReason::TtlExpired);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use compact_str::CompactString;

    use super::{HoldResetReason, check_hold_reset, evaluate_pressure, should_trigger_hold};
    use crate::config::{PressureThresholds, ReclaimHoldConfig};
    use crate::model::{DiskPressure, DiskStats, GIB, ReclaimHoldState};

    #[test]
    fn pressure_hysteresis_handles_every_boundary_and_jump() {
        let t = PressureThresholds::default();

        // Calm escalations and boundary
        assert_eq!(
            evaluate_pressure(DiskPressure::Calm, 80 * GIB, &t),
            DiskPressure::Calm
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Calm, 75 * GIB, &t),
            DiskPressure::Calm
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Calm, 75 * GIB - 1, &t),
            DiskPressure::Elevated
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Calm, 44 * GIB, &t),
            DiskPressure::High
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Calm, 24 * GIB, &t),
            DiskPressure::Critical
        );

        // Elevated hysteresis band [75, 85)
        assert_eq!(
            evaluate_pressure(DiskPressure::Elevated, 85 * GIB - 1, &t),
            DiskPressure::Elevated
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Elevated, 85 * GIB, &t),
            DiskPressure::Calm
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Elevated, 45 * GIB, &t),
            DiskPressure::Elevated
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Elevated, 45 * GIB - 1, &t),
            DiskPressure::High
        );

        // High hysteresis band [45, 55)
        assert_eq!(
            evaluate_pressure(DiskPressure::High, 55 * GIB - 1, &t),
            DiskPressure::High
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::High, 55 * GIB, &t),
            DiskPressure::Elevated
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::High, 80 * GIB, &t),
            DiskPressure::Elevated
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::High, 85 * GIB, &t),
            DiskPressure::Calm
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::High, 25 * GIB, &t),
            DiskPressure::High
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::High, 25 * GIB - 1, &t),
            DiskPressure::Critical
        );

        // Critical hysteresis band [25, 35)
        assert_eq!(
            evaluate_pressure(DiskPressure::Critical, 35 * GIB - 1, &t),
            DiskPressure::Critical
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Critical, 35 * GIB, &t),
            DiskPressure::High
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Critical, 50 * GIB, &t),
            DiskPressure::High
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Critical, 60 * GIB, &t),
            DiskPressure::Elevated
        );
        assert_eq!(
            evaluate_pressure(DiskPressure::Critical, 85 * GIB, &t),
            DiskPressure::Calm
        );
    }

    #[test]
    fn hold_triggers_only_at_or_above_5gib_with_under_20pct_gain() {
        let cfg = ReclaimHoldConfig::default();
        assert!(!should_trigger_hold(5 * GIB - 1, 0, &cfg));
        assert!(should_trigger_hold(5 * GIB, GIB - 1, &cfg));
        assert!(!should_trigger_hold(5 * GIB, GIB, &cfg));
        assert!(should_trigger_hold(10 * GIB, 2 * GIB - 1, &cfg));
        assert!(!should_trigger_hold(10 * GIB, 2 * GIB, &cfg));
    }

    #[test]
    fn hold_resets_on_each_of_four_conditions_and_not_when_tmutil_unavailable() {
        let cfg = ReclaimHoldConfig::default();
        let hold = ReclaimHoldState {
            detected_at_unix: 10_000,
            reclaimed_allocated_bytes: 6 * GIB,
            observed_free_gain_bytes: 300 * (1 << 20),
            free_bytes_at_detection: 40 * GIB,
            pressure_at_detection: DiskPressure::High,
            snapshots_at_detection: vec![CompactString::new("snap-a")],
        };

        let steady_disk = DiskStats {
            mount: PathBuf::from("/System/Volumes/Data"),
            total_bytes: 460 * GIB,
            free_bytes: 42 * GIB,
            local_snapshots: Some(vec![CompactString::new("snap-a")]),
        };
        assert_eq!(
            check_hold_reset(&hold, &steady_disk, DiskPressure::High, 10_000 + 3600, &cfg),
            None
        );

        // tmutil failure (None) must NOT falsely trigger SnapshotsChanged
        let mut no_tmutil = steady_disk.clone();
        no_tmutil.local_snapshots = None;
        assert_eq!(
            check_hold_reset(&hold, &no_tmutil, DiskPressure::High, 10_000 + 3600, &cfg),
            None
        );

        // 1. Snapshots changed
        let mut snaps_changed = steady_disk.clone();
        snaps_changed.local_snapshots = Some(vec![]);
        assert_eq!(
            check_hold_reset(&hold, &snaps_changed, DiskPressure::High, 10_100, &cfg),
            Some(HoldResetReason::SnapshotsChanged)
        );

        // 2. Free space recovered >= 5 GiB
        let mut recovered = steady_disk.clone();
        recovered.free_bytes = 45 * GIB;
        assert_eq!(
            check_hold_reset(&hold, &recovered, DiskPressure::High, 10_100, &cfg),
            Some(HoldResetReason::FreeSpaceRecovered)
        );

        // 3. Pressure escalated strictly above detection level
        assert_eq!(
            check_hold_reset(&hold, &steady_disk, DiskPressure::Critical, 10_100, &cfg),
            Some(HoldResetReason::PressureEscalated)
        );

        // 4. 6h TTL expired
        assert_eq!(
            check_hold_reset(
                &hold,
                &steady_disk,
                DiskPressure::High,
                10_000 + 6 * 3600,
                &cfg
            ),
            Some(HoldResetReason::TtlExpired)
        );
    }
}
