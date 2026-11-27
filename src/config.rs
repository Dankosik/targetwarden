//! Functional Core (Layer 1): zero-config defaults and optional `config.toml` parsing.
//!
//! Allowed dependencies: `error`, `model`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::AppError;
use crate::model::{DiskPressure, GIB};

pub(crate) const DEFAULT_ROOT_NAMES: &[&str] = &["Projects", "Developer", "src", "work"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PressureThresholds {
    pub elevated_enter_bytes: u64,
    pub elevated_exit_bytes: u64,
    pub high_enter_bytes: u64,
    pub high_exit_bytes: u64,
    pub critical_enter_bytes: u64,
    pub critical_exit_bytes: u64,
    pub r5_high_target_bytes: u64,
    pub r5_critical_target_bytes: u64,
}

impl Default for PressureThresholds {
    fn default() -> Self {
        Self {
            elevated_enter_bytes: 75 * GIB,
            elevated_exit_bytes: 85 * GIB,
            high_enter_bytes: 45 * GIB,
            high_exit_bytes: 55 * GIB,
            critical_enter_bytes: 25 * GIB,
            critical_exit_bytes: 35 * GIB,
            r5_high_target_bytes: 55 * GIB,
            r5_critical_target_bytes: 45 * GIB,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiscoveryBudgets {
    pub default_max_depth: usize,
    pub explicit_max_depth: usize,
    pub max_entries: usize,
    pub walk_timeout_secs: u64,
    pub non_rust_git_extra_depth: usize,
    pub max_open_dirs: usize,
}

impl Default for DiscoveryBudgets {
    fn default() -> Self {
        Self {
            default_max_depth: 6,
            explicit_max_depth: 8,
            max_entries: 250_000,
            walk_timeout_secs: 15,
            non_rust_git_extra_depth: 2,
            max_open_dirs: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoolingConfig {
    /// Target-wide short cooling window to avoid sweeping mid-iteration between cargo calls.
    pub sweep_cooling_secs: u64,
    /// Minimum inactivity window required before any full target eviction (`R1`/`R4`/`R5`).
    pub eviction_cooling_secs: u64,
    /// R4 cooled-worktree thresholds by pressure level.
    pub r4_calm_secs: u64,
    pub r4_elevated_secs: u64,
    pub r4_high_secs: u64,
    pub r4_critical_secs: u64,
    /// R5 main-checkout minimum age thresholds in High/Critical.
    pub r5_main_high_secs: u64,
    pub r5_main_critical_secs: u64,
}

impl Default for CoolingConfig {
    fn default() -> Self {
        Self {
            sweep_cooling_secs: 5 * 60,
            eviction_cooling_secs: 30 * 60,
            r4_calm_secs: 72 * 3600,
            r4_elevated_secs: 6 * 3600,
            r4_high_secs: 2 * 3600,
            r4_critical_secs: 30 * 60,
            r5_main_high_secs: 24 * 3600,
            r5_main_critical_secs: 2 * 3600,
        }
    }
}

impl CoolingConfig {
    pub fn r4_age_secs(self, pressure: DiskPressure) -> u64 {
        match pressure {
            DiskPressure::Calm => self.r4_calm_secs,
            DiskPressure::Elevated => self.r4_elevated_secs,
            DiskPressure::High => self.r4_high_secs,
            DiskPressure::Critical => self.r4_critical_secs,
        }
    }

    pub fn r5_main_age_secs(self, pressure: DiskPressure) -> Option<u64> {
        match pressure {
            DiskPressure::Calm | DiskPressure::Elevated => None,
            DiskPressure::High => Some(self.r5_main_high_secs),
            DiskPressure::Critical => Some(self.r5_main_critical_secs),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReclaimHoldConfig {
    pub min_reclaimed_bytes: u64,
    pub min_gain_ratio_pct: u8,
    pub free_recovery_bytes: u64,
    pub ttl_secs: u64,
}

impl Default for ReclaimHoldConfig {
    fn default() -> Self {
        Self {
            min_reclaimed_bytes: 5 * GIB,
            min_gain_ratio_pct: 20,
            free_recovery_bytes: 5 * GIB,
            ttl_secs: 6 * 3600,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SweepConfig {
    pub active_rustc_window_secs: u64,
    pub dup_cooldown_calm_secs: u64,
    pub dup_cooldown_elevated_secs: u64,
    pub dup_cooldown_high_secs: u64,
    pub dup_cooldown_critical_secs: u64,
    pub inc_cooldown_calm_secs: u64,
    pub inc_cooldown_elevated_secs: u64,
    pub inc_cooldown_high_secs: u64,
    pub inc_cooldown_critical_secs: u64,
    pub mixed_stale_calm_secs: u64,
    pub mixed_stale_elevated_secs: u64,
    pub mixed_stale_high_secs: u64,
    pub doc_prune_calm_secs: u64,
    pub doc_prune_high_secs: u64,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            active_rustc_window_secs: 24 * 3600,
            dup_cooldown_calm_secs: 2 * 3600,
            dup_cooldown_elevated_secs: 3600,
            dup_cooldown_high_secs: 30 * 60,
            dup_cooldown_critical_secs: 15 * 60,
            inc_cooldown_calm_secs: 2 * 3600,
            inc_cooldown_elevated_secs: 3600,
            inc_cooldown_high_secs: 30 * 60,
            inc_cooldown_critical_secs: 15 * 60,
            mixed_stale_calm_secs: 7 * 86_400,
            mixed_stale_elevated_secs: 86_400,
            mixed_stale_high_secs: 2 * 3600,
            doc_prune_calm_secs: 7 * 86_400,
            doc_prune_high_secs: 86_400,
        }
    }
}

impl SweepConfig {
    pub fn dup_cooldown_secs(self, pressure: DiskPressure) -> u64 {
        match pressure {
            DiskPressure::Calm => self.dup_cooldown_calm_secs,
            DiskPressure::Elevated => self.dup_cooldown_elevated_secs,
            DiskPressure::High => self.dup_cooldown_high_secs,
            DiskPressure::Critical => self.dup_cooldown_critical_secs,
        }
    }

    pub fn inc_cooldown_secs(self, pressure: DiskPressure) -> u64 {
        match pressure {
            DiskPressure::Calm => self.inc_cooldown_calm_secs,
            DiskPressure::Elevated => self.inc_cooldown_elevated_secs,
            DiskPressure::High => self.inc_cooldown_high_secs,
            DiskPressure::Critical => self.inc_cooldown_critical_secs,
        }
    }

    pub fn anchor_slots_k(self, pressure: DiskPressure) -> usize {
        match pressure {
            DiskPressure::Calm | DiskPressure::Elevated => 2,
            DiskPressure::High | DiskPressure::Critical => 1,
        }
    }

    pub fn inc_finalized_keep_m(self, pressure: DiskPressure) -> usize {
        match pressure {
            DiskPressure::Calm | DiskPressure::Elevated => 2,
            DiskPressure::High | DiskPressure::Critical => 1,
        }
    }

    pub fn mixed_stale_layer_secs(self, pressure: DiskPressure) -> u64 {
        match pressure {
            DiskPressure::Calm => self.mixed_stale_calm_secs,
            DiskPressure::Elevated => self.mixed_stale_elevated_secs,
            DiskPressure::High | DiskPressure::Critical => self.mixed_stale_high_secs,
        }
    }

    pub fn doc_prune_age_secs(self, pressure: DiskPressure) -> u64 {
        match pressure {
            DiskPressure::Calm | DiskPressure::Elevated => self.doc_prune_calm_secs,
            DiskPressure::High | DiskPressure::Critical => self.doc_prune_high_secs,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Config {
    pub configured_roots: Vec<PathBuf>,
    pub pressure: PressureThresholds,
    pub discovery: DiscoveryBudgets,
    pub cooling: CoolingConfig,
    pub sweep: SweepConfig,
    pub reclaim_hold: ReclaimHoldConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    roots: Option<Vec<PathBuf>>,
    #[serde(default)]
    pressure: Option<RawPressureThresholds>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPressureThresholds {
    elevated_enter_gib: Option<u64>,
    elevated_exit_gib: Option<u64>,
    high_enter_gib: Option<u64>,
    high_exit_gib: Option<u64>,
    critical_enter_gib: Option<u64>,
    critical_exit_gib: Option<u64>,
}

impl Config {
    /// Parse an optional TOML configuration string and apply it over built-in defaults.
    pub(crate) fn parse_toml(
        content: &str,
        source_path: &Path,
        home: &Path,
    ) -> Result<Self, AppError> {
        let raw: RawConfig = toml::from_str(content).map_err(|error| AppError::ConfigParse {
            path: source_path.to_path_buf(),
            message: error.to_string(),
        })?;

        let mut config = Self::default();
        if let Some(roots) = raw.roots {
            config.configured_roots = roots
                .into_iter()
                .map(|path| expand_home(&path, home))
                .collect();
        }
        if let Some(p) = raw.pressure {
            if let Some(v) = p.elevated_enter_gib {
                config.pressure.elevated_enter_bytes = gib_to_bytes_checked(v)?;
            }
            if let Some(v) = p.elevated_exit_gib {
                config.pressure.elevated_exit_bytes = gib_to_bytes_checked(v)?;
            }
            if let Some(v) = p.high_enter_gib {
                config.pressure.high_enter_bytes = gib_to_bytes_checked(v)?;
                config.pressure.r5_critical_target_bytes = config.pressure.high_enter_bytes;
            }
            if let Some(v) = p.high_exit_gib {
                config.pressure.high_exit_bytes = gib_to_bytes_checked(v)?;
                config.pressure.r5_high_target_bytes = config.pressure.high_exit_bytes;
            }
            if let Some(v) = p.critical_enter_gib {
                config.pressure.critical_enter_bytes = gib_to_bytes_checked(v)?;
            }
            if let Some(v) = p.critical_exit_gib {
                config.pressure.critical_exit_bytes = gib_to_bytes_checked(v)?;
            }
        }
        config.validate()?;
        Ok(config)
    }

    /// Load configuration according to CLI precedence: explicit `--config` / `TARGETWARDEN_CONFIG`
    /// fails closed if missing; default `~/.config/targetwarden/config.toml` is optional.
    pub(crate) fn load(explicit_path: Option<&Path>, home: &Path) -> Result<Self, AppError> {
        match explicit_path {
            Some(path) => {
                let content =
                    std::fs::read_to_string(path).map_err(|source| AppError::ConfigRead {
                        path: path.to_path_buf(),
                        source,
                    })?;
                Self::parse_toml(&content, path, home)
            }
            None => {
                let default_path = home
                    .join(".config")
                    .join("targetwarden")
                    .join("config.toml");
                match std::fs::read_to_string(&default_path) {
                    Ok(content) => Self::parse_toml(&content, &default_path, home),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Ok(Self::default())
                    }
                    Err(source) => Err(AppError::ConfigRead {
                        path: default_path,
                        source,
                    }),
                }
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), AppError> {
        let p = &self.pressure;
        if p.critical_enter_bytes == 0 {
            return Err(AppError::ConfigInvalid {
                message: "critical_enter_gib must be > 0".to_owned(),
            });
        }
        let ordered = p.critical_enter_bytes < p.critical_exit_bytes
            && p.critical_exit_bytes < p.high_enter_bytes
            && p.high_enter_bytes < p.high_exit_bytes
            && p.high_exit_bytes < p.elevated_enter_bytes
            && p.elevated_enter_bytes < p.elevated_exit_bytes;
        if !ordered {
            return Err(AppError::ConfigInvalid {
                message: "pressure thresholds must satisfy 0 < critical_enter < critical_exit < high_enter < high_exit < elevated_enter < elevated_exit".to_owned(),
            });
        }
        Ok(())
    }

    /// Default candidate scan roots relative to `home`.
    pub(crate) fn default_roots(home: &Path) -> Vec<PathBuf> {
        DEFAULT_ROOT_NAMES
            .iter()
            .map(|name| home.join(name))
            .collect()
    }
}

fn gib_to_bytes_checked(gib: u64) -> Result<u64, AppError> {
    gib.checked_mul(GIB).ok_or_else(|| AppError::ConfigInvalid {
        message: format!("GiB threshold overflow: {gib}"),
    })
}

fn expand_home(path: &Path, home: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        home.join(rest)
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::Config;
    use crate::model::GIB;

    #[test]
    fn default_config_is_valid_with_spec_thresholds() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.pressure.critical_enter_bytes, 25 * GIB);
        assert_eq!(config.pressure.critical_exit_bytes, 35 * GIB);
        assert_eq!(config.pressure.high_enter_bytes, 45 * GIB);
        assert_eq!(config.pressure.high_exit_bytes, 55 * GIB);
        assert_eq!(config.pressure.elevated_enter_bytes, 75 * GIB);
        assert_eq!(config.pressure.elevated_exit_bytes, 85 * GIB);
    }

    #[test]
    fn parse_toml_expands_tilde_and_overrides_thresholds() {
        let toml = r#"
roots = ["~/Workspace", "/Volumes/FastSSD/rust"]

[pressure]
high_enter_gib = 50
high_exit_gib = 60
"#;
        let home = Path::new("/Users/tester");
        let cfg = Config::parse_toml(toml, Path::new("config.toml"), home).unwrap();
        assert_eq!(
            cfg.configured_roots,
            vec![
                PathBuf::from("/Users/tester/Workspace"),
                PathBuf::from("/Volumes/FastSSD/rust"),
            ]
        );
        assert_eq!(cfg.pressure.high_enter_bytes, 50 * GIB);
        assert_eq!(cfg.pressure.high_exit_bytes, 60 * GIB);
        assert_eq!(cfg.pressure.r5_high_target_bytes, 60 * GIB);
        assert_eq!(cfg.pressure.r5_critical_target_bytes, 50 * GIB);
        assert_eq!(cfg.pressure.elevated_enter_bytes, 75 * GIB);
    }

    #[test]
    fn parse_toml_rejects_unknown_keys_and_inverted_hysteresis() {
        let home = Path::new("/Users/tester");
        let unknown = Config::parse_toml("unknown_key = 1\n", Path::new("c.toml"), home);
        assert!(unknown.is_err());

        let inverted = Config::parse_toml(
            "[pressure]\nhigh_enter_gib = 60\nhigh_exit_gib = 55\n",
            Path::new("c.toml"),
            home,
        );
        assert!(inverted.is_err());

        let overlapping = Config::parse_toml(
            "[pressure]\ncritical_exit_gib = 45\nhigh_enter_gib = 45\n",
            Path::new("c.toml"),
            home,
        );
        assert!(overlapping.is_err());
    }

    #[test]
    fn missing_default_config_uses_defaults_but_missing_explicit_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let default_loaded = Config::load(None, dir.path()).unwrap();
        assert_eq!(default_loaded, Config::default());

        let explicit = dir.path().join("missing.toml");
        assert!(Config::load(Some(&explicit), dir.path()).is_err());
    }
}
