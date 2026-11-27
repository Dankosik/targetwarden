//! Imperative Shell (Layer 4): `~/Library/Application Support/targetwarden/` persistence
//! (`run.lock`, `FileStamp`-validated `StateCache`, atomic `state.json`, rotating `actions.jsonl`).
//!
//! Allowed dependencies: `error`, `model`, `state`.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

use crate::error::AppError;
use crate::model::{ActionReceipt, SCHEMA_VERSION};
use crate::state::State;

pub(crate) const MAX_ACTIONS_LOG_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const ROTATE_KEEP_LINES: usize = 2_000;
pub(crate) const CLI_RUN_LOCK_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
const RUN_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Resolve the persistent state directory (overridable via `TARGETWARDEN_STATE_DIR`).
pub(crate) fn resolve_state_dir(home: &Path) -> PathBuf {
    if let Some(override_dir) = std::env::var_os("TARGETWARDEN_STATE_DIR")
        && !override_dir.is_empty()
    {
        return PathBuf::from(override_dir);
    }
    home.join("Library")
        .join("Application Support")
        .join("targetwarden")
}

/// Exclusive BSD `flock` guard over `<state_dir>/run.lock`. Released automatically on drop.
#[derive(Debug)]
pub(crate) struct RunLockGuard {
    file: File,
}

impl Drop for RunLockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Acquire `<state_dir>/run.lock` exclusively via `File::try_lock()`.
/// `retry_timeout == Duration::ZERO` fails immediately (`watch` daemon mode);
/// CLI mutating commands retry up to `5 s` then fail closed with `AppError::RunLockBusy`.
pub(crate) fn acquire_run_lock(
    state_dir: &Path,
    retry_timeout: Duration,
) -> Result<RunLockGuard, AppError> {
    fs::create_dir_all(state_dir).map_err(|error| AppError::Store {
        path: state_dir.to_path_buf(),
        message: format!("cannot create state directory: {error}"),
    })?;

    let lock_path = state_dir.join("run.lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| AppError::Store {
            path: lock_path.clone(),
            message: format!("cannot open run.lock: {error}"),
        })?;

    let deadline = Instant::now() + retry_timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(RunLockGuard { file }),
            Err(TryLockError::WouldBlock) => {
                if retry_timeout.is_zero() || Instant::now() >= deadline {
                    return Err(AppError::RunLockBusy);
                }
                std::thread::sleep(RUN_LOCK_POLL_INTERVAL);
            }
            Err(TryLockError::Error(error)) => {
                return Err(AppError::Store {
                    path: lock_path,
                    message: format!("cannot lock run.lock: {error}"),
                });
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

impl FileStamp {
    fn from_metadata(meta: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                dev: meta.dev(),
                ino: meta.ino(),
                len: meta.len(),
                mtime_sec: meta.mtime(),
                mtime_nsec: meta.mtime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            let (mtime_sec, mtime_nsec) = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or((0, 0), |d| {
                    (
                        i64::try_from(d.as_secs()).unwrap_or(0),
                        i64::from(d.subsec_nanos()),
                    )
                });
            Self {
                dev: 0,
                ino: 0,
                len: meta.len(),
                mtime_sec,
                mtime_nsec,
            }
        }
    }
}

/// `FileStamp`-validated in-memory cache around atomic `state.json`.
#[derive(Debug)]
pub(crate) struct StateCache {
    state_dir: PathBuf,
    state_path: PathBuf,
    cached: Option<(FileStamp, State)>,
    #[cfg(test)]
    disk_reads: usize,
}

impl StateCache {
    pub(crate) fn new(state_dir: PathBuf) -> Self {
        let state_path = state_dir.join("state.json");
        Self {
            state_dir,
            state_path,
            cached: None,
            #[cfg(test)]
            disk_reads: 0,
        }
    }

    /// Load `state.json`, reusing the in-memory value whenever `FileStamp` is unchanged.
    pub(crate) fn load(&mut self) -> Result<State, AppError> {
        let meta = match fs::metadata(&self.state_path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.cached = None;
                return Ok(State::new_default());
            }
            Err(error) => {
                return Err(AppError::Store {
                    path: self.state_path.clone(),
                    message: format!("cannot stat state.json: {error}"),
                });
            }
        };

        let stamp = FileStamp::from_metadata(&meta);
        if let Some((cached_stamp, cached_state)) = &self.cached
            && *cached_stamp == stamp
        {
            return Ok(cached_state.clone());
        }

        let bytes = fs::read(&self.state_path).map_err(|error| AppError::Store {
            path: self.state_path.clone(),
            message: format!("cannot read state.json: {error}"),
        })?;
        #[cfg(test)]
        {
            self.disk_reads += 1;
        }
        let state: State = serde_json::from_slice(&bytes).map_err(|error| AppError::Store {
            path: self.state_path.clone(),
            message: format!("corrupt state.json: {error}"),
        })?;
        if state.schema_version != SCHEMA_VERSION {
            return Err(AppError::Store {
                path: self.state_path.clone(),
                message: format!(
                    "unsupported state schema_version {} (expected {SCHEMA_VERSION})",
                    state.schema_version
                ),
            });
        }
        self.cached = Some((stamp, state.clone()));
        Ok(state)
    }

    /// Load `state.json`, recovering cleanly to default state with a diagnostic message if corrupt
    /// (used by `watch` per Section 6.2).
    #[allow(dead_code)] // Used by Stage 4 `watch`
    pub(crate) fn load_or_recover(&mut self) -> (State, Option<String>) {
        match self.load() {
            Ok(state) => (state, None),
            Err(error) => {
                self.cached = None;
                (State::new_default(), Some(error.to_string()))
            }
        }
    }

    /// Atomically persist `state.json` via `NamedTempFile` + `sync_all` + `persist`.
    pub(crate) fn save(&mut self, state: &State) -> Result<(), AppError> {
        fs::create_dir_all(&self.state_dir).map_err(|error| AppError::Store {
            path: self.state_dir.clone(),
            message: format!("cannot create state directory: {error}"),
        })?;

        let mut payload = serde_json::to_vec_pretty(state).map_err(|error| AppError::Store {
            path: self.state_path.clone(),
            message: format!("cannot serialize state.json: {error}"),
        })?;
        payload.push(b'\n');

        let mut tmp = NamedTempFile::new_in(&self.state_dir).map_err(|error| AppError::Store {
            path: self.state_dir.clone(),
            message: format!("cannot create temp state file: {error}"),
        })?;
        tmp.write_all(&payload).map_err(|error| AppError::Store {
            path: self.state_path.clone(),
            message: format!("cannot write temp state file: {error}"),
        })?;
        tmp.as_file().sync_all().map_err(|error| AppError::Store {
            path: self.state_path.clone(),
            message: format!("cannot sync temp state file: {error}"),
        })?;
        let persisted = tmp
            .persist(&self.state_path)
            .map_err(|error| AppError::Store {
                path: self.state_path.clone(),
                message: format!("cannot atomically persist state.json: {}", error.error),
            })?;

        if let Ok(meta) = persisted.metadata() {
            self.cached = Some((FileStamp::from_metadata(&meta), state.clone()));
        } else {
            self.cached = None;
        }
        Ok(())
    }
}

/// Read `state.json` strictly read-only without creating files or acquiring `run.lock`.
pub(crate) fn load_state_readonly(state_dir: &Path) -> State {
    let state_path = state_dir.join("state.json");
    let Ok(bytes) = fs::read(&state_path) else {
        return State::new_default();
    };
    match serde_json::from_slice::<State>(&bytes) {
        Ok(state) if state.schema_version == SCHEMA_VERSION => state,
        Ok(_) | Err(_) => State::new_default(),
    }
}

/// Append action receipts to `actions.jsonl` and rotate atomically above `2 MiB` keeping `2 000` lines.
pub(crate) fn append_receipts(
    state_dir: &Path,
    receipts: &[ActionReceipt],
) -> Result<(), AppError> {
    append_receipts_with_limits(
        state_dir,
        receipts,
        MAX_ACTIONS_LOG_BYTES,
        ROTATE_KEEP_LINES,
    )
}

fn append_receipts_with_limits(
    state_dir: &Path,
    receipts: &[ActionReceipt],
    max_bytes: u64,
    keep_lines: usize,
) -> Result<(), AppError> {
    if receipts.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(state_dir).map_err(|error| AppError::Store {
        path: state_dir.to_path_buf(),
        message: format!("cannot create state directory: {error}"),
    })?;

    let log_path = state_dir.join("actions.jsonl");
    let mut buf = Vec::new();
    for receipt in receipts {
        serde_json::to_writer(&mut buf, receipt).map_err(|error| AppError::Store {
            path: log_path.clone(),
            message: format!("cannot serialize action receipt: {error}"),
        })?;
        buf.push(b'\n');
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| AppError::Store {
            path: log_path.clone(),
            message: format!("cannot open actions.jsonl: {error}"),
        })?;
    file.write_all(&buf).map_err(|error| AppError::Store {
        path: log_path.clone(),
        message: format!("cannot append actions.jsonl: {error}"),
    })?;
    file.sync_all().map_err(|error| AppError::Store {
        path: log_path.clone(),
        message: format!("cannot sync actions.jsonl: {error}"),
    })?;

    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    drop(file);

    if len > max_bytes {
        rotate_actions_log(state_dir, &log_path, keep_lines)?;
    }
    Ok(())
}

fn rotate_actions_log(
    state_dir: &Path,
    log_path: &Path,
    keep_lines: usize,
) -> Result<(), AppError> {
    let bytes = fs::read(log_path).map_err(|error| AppError::Store {
        path: log_path.to_path_buf(),
        message: format!("cannot read actions.jsonl for rotation: {error}"),
    })?;
    let tail = slice_last_n_lines(&bytes, keep_lines);

    let mut tmp = NamedTempFile::new_in(state_dir).map_err(|error| AppError::Store {
        path: state_dir.to_path_buf(),
        message: format!("cannot create temp rotation file: {error}"),
    })?;
    tmp.write_all(tail).map_err(|error| AppError::Store {
        path: log_path.to_path_buf(),
        message: format!("cannot write rotated actions.jsonl: {error}"),
    })?;
    tmp.as_file().sync_all().map_err(|error| AppError::Store {
        path: log_path.to_path_buf(),
        message: format!("cannot sync rotated actions.jsonl: {error}"),
    })?;
    tmp.persist(log_path).map_err(|error| AppError::Store {
        path: log_path.to_path_buf(),
        message: format!("cannot persist rotated actions.jsonl: {}", error.error),
    })?;
    Ok(())
}

/// Read the latest `limit` entries from `actions.jsonl` using reverse `memchr` scanning.
pub(crate) fn read_recent_receipts(
    state_dir: &Path,
    limit: usize,
) -> Result<Vec<ActionReceipt>, AppError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let log_path = state_dir.join("actions.jsonl");
    let bytes = match fs::read(&log_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(AppError::Store {
                path: log_path,
                message: format!("cannot read actions.jsonl: {error}"),
            });
        }
    };

    let tail = slice_last_n_lines(&bytes, limit);
    let mut receipts = Vec::new();
    for raw_line in tail.split(|&b| b == b'\n') {
        if raw_line.is_empty() {
            continue;
        }
        let receipt: ActionReceipt =
            serde_json::from_slice(raw_line).map_err(|error| AppError::Store {
                path: log_path.clone(),
                message: format!("corrupt entry in actions.jsonl: {error}"),
            })?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

/// Return a subslice containing the last `n` newline-delimited lines using `memchr::memrchr_iter`.
fn slice_last_n_lines(bytes: &[u8], n: usize) -> &[u8] {
    if n == 0 || bytes.is_empty() {
        return &[];
    }
    let trimmed_end = if bytes.last() == Some(&b'\n') {
        bytes.len() - 1
    } else {
        bytes.len()
    };
    if trimmed_end == 0 {
        return &[];
    }

    let mut seen = 0usize;
    for pos in memchr::memrchr_iter(b'\n', &bytes[..trimmed_end]) {
        seen += 1;
        if seen == n {
            return &bytes[pos + 1..];
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use compact_str::CompactString;

    use super::{
        StateCache, acquire_run_lock, append_receipts_with_limits, read_recent_receipts,
        slice_last_n_lines,
    };
    use crate::error::AppError;
    use crate::model::{ActionOutcome, ActionReceipt, DiskPressure, RuleId};

    fn sample_receipt(ts: u64) -> ActionReceipt {
        ActionReceipt {
            ts_unix: ts,
            rule: RuleId::R2BuildSweep,
            target_root: PathBuf::from("/Users/dev/repo/target"),
            profile_rel: Some(PathBuf::from("debug")),
            outcome: ActionOutcome::Applied,
            units_removed: 3,
            allocated_bytes: 1024,
            free_before_bytes: 10_000,
            free_after_bytes: 11_024,
            duration_ms: 12,
            pressure: DiskPressure::Calm,
            reason: CompactString::new("unreachable_duplicates"),
        }
    }

    #[test]
    fn state_cache_hits_on_unchanged_stamp_and_reloads_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = StateCache::new(dir.path().to_path_buf());

        let mut state = cache.load().unwrap();
        assert_eq!(cache.disk_reads, 0);
        state.cumulative_reclaimed_allocated_bytes = 42;
        cache.save(&state).unwrap();

        // Cache hit: zero disk reads after save populated FileStamp
        let loaded = cache.load().unwrap();
        assert_eq!(loaded.cumulative_reclaimed_allocated_bytes, 42);
        assert_eq!(cache.disk_reads, 0);

        // Fresh cache reads once, then hits cache on second load
        let mut cache2 = StateCache::new(dir.path().to_path_buf());
        let first = cache2.load().unwrap();
        assert_eq!(first.cumulative_reclaimed_allocated_bytes, 42);
        assert_eq!(cache2.disk_reads, 1);
        let second = cache2.load().unwrap();
        assert_eq!(second.cumulative_reclaimed_allocated_bytes, 42);
        assert_eq!(cache2.disk_reads, 1);

        // Corrupt state.json recovers cleanly in watch mode
        std::fs::write(dir.path().join("state.json"), b"{not json").unwrap();
        let (recovered, diag) = cache2.load_or_recover();
        assert_eq!(recovered.cumulative_reclaimed_allocated_bytes, 0);
        assert!(diag.is_some());
    }

    #[test]
    fn run_lock_blocks_concurrent_holder_and_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_run_lock(dir.path(), Duration::ZERO).unwrap();

        let contested = acquire_run_lock(dir.path(), Duration::from_millis(60));
        assert!(matches!(contested, Err(AppError::RunLockBusy)));

        drop(guard);
        let reacquired = acquire_run_lock(dir.path(), Duration::ZERO);
        assert!(reacquired.is_ok());
    }

    #[test]
    fn actions_log_rotates_and_tails_last_n_lines_with_memchr() {
        assert_eq!(slice_last_n_lines(b"a\nb\nc\nd\n", 2), b"c\nd\n");
        assert_eq!(slice_last_n_lines(b"a\nb\n", 5), b"a\nb\n");
        assert_eq!(slice_last_n_lines(b"", 5), b"");

        let dir = tempfile::tempdir().unwrap();
        let batch: Vec<ActionReceipt> = (1..=30).map(sample_receipt).collect();
        // Force rotation at 1 KiB keeping latest 5 lines
        append_receipts_with_limits(dir.path(), &batch, 1024, 5).unwrap();

        let recent = read_recent_receipts(dir.path(), 10).unwrap();
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].ts_unix, 26);
        assert_eq!(recent[4].ts_unix, 30);

        let top2 = read_recent_receipts(dir.path(), 2).unwrap();
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].ts_unix, 29);
        assert_eq!(top2[1].ts_unix, 30);
    }
}
