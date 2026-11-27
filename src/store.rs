//! Imperative Shell (Layer 4): `~/Library/Application Support/targetwarden/` persistence
//! (`run.lock`, `FileStamp`-validated `StateCache`, atomic `state.json`, rotating `actions.jsonl`).
//!
//! Allowed dependencies: `error`, `model`, `state`. Scheduled for Stage 2.
