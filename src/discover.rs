//! Imperative Shell (Layer 5): budgeted root traversal (`max_depth`, `max_entries`,
//! non-Rust `.git` cutoff), `CACHEDIR.TAG` / `HeuristicNoTag` verification,
//! 4-layout detection, `fingerprint/*.json` reading, local Git checks, and `st_blocks` accounting.
//!
//! Allowed dependencies: `error`, `model`, `config`, `platform`. Scheduled for Stage 1.
