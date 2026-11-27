//! Imperative Shell (Layer 5): TOCTOU-safe executor (sorted `try_lock_readonly`,
//! post-lock revalidation, V1 `.fingerprint/`-first staging rename, immediate unlock,
//! `rustix` fd-anchored `remove_tree_safe`, and dual staging crash recovery).
//!
//! Allowed dependencies: `error`, `model`, `platform`. Scheduled for Stage 2 (`EvictTarget` in Stage 3).
