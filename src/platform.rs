//! Imperative Shell (Layer 4): narrow `trait Platform` boundary and macOS implementation
//! (`rustix`, `signal-hook`, `File::try_lock`, bounded `lsof -n -P -F0pcftn`, `/sbin/mount`,
//! `tmutil`, `git`, `launchctl`) plus non-macOS `NoPlatform`.
//!
//! Allowed dependencies: `error`, `model`. Scheduled for Stage 1 (`watch` signals in Stage 4).
