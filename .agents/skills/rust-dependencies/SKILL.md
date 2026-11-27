---
name: rust-dependencies
description: "Resolution. Use before adding or upgrading a crate or feature, changing toolchain or edition, or writing a non-domain parser, encoder, wrapper, or coordination helper instead of a library."
---

# Rust Dependencies

**Resolution.** Weigh the behavior and maintenance `targetwarden` would own against a crate's compatibility, operating, compile-time, and supply-chain costs, preferring `std` or an already-resolved dependency over adding new crates when a boundary is simple.

**Library versus custom code.** Check `std` (e.g., `std::fs::File::try_lock()` stabilized in Rust `1.89`), the [library guide](../../../docs/library-guide.md), and the approved `Cargo.toml` blueprint in the [specification](../../../specs/targetwarden/README.md) (`clap`, `clap_complete`, `serde`, `serde_json`, `toml`, `thiserror`, `walkdir`, `tempfile`, `memchr`, `compact_str`, `smallvec`, `rustix`, `signal-hook`, `assert_cmd`) first. Delegate generic mechanics (`statvfs`, fd-anchored `openat`/`unlinkat`/`Dir`, `poll`, `kill_process_group`, self-pipe signal wakeups) to `rustix` and `signal-hook` while keeping domain policy local. Choose small custom code only for narrow fixed formats (e.g., `CACHEDIR.TAG`, NUL `lsof`/`mount` parsing, ~20-line RFC3339 UTC formatting) or explicit `unsafe_code = "forbid"` constraints, pinning edge cases with unit tests.

**Proportional evaluation.** Match evaluation depth to the decision: record behavior, toolchain (`rust-version = "1.98.1"`), license (`deny.toml` allows `MIT`, `Apache-2.0`, `Unicode-3.0` only), `unsafe_code = "forbid"` compatibility, and feature minimization concisely in the PR/specification when adding or upgrading any crate. Explicitly reject `tokio`, `rusqlite`, `nix`, direct `libc`, `fs4`/`fs2`, `libproc`/`bindgen`, and `toml_edit` unless the specification is revised.

**Manifest and lockfile.** Declare dependencies in `Cargo.toml` with minimal features (`default-features = false` where supported), update `Cargo.lock` deliberately through Cargo, inspect and include its diff, and run validation with `--locked` (`make verify` and `cargo deny check` where installed).

**Toolchain and scope.** Move `rust-toolchain.toml`, `Cargo.toml` (`edition`/`rust-version`), `clippy.toml` (`msrv`), and docs together in one reviewed change, verifying actual compilation and runtime behavior against the pinned toolchain rather than relying on metadata alone.
