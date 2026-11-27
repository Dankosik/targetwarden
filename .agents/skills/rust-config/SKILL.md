---
name: rust-config
description: "One owner per key. Use when changing configuration keys, defaults, validation, CLI flags, or file-versus-env precedence."
---

# Rust Config

**One owner per key.** Trace each setting from declaration and precedence through decoding, validation, and runtime consumption, keeping zero-config defaults in `src/config.rs` and CLI overrides in `src/cli.rs` with cross-field bounds checked at the boundary.

**Loader authority.** Keep `src/config.rs` as the single configuration authority: built-in zero-config defaults work with zero files on disk, and the optional `~/.config/targetwarden/config.toml` (or `--config` / `TARGETWARDEN_CONFIG`) is read-only (`toml` + `serde`, never mutated by `targetwarden`). Keep `--help`, `--version`, and `completions` completely independent of `config.toml` and `state.json`.

**Input semantics.** Define exact behavior for omitted, blank, malformed, duplicate, and unknown inputs (`#[serde(deny_unknown_fields)]` on `config.toml`), ensuring invalid env values (such as `TARGETWARDEN_FORMAT=bogus`) fail clearly with exit `2` rather than silently falling back. Keep CLI vs env vs config file precedence explicit (`--format` > `TARGETWARDEN_FORMAT` > text; `--config` > `TARGETWARDEN_CONFIG` > optional default path; `--root` augments/overrides configured roots cleanly).

**Key lifecycle.** Require a real runtime consumer and either a justified default or mandatory supply for every key. Validate cross-field invariants up front (for example hysteresis exit thresholds strictly above entry thresholds: `Calm >= 85 GiB` / `Elevated < 75 GiB`, `High < 45 GiB` / exit `>= 55 GiB`, `Critical < 25 GiB` / exit `>= 35 GiB`, and positive traversal/cooldown bounds) before planning runs, and pass immutable config snapshots downstream.
