---
name: rust-review
description: "Falsification. Use whenever reviewing, auditing, or critiquing Rust modules, .rs files, PR diffs, or tests read-only to find correctness, concurrency, type, error, API, and test defects."
---

# Rust Review

**Falsification first.** Read the target Rust diff or module alongside its callers before commenting, hunting for reachable runtime defects, broken invariants, and fragile seams rather than surface style nits. Follow [Agent Review](../../../docs/agent-review.md) for severity framing and verification boundaries, and apply the method below directly during standalone or PR reviews.

**Domain lenses.** Load matching domain skills before judging—`rust-idiomatic` and `rust-coder` for state representation, ownership, and API contracts, `rust-errors` for failure semantics and fail-closed error chains, `rust-concurrency`, `rust-filesystem`, and `rust-processes` for `flock`, `O_NOFOLLOW`/`st_dev` traversal, TOCTOU staging renames, and bounded `lsof`/`git` subprocess handling, `rust-security` for untrusted paths, symlinks, mount boundaries, and control-byte sanitization, `rust-performance` for algorithmic or allocation regressions on 5 000+ build units, and `rust-structural-quality` for ownership seams and unnecessary wrappers. Test each candidate issue against a concrete reachable path rather than subjective style preference.

**Test falsifiability.** Audit accompanying tests with `rust-testing` using the Mutation Mental Test—mentally invert or delete each guarded production branch, boundary check, lock probe, or error path and flag tests that would still pass, assert tautologies, omit time or concurrency edge cases, or prove only mock interactions rather than real observable behavior.

**Actionable output.** Inspect statically without building speculative scratch binaries unless disambiguating an ambiguous compiler or runtime fact. Group confirmed findings by severity (`Must fix`, `Should fix`, `Consider`) with exact `file:line` citations, the concrete reachable failure trace or surviving mutant, and a minimal compiling replacement snippet for each fix, stating explicitly when no defect survives.
