# `targetwarden`: Empirical Verification Record (`R1–R5`)

Date: `2026-11-27`.
Host: macOS `26.4` (Build `25E246`), `arm64`, APFS container `disk3s5` (`/System/Volumes/Data`: `460.38 GiB` / `494.33 GB`, `~81.89–84.5 GiB` free, `3` active local snapshots `com.apple.os.update-*`), `403` total processes / `248` processes for UID `501`.
Toolchains present: `stable` (`1.98.1`, default), `1.85.0`, `1.98.1`, `1.99.0`, `1.100.0`. Global `~/.cargo/config.toml` enables `rustc-wrapper = "/opt/homebrew/bin/sccache"` (`8G`), `debug = "line-tables-only"`, and `profile.dev.package."*".debug = false`.

All experiments were conducted read-only on existing local directories under `~/Projects` or inside disposable `$TMPDIR` directories that were cleaned up afterward.

---

## R0. Observed Cargo `target/` Layouts on Host

Testing `+1.98.1`, `+1.99.0`, and `+1.100.0` plus scanning `~/Projects` established:

1. **Default `build-dir-new-layout` switched on in `1.100.0`, not `1.98.1`:**
   - `cargo +1.98.1 check` and `cargo +1.99.0 check` emit **Legacy V1** (`.fingerprint/`, `deps/`, `build/<pkg>-<16hex>/`, `incremental/`).
   - `cargo +1.100.0 check` emits **BuildDir V2** (`build/<pkg>/<16hex>/{fingerprint/, out/}`, `incremental/`; no `.fingerprint/` or `deps/`).
   - Large V2 `target/` directories on this host (`workspace-v2-a`, `workspace-v2-b`) are built under pinned `rust-toolchain.toml` `1.100.0`.
2. **Four distinct layouts coexist in practice:**
   - **`BuildDirV2`:** `workspace-v2-a/target/debug` (`44.47 GiB` `build/` across `4 657` units, `38.62 GiB` `incremental/` across `1 696` directories, nested `target/grpc-codegen/`, plus `sqlx-prepare-check/`, `sqlx-tmp/`, `doc/.lock`) and `workspace-v2-b/target/debug` (`1 663` units, `393` `incremental/` dirs). Top-level binaries under `target/debug/<bin>` had `st_nlink == 1`.
   - **`LegacyV1`:** `legacy-v1-repo/target/debug` (`208` `.fingerprint/<pkg>-<16hex>/` dirs, `34` V1 `build/<pkg>-<16hex>/` dirs matched 34/34 to `.fingerprint/`, `52` `incremental/` dirs with `77` `s-*` sessions).
   - **`MixedV1V2`:** `mixed-v1v2-repo/target/debug` (and `release`) contains **both** V1 (`.fingerprint/` = `432`, `deps/` = `6 455`, `70` V1 `build/<pkg>-<16hex>/` dirs) and V2 (`145–214` `build/<pkg>/<16hex>/fingerprint/` dirs) in the **same** profile directory, plus `target/package/` and `76` `incremental/` dirs (`103` `s-*` sessions).
   - **`ArtifactsOnly`:** `artifacts-only-repo/generation-target` lacks `CACHEDIR.TAG`, holds `.rustc_info.json`, `tmp/`, and `debug/{.cargo-lock, .cargo-build-lock, .cargo-artifact-lock, examples/, worker-bin, *.rlib, *.d}` without `build/`, `deps/`, `.fingerprint/`, or `incremental/`. Sibling metadata (`artifact-{a,b}-metadata.json`) confirmed `target_directory == build_directory`.
3. **False `CACHEDIR.TAG` and mixed `.rustc_info.json` directories:**
   - `.ruff_cache/`, `.venv/`, and `.pytest_cache/` contain standard `CACHEDIR.TAG` headers (`8a477f597d28d172789f06886806bc55`) without `cargo`, requiring a case-insensitive `cargo` check.
   - `.../.artifacts/tools/store-check` lacked `CACHEDIR.TAG`, contained `.rustc_info.json` and `debug/`, and also contained non-Cargo `verification.log`, requiring a strict top-level whitelist for `HeuristicNoTag`.

---

## R1. Cargo, `rustdoc`, and `rustc` File Locking

Tested with a `build.rs` sleeping `1.2 s`, concurrent `flock(LOCK_EX | LOCK_NB)` + `fcntl(F_GETLK)` probes, and a Rust `1.98.1` binary calling `std::fs::File::open` + `File::try_lock()`:

| Command (`+1.98.1` & `+1.100.0`) | `.cargo-lock` | `.cargo-build-lock` | `.cargo-artifact-lock` | `target/doc/.lock` |
| --- | --- | --- | --- | --- |
| `cargo check` | locked (`flock`) | locked (`flock`) | unlocked / absent | — |
| `cargo build` / `cargo test --no-run` | locked (`flock`) | locked (`flock`) | locked (`flock`) | — |
| `cargo doc --no-deps` | locked (`flock`) | locked (`flock`) | locked (`flock`) | locked by `rustdoc` (`flock`) |

- **Mechanism:** BSD `flock(2)`. On macOS, `fcntl(F_GETLK)` reported `l_type = F_WRLCK` and `l_pid = -1`. On XNU, `flock` on an `O_RDONLY` fd reliably conflicts with both `flock(LOCK_EX)` and `fcntl(F_SETLK, F_WRLCK)` in both directions.
- **`std::fs::File::try_lock()`:** Stabilized in Rust `1.89`; `File::open` (`O_RDONLY`, never `O_CREAT`) + `try_lock()` enforces mutual exclusion without creating files or needing external crates (`fs4`/`fs2`).
- **Wait behavior under `600 ms` external `LOCK_EX`:**
  - `.cargo-lock` vs `cargo check`: `+1.98.1` waited `627 ms`, `+1.100.0` waited `648 ms`, `rc = 0`.
  - `.cargo-build-lock` vs `cargo check`: `+1.98.1` waited `613 ms`, `+1.100.0` waited `614 ms`, `rc = 0`.
  - `.cargo-artifact-lock` vs `cargo build`: `+1.98.1` waited `656 ms`, `+1.100.0` waited `657 ms`, `rc = 0`.
  - `incremental/*/s-*.lock`: `rustc` uses BSD `flock(2)`. Holding `LOCK_EX` on `s-*.lock` caused `cargo check` after a source edit to cleanly allocate a new `s-*` session (`rc = 0`).
- **Lock-inode split on full target rename:** For `R2`/`R3` intra-target sweep, lock files remain at identical inodes. For full `rename` of `target/` (`R1`/`R4`/`R5`), one waiting Cargo survived (`rc = 0`), whereas two concurrent Cargo starts within `< 5 ms` can split across renamed vs newly created inodes. Hence full eviction requires zero processes in the worktree, `>= 30m` cooldown, and post-lock `lsof` revalidation.

---

## R2. Surgical Build-Unit Sweep (`mtime`, Reachability Graph, Edge Cases)

1. **`mtime` on pure cache hit (`cargo check`, `recompiled = []`):**
   - After `1.1 s` pause: `+1.98.1` (`60.6 ms`) → `mtime_changed = 0`; `+1.100.0` (`76.8 ms`) → `mtime_changed = 0` (`atime_changed = 1..2`).
2. **Dependency reachability graph (`fingerprint/*.json`):**
   - `deps` array items `[dep_id, extern_name, public, dep_fp_hash]` match `u64::from_le_bytes` decoded from companion 16-hex `fingerprint/<kind>-<name>` files.
   - Live resolution rates:
     - `workspace-v2-b` (V2, `1 659` complete units): `14 146 / 14 146` (`100.00%`), including `128` `lib -> run-build-script` and `69` `run-build-script -> build-script-build`.
     - `workspace-v2-a` (V2, `4 580` complete units): `0` `fp_u64` collisions, `61 371 / 61 964` (`99.04%`; remaining `0.96%` were stale edges to workspace crates recompiled in-place under the same `<unit-hash>`).
     - `mixed-v1v2-repo` (V2: `446 / 446`; V1: `1 144 / 1 144`) and `legacy-v1-repo` (V1: `1 061 / 1 061`): `100.00%` edges resolved, and `6 455 / 6 455` `deps/` entries + `70 / 70` V1 `build/` dirs matched `.fingerprint/<pkg>-<16hex>`.
3. **`rustc` hash mismatch pitfall:**
   - `.rustc_info.json["rustc_fingerprint"]` (`13443761199211776259`) differs from `fingerprint/*.json["rustc"]` (`4106920547260086991` for `1.100.0`, `17329007180185699724` for `1.98.1`). Active `rustc_hash` must be derived from recent `Complete` profile units.
4. **Multi-JSON & incomplete units:**
   - `workspace-v2-a/target/debug/build/console/ebb6e057e015c01f/fingerprint/` holds two `.json` files (`doc-bin-console.json` + `doc-lib-service.json`).
   - `60` units in `workspace-v2-a` and `4` in `workspace-v2-b` had `0` `.json` files in `fingerprint/` (aborted compilations).
5. **Dry-run simulation & `$TMPDIR` rebuild check:**
   - Live simulation (`all_groups` + BFS on `44.47 GiB` `workspace-v2-a/target/debug/build/`): `14.67 GiB` reclaimed (`Calm 2h`, `K=2/tK=1`, `33.0%`) to `17.12 GiB` (`Critical 15m`, `K=1/tK=1`, `38.5%`).
   - After deleting an alternate `--features foo` unit in `$TMPDIR`, warm `cargo check` finished in `44.7 ms` (V2) and `43.9 ms` (V1) with `rc = 0` and `recompiled = []`.

---

## R3. Incremental Pruning (`+1.98.1` V1 & `+1.100.0` V2)

Controlled workspace experiment (`dep-lib` + `app` with `--features foo` and default sessions):

| Scenario | `+1.98.1` (V1) | `+1.100.0` (V2) | Observed result |
| --- | --- | --- | --- |
| Baseline warm `cargo check` | `60.6 ms`, `rc=0`, `recompiled=[]` | `76.8 ms`, `rc=0`, `recompiled=[]` | Reference (`mtime_changed = 0`) |
| (a) Delete old/other-feature `incremental/app-<hash>/` keeping active `Finalized` | `43.6 ms`, `rc=0`, `recompiled=[]` | `46.3 ms`, `rc=0`, `recompiled=[]` | 100% cache hit |
| (b.1) Delete active `incremental/app-<hash>/` (no source edit) | `42.3 ms`, `rc=0`, `recompiled=[]` | `43.1 ms`, `rc=0`, `recompiled=[]` | Fingerprints give 100% cache hit |
| (b.2) Delete active `incremental/app-<hash>/` + edit `app/src/main.rs` | `66.2 ms`, `rc=0`, `recompiled=['Checking app']` | `61.4 ms`, `rc=0`, `recompiled=['Checking app']` | Clean rebuild of `app` only; `dep-lib` untouched |
| Subsequent warm `cargo check` after (b.2) | `44.5 ms`, `rc=0`, `recompiled=[]` | `44.9 ms`, `rc=0`, `recompiled=[]` | Clean new session, healthy `target/` |

Live anomalies & savings:
- `15` directories in `workspace-v2-a/target/debug/incremental/` (`38.62 GiB`, `1 696` dirs across `99` prefixes) and `2` in `workspace-v2-b` contained **only `s-*-working/`** (aborted `rustc`), motivating strict `Finalized` vs `WorkingOnly` separation.
- Multiple `s-*` sessions accumulate inside a single `<crate>-<base36>/` dir (`27/76` dirs in `mixed-v1v2-repo`, `25/52` in `legacy-v1-repo`), motivating two-level pruning.
- Live `workspace-v2-a` R3 simulation: `26.93 GiB` (`Calm 2h`, `M=2`, `69.7%`) to `30.84 GiB` (`Critical 15m`, `M=1`, `79.9%`). Combined `R2 + R3` on `83.09 GiB`: `41.60–47.96 GiB` (`50–58%`).

---

## R4. Process & FD Detection Benchmark on macOS `26.4`

5 consecutive runs on the same live process set (`403` total processes, `248` UID `501`):

| Method | Median (min–max; output) | Simplicity | Reliability | `unsafe` | Coverage |
| --- | --- | --- | --- | --- | --- |
| `/bin/ps -axo pid=,ppid=,uid=,comm=` | `20.7 ms` (`18.1–22.5 ms`; `37.5 KB`) | High | High (`err=0`) | `0` | `pid`/`ppid`/`uid` + exe path; no `cwd`, FDs, `txt` |
| `/bin/ps -axo pid=,ppid=,uid=,args=` | `20.6 ms` (`19.0–23.7 ms`; `92.7 KB`) | High | High (`err=0`) | `0` | Full `argv`; no `cwd`, FDs, `txt` |
| `/usr/sbin/lsof -n -P -d cwd -F0pcftn` | `102.6 ms` (`95.3–267.2 ms`; `14.2 KB`) | High | Medium | `0` | `cwd` + `comm` (`<= 31B`); blind to open FDs & mapped binaries |
| `/usr/sbin/lsof -n -P -F0pcftn` | `121.3 ms` (`117.5–126.5 ms`; `1.03 MB`) | High | High (`err=0`, `NOFD=0`) | `0` (`forbid`) | `cwd` + open vnode FDs + `txt` mmaps (`nextest` bins, `.rmeta`, `.dylib`, full exe path) + `comm` |
| `libproc` (`cwd` + `proc_pidpath`, `387` PIDs) | `0.8 ms` (`0.8–1.4 ms`) | Low (raw XNU structs) | Medium (`bindgen`/ABI drift) | High (`unsafe`) | `cwd` + `exe`; no open FDs or `txt` mmaps |
| `libproc` (`+ PROC_PIDLISTFDS`, `5 031` FDs) | `7.1 ms` (`6.0–16.4 ms`) | Low (3-stage FFI) | Medium | High (`unsafe`) | `cwd` + open vnode FDs; still misses `txt` mmaps without region scan |

Audit of live `lsof -n -P -F0pcftn`: `stderr = 0 B`, `NOFD = 0`, `caret = 0`; empty `n` field occurred only on `PIPE` (`21`), `NPOLICY` (`64`), `NEXUS` (`8`); non-ASCII paths use `\xHH` escapes; `c` preserves spaces and truncates at 31 bytes (resolved via `ftxt`/`REG` `exe_path`). Selected `/usr/sbin/lsof -n -P -F0pcftn` (`0.067%` CPU at `180 s` tick).

---

## R5. APFS Clones, `statvfs`, `st_blocks`, and Local Snapshots

Tested with a `64 MiB` incompressible random file and `cp -c` clone on `/System/Volumes/Data`:
- `cp -c` preserves `mtime_ns` (`clone.mtime_ns == orig.mtime_ns`) and resets `ctime_ns` (`clone.ctime_ns > orig.ctime_ns`), confirming `ctime` must never be used for freshness.
- Both files report `st_blocks * 512 == 64 MiB` and `ATTR_CMNEXT_PRIVATESIZE == 0 MiB`.
- Deleting `clone.bin`: `statvfs` free delta = `+0.00 MiB` (`orig` private blocks jumped `0 -> 64 MiB`).
- Deleting `orig.bin`: `statvfs` free delta = `+63.97 MiB`.
- `tmutil listlocalsnapshots /` runs unprivileged in `88.7 ms` and returned 3 active `com.apple.os.update-*` snapshots.
- Conclusion: omit `unsafe` `getattrlist` in v1; report `allocated_bytes` (`st_blocks * 512` with hardlink dedup) alongside `statvfs` free space and `ReclaimHoldState`.

---

## Remaining Live Checks (Stage 0 / Stage 1)

1. Capture `lsof -n -P -F0pcftn` while `rust-analyzer` + `rust-analyzer-proc-macro-srv` is running to verify exact `comm` truncation and `txt` vs `REG` fd layout for loaded `.dylib` proc-macros.
2. Benchmark full Rust `walkdir` discovery + `fingerprint/*.json` parsing across `~/Projects` (`< 2 s` acceptance gate in Stage 1).
3. Cover V1 `deps/*.dSYM` directory entries in Stage 2 filesystem fixtures (`debug = true` local overrides).
