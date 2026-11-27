//! Live macOS `git worktree` and `pin`/`unpin` integration tests (Stage 3 T11).
//! All fixtures live inside disposable `$TMPDIR` directories; nothing outside `$TMPDIR` is touched.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::Path;
use std::process::Command as StdCommand;
use std::time::Duration;

use assert_cmd::Command;

fn write_calm_config(home: &Path) -> std::path::PathBuf {
    let path = home.join("calm-config.toml");
    fs::write(
        &path,
        "\
[pressure]
critical_enter_gib = 1
critical_exit_gib = 2
high_enter_gib = 3
high_exit_gib = 4
elevated_enter_gib = 5
elevated_exit_gib = 6
",
    )
    .unwrap();
    path
}

fn cli(home: &Path, state_dir: &Path, config_path: &Path) -> Command {
    let mut cmd = Command::cargo_bin("targetwarden").expect("binary is built");
    cmd.env_remove("TARGETWARDEN_FORMAT")
        .env_remove("CARGO_TARGET_DIR")
        .env("HOME", home)
        .env("TARGETWARDEN_STATE_DIR", state_dir)
        .env("TARGETWARDEN_CONFIG", config_path)
        .env("NO_COLOR", "1")
        .timeout(Duration::from_secs(60));
    cmd
}

fn git(cwd: &Path, args: &[&str]) {
    let out = StdCommand::new("git")
        .args(args)
        .current_dir(cwd)
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "tester")
        .env("GIT_AUTHOR_EMAIL", "tester@example.com")
        .env("GIT_COMMITTER_NAME", "tester")
        .env("GIT_COMMITTER_EMAIL", "tester@example.com")
        .output()
        .expect("git executes");
    assert!(
        out.status.success(),
        "git {args:?} failed in {}: {}",
        cwd.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn create_cargo_target(dir: &Path, age: Duration) {
    let target = dir.join("target");
    fs::create_dir_all(target.join("debug/build/demo/1111111111111111/fingerprint")).unwrap();
    fs::write(
        target.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n# Created by cargo.\n",
    )
    .unwrap();
    fs::write(
        target.join("debug/build/demo/1111111111111111/fingerprint/bin-demo.json"),
        r#"{"rustc":42,"deps":[]}"#,
    )
    .unwrap();
    fs::write(target.join("debug/demo_bin"), vec![1u8; 4096]).unwrap();

    let ts = std::time::SystemTime::now() - age;
    let mut dirs = Vec::new();
    for entry in walkdir::WalkDir::new(&target)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if entry.file_type().is_dir() {
            dirs.push(entry.path().to_path_buf());
        } else if let Ok(f) = fs::OpenOptions::new().write(true).open(entry.path()) {
            let _ = f.set_modified(ts);
        }
    }
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for d in dirs {
        let _ = StdCommand::new("/usr/bin/touch")
            .args(["-m", "-d", "2020-01-01T00:00:00Z"])
            .arg(&d)
            .output();
    }
}

#[test]
fn live_git_worktree_matrix_enforces_r1_and_all_git_safety_barriers() {
    let home = tempfile::tempdir().unwrap();
    let cfg_path = write_calm_config(home.path());
    let state_dir = home.path().join("state");
    let projects = home.path().join("Projects");
    let main_repo = projects.join("main_repo");
    fs::create_dir_all(&main_repo).unwrap();

    git(&main_repo, &["init", "-b", "main"]);
    fs::write(main_repo.join(".gitignore"), "/target\n").unwrap();
    fs::write(main_repo.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
    git(&main_repo, &["add", ".gitignore", "Cargo.toml"]);
    git(&main_repo, &["commit", "-m", "initial"]);

    // Main checkout target (must stay protected by MainCheckoutProtected in Calm!)
    create_cargo_target(&main_repo, Duration::from_secs(48 * 3600));

    // 1. Merged clean unlocked worktree (age 2h >= 30m) -> MUST be evicted by R1!
    let wt_merged = projects.join("wt_merged");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/merged",
            wt_merged.to_str().unwrap(),
        ],
    );
    create_cargo_target(&wt_merged, Duration::from_secs(2 * 3600));

    // 2. Unmerged worktree (1 commit ahead of main, age 2h < 72h) -> SweepOnly(DirtyOrUnmergedWorktree)
    let wt_unmerged = projects.join("wt_unmerged");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/unmerged",
            wt_unmerged.to_str().unwrap(),
        ],
    );
    fs::write(wt_unmerged.join("feature.txt"), b"wip commit").unwrap();
    git(&wt_unmerged, &["add", "feature.txt"]);
    git(&wt_unmerged, &["commit", "-m", "unmerged feature"]);
    create_cargo_target(&wt_unmerged, Duration::from_secs(2 * 3600));

    // 3. Dirty worktree (uncommitted file, branch at main, age 2h < 72h) -> SweepOnly(DirtyOrUnmergedWorktree)
    let wt_dirty = projects.join("wt_dirty");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/dirty",
            wt_dirty.to_str().unwrap(),
        ],
    );
    fs::write(wt_dirty.join("uncommitted.rs"), b"// dirty").unwrap();
    create_cargo_target(&wt_dirty, Duration::from_secs(2 * 3600));

    // 4. Locked worktree (`git worktree lock`, even after 80h!) -> SweepOnly(DirtyOrUnmergedWorktree)
    let wt_locked = projects.join("wt_locked");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/locked",
            wt_locked.to_str().unwrap(),
        ],
    );
    git(
        &main_repo,
        &["worktree", "lock", wt_locked.to_str().unwrap()],
    );
    create_cargo_target(&wt_locked, Duration::from_secs(80 * 3600));

    // 5. Tracked file inside `target/` -> Protected(TrackedFilesInTarget)
    let wt_tracked = projects.join("wt_tracked");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/tracked",
            wt_tracked.to_str().unwrap(),
        ],
    );
    create_cargo_target(&wt_tracked, Duration::from_secs(2 * 3600));
    fs::write(wt_tracked.join("target/tracked.txt"), b"tracked").unwrap();
    git(&wt_tracked, &["add", "-f", "target/tracked.txt"]);
    git(&wt_tracked, &["commit", "-m", "track file in target"]);

    // 6. Active `index.lock` inside worktree's git dir -> Protected(GitOperationInProgress)
    let wt_index_lock = projects.join("wt_index_lock");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/index_lock",
            wt_index_lock.to_str().unwrap(),
        ],
    );
    create_cargo_target(&wt_index_lock, Duration::from_secs(2 * 3600));
    let gitdir_out = StdCommand::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(&wt_index_lock)
        .output()
        .unwrap();
    let wt_gitdir = std::path::PathBuf::from(
        String::from_utf8(gitdir_out.stdout)
            .unwrap()
            .trim()
            .to_owned(),
    );
    fs::write(wt_gitdir.join("index.lock"), b"").unwrap();

    // 7. `.targetwarden-pin` marker on a merged worktree -> Protected(PinMarkerFile)
    let wt_marker = projects.join("wt_marker");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/marker",
            wt_marker.to_str().unwrap(),
        ],
    );
    create_cargo_target(&wt_marker, Duration::from_secs(2 * 3600));
    fs::write(wt_marker.join(".targetwarden-pin"), b"").unwrap();

    // 8. Cooled unmerged unlocked worktree (age 80h >= 72h Calm R4) -> MUST be evicted by R4!
    let wt_cooled = projects.join("wt_cooled");
    git(
        &main_repo,
        &[
            "worktree",
            "add",
            "-b",
            "feat/cooled",
            wt_cooled.to_str().unwrap(),
        ],
    );
    fs::write(wt_cooled.join("cooled.rs"), b"// unmerged cooled").unwrap();
    git(&wt_cooled, &["add", "cooled.rs"]);
    git(&wt_cooled, &["commit", "-m", "unmerged cooled feature"]);
    create_cargo_target(&wt_cooled, Duration::from_secs(80 * 3600));

    // Inspect status first and verify exact verdicts/reasons
    let status = cli(home.path(), &state_dir, &cfg_path)
        .args(["status", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let targets = status_json["targets"].as_array().unwrap();
    let find_target = |name: &str| {
        targets
            .iter()
            .find(|t| t["root"].as_str().unwrap().contains(name))
            .unwrap_or_else(|| panic!("missing target {name} in {status_json}"))
    };
    assert_eq!(
        find_target("wt_merged")["verdict"],
        "eligible",
        "wt_merged={}",
        find_target("wt_merged")
    );
    assert_eq!(find_target("wt_cooled")["verdict"], "eligible");
    assert_eq!(find_target("wt_unmerged")["verdict"], "sweep_only");
    assert_eq!(find_target("wt_dirty")["verdict"], "sweep_only");
    assert_eq!(find_target("wt_locked")["verdict"], "sweep_only");
    assert_eq!(find_target("wt_tracked")["verdict"], "protected");
    assert_eq!(find_target("wt_index_lock")["verdict"], "protected");
    assert_eq!(find_target("wt_marker")["verdict"], "protected");
    assert_eq!(find_target("main_repo")["verdict"], "sweep_only");

    // Run full reclaim: ONLY `wt_merged/target` (R1) and `wt_cooled/target` (R4) must be evicted!
    let reclaim = cli(home.path(), &state_dir, &cfg_path)
        .args(["reclaim", "--profile", "full", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        reclaim.status.success(),
        "reclaim failed: {}",
        String::from_utf8_lossy(&reclaim.stderr)
    );
    let reclaim_json: serde_json::Value = serde_json::from_slice(&reclaim.stdout).unwrap();
    assert_eq!(reclaim_json["summary"]["applied_actions"], 2);
    let rules: Vec<&str> = reclaim_json["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rule"].as_str().unwrap())
        .collect();
    assert!(rules.contains(&"r1_dead_worktree"));
    assert!(rules.contains(&"r4_cooled_worktree"));

    assert!(!wt_merged.join("target").exists());
    assert!(wt_merged.join("Cargo.toml").exists()); // Worktree & sources untouched!
    assert!(!wt_cooled.join("target").exists());
    assert!(wt_cooled.join("cooled.rs").exists()); // Unmerged source files untouched!
    assert!(main_repo.join("target").exists());
    assert!(wt_unmerged.join("target").exists());
    assert!(wt_dirty.join("target").exists());
    assert!(wt_locked.join("target").exists());
    assert!(wt_tracked.join("target").exists());
    assert!(wt_index_lock.join("target").exists());
    assert!(wt_marker.join("target").exists());
}

#[test]
fn pin_and_unpin_control_eviction_and_allow_sweep_scope() {
    let home = tempfile::tempdir().unwrap();
    let cfg_path = write_calm_config(home.path());
    let state_dir = home.path().join("state");
    let projects = home.path().join("Projects");
    let main_repo = projects.join("repo");
    fs::create_dir_all(&main_repo).unwrap();

    git(&main_repo, &["init", "-b", "main"]);
    fs::write(main_repo.join(".gitignore"), "/target\n").unwrap();
    fs::write(main_repo.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
    git(&main_repo, &["add", ".gitignore", "Cargo.toml"]);
    git(&main_repo, &["commit", "-m", "initial"]);

    let wt = projects.join("wt_pin_test");
    git(
        &main_repo,
        &["worktree", "add", "-b", "feat/pin", wt.to_str().unwrap()],
    );
    create_cargo_target(&wt, Duration::from_secs(2 * 3600));

    // 1. Pin full -> blocks eviction completely
    let pin = cli(home.path(), &state_dir, &cfg_path)
        .args([
            "pin",
            wt.to_str().unwrap(),
            "--note",
            "keep me",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(pin.status.success());
    let pin_json: serde_json::Value = serde_json::from_slice(&pin.stdout).unwrap();
    assert_eq!(pin_json["scope"], "full");

    let r1 = cli(home.path(), &state_dir, &cfg_path)
        .args(["reclaim", "--profile", "full", "--format", "json"])
        .output()
        .unwrap();
    assert!(r1.status.success());
    assert!(wt.join("target").exists());

    // 2. Pin --allow-sweep -> verdict is sweep_only (still blocks full eviction!)
    let pin_sweep = cli(home.path(), &state_dir, &cfg_path)
        .args([
            "pin",
            wt.to_str().unwrap(),
            "--allow-sweep",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(pin_sweep.status.success());
    let pin_sweep_json: serde_json::Value = serde_json::from_slice(&pin_sweep.stdout).unwrap();
    assert_eq!(pin_sweep_json["scope"], "allow_sweep");

    let r2 = cli(home.path(), &state_dir, &cfg_path)
        .args(["reclaim", "--profile", "full", "--format", "json"])
        .output()
        .unwrap();
    assert!(r2.status.success());
    assert!(wt.join("target").exists());

    // 3. Unpin -> now eligible and evicted by R1!
    let unpin = cli(home.path(), &state_dir, &cfg_path)
        .args(["unpin", wt.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(unpin.status.success());
    let unpin_json: serde_json::Value = serde_json::from_slice(&unpin.stdout).unwrap();
    assert_eq!(unpin_json["removed"], true);

    let r3 = cli(home.path(), &state_dir, &cfg_path)
        .args(["reclaim", "--profile", "full", "--format", "json"])
        .output()
        .unwrap();
    assert!(r3.status.success());
    assert!(!wt.join("target").exists());
}

#[test]
fn concurrent_run_lock_contention_fails_closed_after_retry_budget() {
    let home = tempfile::tempdir().unwrap();
    let cfg_path = write_calm_config(home.path());
    let state_dir = home.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let pin_target = home.path().join("Projects/locked_proj");
    fs::create_dir_all(&pin_target).unwrap();

    let lock_path = state_dir.join("run.lock");
    let holder = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    holder.try_lock().unwrap();

    let out = cli(home.path(), &state_dir, &cfg_path)
        .args(["pin", pin_target.to_str().unwrap()])
        .output()
        .unwrap();

    holder.unlock().unwrap();
    drop(holder);

    assert!(out.status.code() == Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("run.lock"));
}

#[test]
fn stale_rebase_head_main_merge_head_and_sweep_then_evict_never_deadlock() {
    let home = tempfile::tempdir().unwrap();
    let cfg_path = write_calm_config(home.path());
    let state_dir = home.path().join("state");
    let projects = home.path().join("Projects");
    let main_repo = projects.join("main_repo");
    fs::create_dir_all(&main_repo).unwrap();

    git(&main_repo, &["init", "-b", "main"]);
    fs::write(main_repo.join(".gitignore"), "/target\n").unwrap();
    fs::write(main_repo.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
    git(&main_repo, &["add", ".gitignore", "Cargo.toml"]);
    git(&main_repo, &["commit", "-m", "initial"]);
    create_cargo_target(&main_repo, Duration::from_secs(48 * 3600));

    // Simulate an active merge in `main_repo/.git/MERGE_HEAD` — must protect `main_repo` ONLY,
    // NOT linked worktrees!
    fs::write(main_repo.join(".git/MERGE_HEAD"), b"deadbeef\n").unwrap();

    // Linked worktree with:
    //  1) Stale `REBASE_HEAD` (no `rebase-merge/`) -> must NOT falsely mark `git_op`!
    //  2) Swept V2 duplicate + pruned incremental session before full eviction ->
    //     must NOT reset target age or fail `EvictTarget` with `mtime_advanced`!
    let wt = projects.join("wt_sweep_then_evict");
    git(
        &main_repo,
        &["worktree", "add", "-b", "feat/done", wt.to_str().unwrap()],
    );
    create_cargo_target(&wt, Duration::from_secs(5 * 3600));

    // Add an incomplete V2 unit and an old incremental session so `sweep-only` mutates both
    // `target/` (via internal staging) and `incremental/<crate>/` (via session removal)!
    let wt_target = wt.join("target");
    fs::create_dir_all(wt_target.join("debug/build/aborted/2222222222222222")).unwrap();
    let inc_crate = wt_target.join("debug/incremental/demo-abc1234567890");
    fs::create_dir_all(inc_crate.join("s-002-new-final")).unwrap();
    fs::create_dir_all(inc_crate.join("s-001-old-final")).unwrap();
    fs::write(inc_crate.join("s-002-new-final/dep.bin"), b"new").unwrap();
    fs::write(inc_crate.join("s-001-old-final/dep.bin"), b"old").unwrap();
    fs::write(inc_crate.join("s-002-new.lock"), b"").unwrap();
    fs::write(inc_crate.join("s-001-old.lock"), b"").unwrap();

    // Backdate everything inside `wt/target` to > 5h ago (with s-002 newer than s-001)
    let age_5h = std::time::SystemTime::now() - Duration::from_secs(5 * 3600);
    let age_8h = std::time::SystemTime::now() - Duration::from_secs(8 * 3600);
    for entry in walkdir::WalkDir::new(&wt_target)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if entry.file_type().is_file() {
            let ts = if entry.path().to_string_lossy().contains("s-001-old") {
                age_8h
            } else {
                age_5h
            };
            if let Ok(f) = fs::OpenOptions::new().write(true).open(entry.path()) {
                let _ = f.set_modified(ts);
            }
        }
    }
    let mut dirs: Vec<_> = walkdir::WalkDir::new(&wt_target)
        .follow_links(false)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.into_path())
        .collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for d in dirs {
        let _ = StdCommand::new("/usr/bin/touch")
            .args(["-m", "-d", "2020-01-01T00:00:00Z"])
            .arg(&d)
            .output();
    }

    // Plant stale `REBASE_HEAD` inside the worktree's git dir (without `rebase-merge/`)
    let gitdir_out = StdCommand::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(&wt)
        .output()
        .unwrap();
    let wt_gitdir = std::path::PathBuf::from(
        String::from_utf8(gitdir_out.stdout)
            .unwrap()
            .trim()
            .to_owned(),
    );
    fs::write(wt_gitdir.join("REBASE_HEAD"), b"0123456789abcdef\n").unwrap();

    // Step 1: status sees `main_repo` as `protected` (`git_op`) and `wt` as `eligible`!
    let status = cli(home.path(), &state_dir, &cfg_path)
        .args(["status", "--format", "json"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let targets = status_json["targets"].as_array().unwrap();
    let main_entry = targets
        .iter()
        .find(|t| t["root"].as_str().unwrap().contains("main_repo"))
        .unwrap();
    let wt_entry = targets
        .iter()
        .find(|t| t["root"].as_str().unwrap().contains("wt_sweep_then_evict"))
        .unwrap();
    assert_eq!(main_entry["verdict"], "protected");
    assert_eq!(wt_entry["verdict"], "eligible", "wt={wt_entry}");

    // Step 2: run `reclaim --profile sweep-only` (bumps `target/` and `incremental/<crate>/` mtimes to NOW!)
    let sweep = cli(home.path(), &state_dir, &cfg_path)
        .args(["reclaim", "--profile", "sweep-only", "--format", "json"])
        .output()
        .unwrap();
    assert!(sweep.status.success());
    let sweep_json: serde_json::Value = serde_json::from_slice(&sweep.stdout).unwrap();
    assert!(
        sweep_json["summary"]["applied_actions"].as_u64().unwrap() >= 2,
        "expected both R2 and R3 to apply: {sweep_json}"
    );
    assert!(!wt_target.join("debug/build/aborted").exists());
    assert!(!inc_crate.join("s-001-old-final").exists());
    assert!(inc_crate.join("s-002-new-final").exists());

    // Step 3: immediately run `reclaim --profile full` -> MUST NOT deadlock with `mtime_advanced`
    //         and MUST NOT have reset age to 0! `R1` MUST evict `wt/target` cleanly!
    let evict = cli(home.path(), &state_dir, &cfg_path)
        .args(["reclaim", "--profile", "full", "--format", "json"])
        .output()
        .unwrap();
    assert!(evict.status.success());
    let evict_json: serde_json::Value = serde_json::from_slice(&evict.stdout).unwrap();
    assert_eq!(
        evict_json["summary"]["applied_actions"], 1,
        "evict={evict_json}"
    );
    assert_eq!(evict_json["receipts"][0]["rule"], "r1_dead_worktree");
    assert!(!wt_target.exists());
    assert!(wt.join("Cargo.toml").exists());
}
