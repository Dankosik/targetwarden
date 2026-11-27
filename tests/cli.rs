//! Built CLI contract tests: grammar, completions, independence from `HOME`, exit codes,
//! and Stage 1 read-only `status`/`scan` framing.

use std::fs;
use std::path::Path;
use std::time::Duration;

use assert_cmd::Command;

fn command(home: &Path) -> Command {
    let mut command = Command::cargo_bin("targetwarden").expect("binary is built");
    command
        .env_remove("TARGETWARDEN_FORMAT")
        .env_remove("TARGETWARDEN_CONFIG")
        .env_remove("TARGETWARDEN_STATE_DIR")
        .env_remove("CARGO_TARGET_DIR")
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .timeout(Duration::from_secs(60));
    command
}

#[test]
fn help_lists_commands_and_version_prints_without_home_reads() {
    let missing_home = tempfile::tempdir().unwrap().path().join("nonexistent");
    let help = command(&missing_home).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    let help_text = String::from_utf8(help.stdout).unwrap();
    for name in [
        "status",
        "scan",
        "reclaim",
        "watch",
        "pin",
        "unpin",
        "history",
        "install",
        "uninstall",
        "completions",
    ] {
        assert!(
            help_text.contains(name),
            "{name} missing from help:\n{help_text}"
        );
    }

    let version = command(&missing_home).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        format!("targetwarden {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn completions_zsh_prints_without_touching_system() {
    let home = tempfile::tempdir().unwrap();
    let output = command(home.path())
        .args(["completions", "zsh"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let script = String::from_utf8(output.stdout).unwrap();
    assert!(script.contains("targetwarden"));
}

#[test]
fn invalid_usage_returns_exit_code_2() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        &["--unknown-flag"][..],
        &["unknown-subcommand"][..],
        &["reclaim", "--profile", "bogus"][..],
    ] {
        let output = command(home.path()).args(args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "expected exit 2 for {args:?}"
        );
    }
}

#[test]
fn invalid_format_env_is_rejected_with_exit_code_2() {
    let home = tempfile::tempdir().unwrap();
    let output = command(home.path())
        .env("TARGETWARDEN_FORMAT", "bogus")
        .arg("watch")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[cfg(target_os = "macos")]
#[test]
fn status_and_scan_report_discovered_targets_without_writing_state() {
    let home = tempfile::tempdir().unwrap();
    let project_target = home.path().join("Projects/demo/target");
    fs::create_dir_all(project_target.join("debug/build/demo/0123456789abcdef/fingerprint"))
        .unwrap();
    fs::write(
        project_target.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n# Created by cargo.\n",
    )
    .unwrap();
    fs::write(
        project_target.join("debug/build/demo/0123456789abcdef/fingerprint/bin-demo.json"),
        r#"{"rustc":42,"deps":[]}"#,
    )
    .unwrap();

    let status = command(home.path())
        .args(["status", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(status.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "status");
    assert_eq!(json["totals"]["target_count"], 1);
    assert_eq!(json["targets"][0]["layout"], "build_dir_v2");

    // Read-only commands must never create state dir or run.lock
    let state_dir = home.path().join("Library/Application Support/targetwarden");
    assert!(!state_dir.exists());

    // Text mode scan against explicit path
    let scan = command(home.path())
        .args(["scan", home.path().join("Projects").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        scan.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let text = String::from_utf8(scan.stdout).unwrap();
    assert!(text.contains("Targets: 1"));
    assert!(text.contains("build_dir_v2"));
}

#[cfg(target_os = "macos")]
#[test]
fn scan_nonexistent_path_exits_1_with_sanitized_stderr() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("does-not-exist");
    let output = command(home.path())
        .args(["scan", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error:"));
}

#[cfg(target_os = "macos")]
fn backdate_tree(root: &Path, age: Duration) {
    let ts = std::time::SystemTime::now() - age;
    let mut dirs = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        let path = entry.path().to_path_buf();
        if entry.file_type().is_dir() {
            dirs.push(path);
        } else if let Ok(file) = fs::OpenOptions::new().write(true).open(&path) {
            let _ = file.set_modified(ts);
        }
    }
    // Touch directories bottom-up so child updates don't overwrite parent mtime.
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for dir in dirs {
        let _ = std::process::Command::new("/usr/bin/touch")
            .args(["-m", "-d", "2020-01-01T00:00:00Z"])
            .arg(&dir)
            .output();
    }
}

#[cfg(target_os = "macos")]
#[test]
fn reclaim_dry_run_and_apply_sweep_only_and_history_roundtrip() {
    let home = tempfile::tempdir().unwrap();
    let state_dir = home.path().join("state");
    let target = home.path().join("Projects/app/target");
    let debug = target.join("debug");

    fs::create_dir_all(debug.join("build/app/1111111111111111/fingerprint")).unwrap();
    fs::create_dir_all(debug.join("build/old_crate/2222222222222222/fingerprint")).unwrap();
    fs::create_dir_all(debug.join("incremental/app-fin0000000001/s-100-aaa-final")).unwrap();
    fs::create_dir_all(debug.join("incremental/app-wrk0000000002/s-200-bbb-working")).unwrap();
    fs::write(
        target.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n# Created by cargo.\n",
    )
    .unwrap();
    fs::write(
        debug.join("build/app/1111111111111111/fingerprint/bin-app.json"),
        r#"{"rustc":99999,"deps":[]}"#,
    )
    .unwrap();
    fs::write(
        debug.join("build/old_crate/2222222222222222/fingerprint/lib-old_crate.json"),
        r#"{"rustc":11111,"deps":[]}"#,
    )
    .unwrap();
    fs::write(
        debug.join("build/old_crate/2222222222222222/out_blob"),
        vec![0u8; 8192],
    )
    .unwrap();

    // Backdate everything > 48h; make active unit 5h old so rustc=99999 is active while rustc=11111 is stale (> 24h).
    backdate_tree(&target, Duration::from_secs(48 * 3600));
    let recent_ts = std::time::SystemTime::now() - Duration::from_secs(5 * 3600);
    fs::OpenOptions::new()
        .write(true)
        .open(debug.join("build/app/1111111111111111/fingerprint/bin-app.json"))
        .unwrap()
        .set_modified(recent_ts)
        .unwrap();

    // 1. Dry-run must NOT mutate target or create state_dir
    let dry = command(home.path())
        .env("TARGETWARDEN_STATE_DIR", &state_dir)
        .args([
            "reclaim",
            "--dry-run",
            "--profile",
            "sweep-only",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        dry.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let dry_json: serde_json::Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(dry_json["schema_version"], 1);
    assert_eq!(dry_json["dry_run"], true);
    assert!(dry_json["summary"]["planned_actions"].as_u64().unwrap() >= 2);
    assert!(!state_dir.exists());
    assert!(debug.join("build/old_crate/2222222222222222").exists());

    // 2. Apply sweep-only removes stale unit & working-only inc dir, keeps active & finalized
    let apply = command(home.path())
        .env("TARGETWARDEN_STATE_DIR", &state_dir)
        .args(["reclaim", "--profile", "sweep-only", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let apply_json: serde_json::Value = serde_json::from_slice(&apply.stdout).unwrap();
    assert_eq!(apply_json["dry_run"], false);
    assert!(apply_json["summary"]["applied_actions"].as_u64().unwrap() >= 2);
    assert!(debug.join("build/app/1111111111111111").exists());
    assert!(!debug.join("build/old_crate/2222222222222222").exists());
    assert!(debug.join("incremental/app-fin0000000001").exists());
    assert!(!debug.join("incremental/app-wrk0000000002").exists());

    // 3. History reads back recorded actions in JSON and text
    let hist = command(home.path())
        .env("TARGETWARDEN_STATE_DIR", &state_dir)
        .args(["history", "--limit", "10", "--format", "json"])
        .output()
        .unwrap();
    assert!(hist.status.success());
    let hist_json: serde_json::Value = serde_json::from_slice(&hist.stdout).unwrap();
    assert_eq!(hist_json["schema_version"], 1);
    assert!(hist_json["count"].as_u64().unwrap() >= 2);
}

#[cfg(target_os = "macos")]
#[test]
fn real_cargo_sweep_preserves_zero_recompilation_on_cargo_check() {
    let home = tempfile::tempdir().unwrap();
    let state_dir = home.path().join("state");
    let proj = home.path().join("Projects/mini_ws");
    fs::create_dir_all(proj.join("dep_lib/src")).unwrap();
    fs::create_dir_all(proj.join("app/src")).unwrap();
    fs::write(
        proj.join("Cargo.toml"),
        "[workspace]\nmembers = [\"dep_lib\", \"app\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    fs::write(
        proj.join("dep_lib/Cargo.toml"),
        "[package]\nname = \"dep_lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(
        proj.join("dep_lib/src/lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    )
    .unwrap();
    fs::write(
        proj.join("app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ndep_lib = { path = \"../dep_lib\" }\n[features]\nextra = []\n",
    )
    .unwrap();
    fs::write(
        proj.join("app/src/main.rs"),
        "fn main() { println!(\"{}\", dep_lib::answer()); }\n",
    )
    .unwrap();

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let run_cargo = |args: &[&str]| {
        std::process::Command::new(&cargo)
            .args(args)
            .current_dir(&proj)
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("cargo executes")
    };

    // Build once with `--features extra`, then once with default features
    let c1 = run_cargo(&["check", "--features", "extra"]);
    assert!(
        c1.status.success(),
        "cargo check --features extra failed: {}",
        String::from_utf8_lossy(&c1.stderr)
    );
    let c2 = run_cargo(&["check"]);
    assert!(
        c2.status.success(),
        "cargo check failed: {}",
        String::from_utf8_lossy(&c2.stderr)
    );

    // Inject an obsolete stale-rustc unit & abandoned working incremental dir alongside real artifacts,
    // then backdate target/ so cooling passes while keeping real units valid.
    let target = proj.join("target");
    fs::create_dir_all(target.join("debug/.fingerprint/stale_dep-000000000000cafe")).unwrap();
    fs::write(
        target.join("debug/.fingerprint/stale_dep-000000000000cafe/lib-stale_dep.json"),
        r#"{"rustc":1,"deps":[]}"#,
    )
    .unwrap();
    fs::write(
        target.join("debug/deps/libstale_dep-000000000000cafe.rlib"),
        vec![0u8; 4096],
    )
    .unwrap();
    fs::create_dir_all(target.join("debug/incremental/app-dead000000001/s-old-abc-working"))
        .unwrap();

    // Backdate source files to 48h ago so `source_mtime < fingerprint_mtime`,
    // backdate `target/` to 48h ago (so stale_dep is > 24h older than active rustc window),
    // and set real fingerprint files to 4h ago (> 2h dup_cooldown).
    backdate_tree(&proj, Duration::from_secs(48 * 3600));
    backdate_tree(&target, Duration::from_secs(48 * 3600));

    let real_ts = std::time::SystemTime::now() - Duration::from_secs(4 * 3600);
    for entry in walkdir::WalkDir::new(target.join("debug/.fingerprint"))
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if entry.path().to_string_lossy().contains("stale_dep") {
            continue;
        }
        if entry.file_type().is_file()
            && let Ok(f) = fs::OpenOptions::new().write(true).open(entry.path())
        {
            let _ = f.set_modified(real_ts);
        }
    }

    let sweep = command(home.path())
        .env("TARGETWARDEN_STATE_DIR", &state_dir)
        .args(["reclaim", "--profile", "sweep-only", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        sweep.status.success(),
        "sweep failed: {}",
        String::from_utf8_lossy(&sweep.stderr)
    );
    let sweep_json: serde_json::Value = serde_json::from_slice(&sweep.stdout).unwrap();
    assert!(
        sweep_json["summary"]["applied_actions"].as_u64().unwrap() >= 2,
        "expected build + incremental sweep: {sweep_json}"
    );
    assert!(
        !target
            .join("debug/.fingerprint/stale_dep-000000000000cafe")
            .exists()
    );
    assert!(
        !target
            .join("debug/deps/libstale_dep-000000000000cafe.rlib")
            .exists()
    );
    assert!(!target.join("debug/incremental/app-dead000000001").exists());

    // Subsequent `cargo check` MUST be a 100% cache hit (`recompiled = []`)!
    let c3 = run_cargo(&["check"]);
    assert!(
        c3.status.success(),
        "post-sweep cargo check failed: {}",
        String::from_utf8_lossy(&c3.stderr)
    );
    let stderr3 = String::from_utf8_lossy(&c3.stderr);
    assert!(
        !stderr3.contains("Compiling ") && !stderr3.contains("Checking "),
        "expected zero recompilation after surgical sweep, got:\n{stderr3}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn reclaim_exits_partial_3_when_action_fails_on_unwritable_target() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let state_dir = home.path().join("state");
    let target = home.path().join("Projects/ro_app/target");
    let debug = target.join("debug");
    fs::create_dir_all(debug.join("build/old_crate/2222222222222222/fingerprint")).unwrap();
    fs::write(
        target.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n# Created by cargo.\n",
    )
    .unwrap();
    backdate_tree(&target, Duration::from_secs(48 * 3600));

    // Make target root read-only (0555) so creating the internal staging dir fails -> ActionOutcome::Failed -> exit 3!
    fs::set_permissions(&target, fs::Permissions::from_mode(0o555)).unwrap();
    let out = command(home.path())
        .env("TARGETWARDEN_STATE_DIR", &state_dir)
        .args(["reclaim", "--profile", "sweep-only", "--format", "json"])
        .output()
        .unwrap();
    // Restore permissions immediately so tempdir cleans up cleanly!
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        out.status.code(),
        Some(3),
        "expected PARTIAL exit code 3, got {:?}, stdout={}, stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["summary"]["failed_actions"], 1);
}

#[cfg(unix)]
#[test]
fn broken_pipe_on_stdout_exits_0_cleanly() {
    use std::process::{Command as StdCommand, Stdio};

    let home = tempfile::tempdir().unwrap();
    let bin = assert_cmd::cargo::cargo_bin("targetwarden");
    let mut child = StdCommand::new(bin)
        .args(["completions", "zsh"])
        .env("HOME", home.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close stdout reader immediately to induce EPIPE on write!
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "BrokenPipe must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
}
