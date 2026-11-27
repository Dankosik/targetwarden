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
