//! Built CLI contract tests: grammar, completions, independence from `HOME`, and exit codes.

use std::time::Duration;

use assert_cmd::Command;

fn command(home: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("targetwarden").expect("binary is built");
    command
        .env_remove("TARGETWARDEN_FORMAT")
        .env_remove("TARGETWARDEN_CONFIG")
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

#[test]
fn unimplemented_stage1_status_exits_1_with_sanitized_stderr() {
    let home = tempfile::tempdir().unwrap();
    let output = command(home.path()).arg("status").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("not implemented yet"));
}
