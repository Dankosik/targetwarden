//! Imperative Shell (Layer 5): pure LaunchAgent plist generator (`io.github.dankosik.targetwarden`)
//! and `install`/`uninstall` orchestration over `&impl Platform`.
//!
//! Allowed dependencies: `error`, `platform`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::error::AppError;
use crate::platform::Platform;

pub(crate) const LAUNCHAGENT_LABEL: &str = "io.github.dankosik.targetwarden";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstallOutcome {
    pub label: &'static str,
    pub domain: String,
    pub plist_path: PathBuf,
    pub log_path: PathBuf,
    pub plist_xml: String,
    pub launchctl_actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UninstallOutcome {
    pub label: &'static str,
    pub domain: String,
    pub plist_path: PathBuf,
    pub removed_plist: bool,
    pub booted_out: bool,
}

/// Pure LaunchAgent plist renderer (`Nice = 10`, `Aqua`, `ThrottleInterval = 60`,
/// deliberately omitting `ProcessType=Background` and `LowPriorityIO`).
pub(crate) fn render_plist(exe: &Path, home: &Path) -> Result<String, AppError> {
    if !exe.is_absolute() {
        return Err(AppError::InvalidPath {
            path: exe.to_path_buf(),
            message: "LaunchAgent executable path must be absolute".to_owned(),
        });
    }
    if !home.is_absolute() {
        return Err(AppError::InvalidPath {
            path: home.to_path_buf(),
            message: "HOME directory path must be absolute".to_owned(),
        });
    }

    let exe_str = path_to_valid_xml_utf8(exe)?;
    let log_path = log_path_for(home);
    let log_str = path_to_valid_xml_utf8(&log_path)?;

    let escaped_exe = escape_xml(exe_str);
    let escaped_log = escape_xml(log_str);

    Ok(format!(
        "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>{LAUNCHAGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{escaped_exe}</string>
        <string>watch</string>
    </array>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>60</integer>
    <key>Nice</key>
    <integer>10</integer>
    <key>StandardErrorPath</key>
    <string>{escaped_log}</string>
</dict>
</plist>
"
    ))
}

/// Install and bootstrap the per-user LaunchAgent over `&impl Platform`.
/// When `dry_run` is `true`, performs zero filesystem writes and zero `launchctl` invocations.
pub(crate) fn install(
    exe: &Path,
    home: &Path,
    dry_run: bool,
    platform: &impl Platform,
) -> Result<InstallOutcome, AppError> {
    let uid = platform.euid()?;
    if uid == 0 {
        return Err(AppError::RunningAsRoot);
    }

    let domain = format!("gui/{uid}");
    let service_target = format!("{domain}/{LAUNCHAGENT_LABEL}");
    let launch_agents_dir = home.join("Library").join("LaunchAgents");
    let plist_path = plist_path_for(home);
    let log_dir = home.join("Library").join("Logs");
    let log_path = log_path_for(home);

    let plist_str = path_to_valid_xml_utf8(&plist_path)?.to_owned();
    let plist_xml = render_plist(exe, home)?;
    let launchctl_actions = vec![
        format!("launchctl bootout {service_target}"),
        format!("launchctl enable {service_target}"),
        format!("launchctl bootstrap {domain} {plist_str}"),
    ];

    if dry_run {
        return Ok(InstallOutcome {
            label: LAUNCHAGENT_LABEL,
            domain,
            plist_path,
            log_path,
            plist_xml,
            launchctl_actions,
        });
    }

    fs::create_dir_all(&launch_agents_dir).map_err(|error| AppError::Store {
        path: launch_agents_dir.clone(),
        message: format!("cannot create LaunchAgents directory: {error}"),
    })?;
    fs::create_dir_all(&log_dir).map_err(|error| AppError::Store {
        path: log_dir.clone(),
        message: format!("cannot create Logs directory: {error}"),
    })?;

    write_plist_atomic(&launch_agents_dir, &plist_path, plist_xml.as_bytes())?;

    // Best-effort bootout of any existing registration so re-installing is idempotent.
    let _ = platform.run_launchctl(&["bootout", &service_target])?;

    let enable = platform.run_launchctl(&["enable", &service_target])?;
    if enable.status_code != Some(0) {
        return Err(AppError::CommandFailed {
            program: "launchctl",
            message: format!(
                "launchctl enable exited {:?}: {}",
                enable.status_code,
                String::from_utf8_lossy(&enable.stderr).trim()
            ),
        });
    }

    let bootstrap = platform.run_launchctl(&["bootstrap", &domain, &plist_str])?;
    if bootstrap.status_code != Some(0) {
        return Err(AppError::CommandFailed {
            program: "launchctl",
            message: format!(
                "launchctl bootstrap exited {:?}: {}",
                bootstrap.status_code,
                String::from_utf8_lossy(&bootstrap.stderr).trim()
            ),
        });
    }

    Ok(InstallOutcome {
        label: LAUNCHAGENT_LABEL,
        domain,
        plist_path,
        log_path,
        plist_xml,
        launchctl_actions,
    })
}

/// Bootout and remove the per-user LaunchAgent plist while preserving state and history.
pub(crate) fn uninstall(
    home: &Path,
    platform: &impl Platform,
) -> Result<UninstallOutcome, AppError> {
    let uid = platform.euid()?;
    if uid == 0 {
        return Err(AppError::RunningAsRoot);
    }

    let domain = format!("gui/{uid}");
    let service_target = format!("{domain}/{LAUNCHAGENT_LABEL}");
    let plist_path = plist_path_for(home);

    let bootout = platform.run_launchctl(&["bootout", &service_target])?;
    let booted_out = bootout.status_code == Some(0);

    let removed_plist = match fs::remove_file(&plist_path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(AppError::Store {
                path: plist_path,
                message: format!("cannot remove LaunchAgent plist: {error}"),
            });
        }
    };

    Ok(UninstallOutcome {
        label: LAUNCHAGENT_LABEL,
        domain,
        plist_path,
        removed_plist,
        booted_out,
    })
}

fn plist_path_for(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHAGENT_LABEL}.plist"))
}

fn log_path_for(home: &Path) -> PathBuf {
    home.join("Library").join("Logs").join("targetwarden.log")
}

fn path_to_valid_xml_utf8(path: &Path) -> Result<&str, AppError> {
    let text = path.to_str().ok_or_else(|| AppError::InvalidPath {
        path: path.to_path_buf(),
        message: "path is not valid UTF-8 for XML plist".to_owned(),
    })?;
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(AppError::InvalidPath {
            path: path.to_path_buf(),
            message: "path contains XML-invalid control character".to_owned(),
        });
    }
    Ok(text)
}

fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

fn write_plist_atomic(dir: &Path, dst: &Path, payload: &[u8]) -> Result<(), AppError> {
    let mut tmp = NamedTempFile::new_in(dir).map_err(|error| AppError::Store {
        path: dir.to_path_buf(),
        message: format!("cannot create temporary plist: {error}"),
    })?;
    tmp.write_all(payload).map_err(|error| AppError::Store {
        path: dst.to_path_buf(),
        message: format!("cannot write temporary plist: {error}"),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|error| AppError::Store {
                path: dst.to_path_buf(),
                message: format!("cannot set plist permissions: {error}"),
            })?;
    }
    tmp.as_file().sync_all().map_err(|error| AppError::Store {
        path: dst.to_path_buf(),
        message: format!("cannot sync temporary plist: {error}"),
    })?;
    tmp.persist(dst).map_err(|error| AppError::Store {
        path: dst.to_path_buf(),
        message: format!("cannot atomically persist plist: {}", error.error),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{LAUNCHAGENT_LABEL, install, render_plist, uninstall};
    use crate::error::AppError;
    use crate::model::{DiskStats, MountEntry, ProcessSnapshot};
    use crate::platform::{CommandOutput, LockProbe, Platform};

    struct FakePlatform {
        uid: u32,
        launchctl_calls: RefCell<Vec<Vec<String>>>,
        launchctl_results: RefCell<Vec<CommandOutput>>,
    }

    impl FakePlatform {
        fn new(uid: u32, results: Vec<CommandOutput>) -> Self {
            Self {
                uid,
                launchctl_calls: RefCell::new(Vec::new()),
                launchctl_results: RefCell::new(results),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.launchctl_calls.borrow().clone()
        }
    }

    impl Platform for FakePlatform {
        fn euid(&self) -> Result<u32, AppError> {
            Ok(self.uid)
        }
        fn now_unix(&self) -> u64 {
            1_800_000_000
        }
        fn disk_stats(&self, _volume: &Path) -> Result<DiskStats, AppError> {
            Err(AppError::UnsupportedPlatform)
        }
        fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
            Err(AppError::UnsupportedPlatform)
        }
        fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
            Err(AppError::UnsupportedPlatform)
        }
        fn run_git(&self, _cwd: &Path, _args: &[&str]) -> Result<CommandOutput, AppError> {
            Err(AppError::UnsupportedPlatform)
        }
        fn try_lock_readonly(&self, _path: &Path) -> Result<LockProbe, AppError> {
            Err(AppError::UnsupportedPlatform)
        }
        fn run_launchctl(&self, args: &[&str]) -> Result<CommandOutput, AppError> {
            self.launchctl_calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            let mut results = self.launchctl_results.borrow_mut();
            if results.is_empty() {
                Ok(CommandOutput {
                    status_code: Some(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            } else {
                Ok(results.remove(0))
            }
        }
    }

    fn ok_output() -> CommandOutput {
        CommandOutput {
            status_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn err_output(code: i32, stderr: &str) -> CommandOutput {
        CommandOutput {
            status_code: Some(code),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn render_plist_escapes_xml_and_omits_qos_throttling_keys() {
        let exe = Path::new("/opt/tools/a&b/<c>\"d'e/targetwarden");
        let home = Path::new("/Users/dev&ops");
        let xml = render_plist(exe, home).unwrap();

        let expected_label = format!("<string>{LAUNCHAGENT_LABEL}</string>");
        let expected_exe =
            "<string>/opt/tools/a&amp;b/&lt;c&gt;&quot;d&apos;e/targetwarden</string>";
        let expected_log = "<string>/Users/dev&amp;ops/Library/Logs/targetwarden.log</string>";
        assert!(xml.contains(&expected_label));
        assert!(xml.contains(expected_exe));
        assert!(xml.contains("<string>watch</string>"));
        assert!(xml.contains("<key>LimitLoadToSessionType</key>\n    <string>Aqua</string>"));
        assert!(xml.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(xml.contains("<key>KeepAlive</key>\n    <true/>"));
        assert!(xml.contains("<key>ThrottleInterval</key>\n    <integer>60</integer>"));
        assert!(xml.contains("<key>Nice</key>\n    <integer>10</integer>"));
        assert!(xml.contains(expected_log));

        // Must deliberately omit ProcessType=Background and LowPriorityIO per spec Section 4.5.
        assert!(!xml.contains("ProcessType"));
        assert!(!xml.contains("Background"));
        assert!(!xml.contains("LowPriorityIO"));

        // Reject relative paths and XML-illegal control bytes.
        assert!(render_plist(Path::new("relative/targetwarden"), home).is_err());
        assert!(render_plist(Path::new("/usr/bin/bad\x07exe"), home).is_err());
    }

    #[test]
    fn install_dry_run_makes_zero_writes_and_zero_launchctl_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let exe = PathBuf::from("/usr/local/bin/targetwarden");
        let platform = FakePlatform::new(501, vec![]);

        let outcome = install(&exe, home, true, &platform).unwrap();
        assert_eq!(outcome.label, LAUNCHAGENT_LABEL);
        assert_eq!(outcome.domain, "gui/501");
        assert!(!outcome.plist_path.exists());
        assert!(!home.join("Library").exists());
        assert!(platform.calls().is_empty());
        assert_eq!(outcome.launchctl_actions.len(), 3);
    }

    #[test]
    fn install_and_uninstall_drive_launchctl_sequence_and_preserve_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let state_dir = home.join("Library/Application Support/targetwarden");
        fs::create_dir_all(&state_dir).unwrap();
        let state_file = state_dir.join("state.json");
        fs::write(&state_file, b"{\"schema_version\":1}").unwrap();

        let exe = PathBuf::from("/opt/homebrew/bin/targetwarden");
        // Simulate first install where initial bootout returns 3 (not loaded yet), then enable=0, bootstrap=0.
        let platform = FakePlatform::new(
            501,
            vec![
                err_output(3, "No such process"),
                ok_output(),
                ok_output(),
                ok_output(),
            ],
        );

        let installed = install(&exe, home, false, &platform).unwrap();
        assert!(installed.plist_path.exists());
        assert!(home.join("Library/Logs").is_dir());
        let written = fs::read_to_string(&installed.plist_path).unwrap();
        assert_eq!(written, installed.plist_xml);

        let calls_after_install = platform.calls();
        assert_eq!(calls_after_install.len(), 3);
        assert_eq!(
            calls_after_install[0],
            vec!["bootout", "gui/501/io.github.dankosik.targetwarden"]
        );
        assert_eq!(
            calls_after_install[1],
            vec!["enable", "gui/501/io.github.dankosik.targetwarden"]
        );
        assert_eq!(
            calls_after_install[2],
            vec![
                "bootstrap",
                "gui/501",
                installed.plist_path.to_str().unwrap()
            ]
        );

        let uninstalled = uninstall(home, &platform).unwrap();
        assert!(uninstalled.booted_out);
        assert!(uninstalled.removed_plist);
        assert!(!installed.plist_path.exists());
        // State and history MUST be preserved across uninstall!
        assert!(state_file.exists());

        // Uninstall is idempotent when already removed & unloaded.
        let idle_platform = FakePlatform::new(501, vec![err_output(3, "not loaded")]);
        let second = uninstall(home, &idle_platform).unwrap();
        assert!(!second.booted_out);
        assert!(!second.removed_plist);
    }

    #[test]
    fn install_fails_closed_on_root_and_bootstrap_error() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = PathBuf::from("/usr/local/bin/targetwarden");

        let root_plat = FakePlatform::new(0, vec![]);
        assert!(matches!(
            install(&exe, tmp.path(), false, &root_plat),
            Err(AppError::RunningAsRoot)
        ));
        assert!(matches!(
            uninstall(tmp.path(), &root_plat),
            Err(AppError::RunningAsRoot)
        ));

        let fail_boot = FakePlatform::new(
            501,
            vec![
                ok_output(),
                ok_output(),
                err_output(5, "Input/output error"),
            ],
        );
        assert!(matches!(
            install(&exe, tmp.path(), false, &fail_boot),
            Err(AppError::CommandFailed {
                program: "launchctl",
                ..
            })
        ));
    }
}
