use std::io;
use std::path::PathBuf;

/// Typed application errors for fail-closed handling and exit status mapping.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
    #[error("`{command}` is not implemented yet (scheduled for {stage})")]
    NotImplemented {
        command: &'static str,
        stage: &'static str,
    },
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    #[error("targetwarden supports macOS only")]
    UnsupportedPlatform,
    #[error("refusing to run as root (uid == 0)")]
    RunningAsRoot,
    #[error("cannot determine home directory (HOME is unset or empty)")]
    HomeUnavailable,
    #[error("cannot read config `{path}`: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot parse config `{path}`: {message}")]
    ConfigParse { path: PathBuf, message: String },
    #[error("invalid configuration: {message}")]
    ConfigInvalid { message: String },
    #[error("invalid path `{path}`: {message}")]
    InvalidPath { path: PathBuf, message: String },
    #[error("cannot read disk statistics for `{path}`: {message}")]
    DiskStats { path: PathBuf, message: String },
    #[error("process snapshot failed (fail-closed): {0}")]
    ProcessSnapshot(String),
    #[error("mount table inspection failed (fail-closed): {0}")]
    MountTable(String),
    #[error("external command `{program}` failed: {message}")]
    CommandFailed {
        program: &'static str,
        message: String,
    },
    #[error("lock probe failed for `{path}`: {source}")]
    LockProbe {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot write standard output: {0}")]
    Output(#[source] io::Error),
}

impl AppError {
    pub fn is_stdout_closed(&self) -> bool {
        matches!(self, Self::Output(error) if error.kind() == io::ErrorKind::BrokenPipe)
    }
}

/// Escape control bytes so untrusted paths or messages cannot issue terminal escapes.
pub(crate) fn diagnostic(error: &impl std::fmt::Display) -> String {
    sanitize_terminal_text(&error.to_string())
}

/// Escape ASCII and Unicode control characters in untrusted terminal output.
pub(crate) fn sanitize_terminal_text(text: &str) -> String {
    let mut message = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            message.extend(character.escape_default());
        } else {
            message.push(character);
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{AppError, diagnostic, sanitize_terminal_text};

    #[test]
    fn only_stdout_broken_pipe_is_a_clean_pipeline_end() {
        assert!(AppError::Output(io::ErrorKind::BrokenPipe.into()).is_stdout_closed());
        assert!(!AppError::Output(io::ErrorKind::PermissionDenied.into()).is_stdout_closed());
    }

    #[test]
    fn diagnostics_escape_terminal_controls() {
        assert_eq!(
            diagnostic(&"bad\u{1b}[2J\npath\t"),
            "bad\\u{1b}[2J\\npath\\t"
        );
        assert_eq!(
            sanitize_terminal_text("safe/path\r\u{0007}"),
            "safe/path\\r\\u{7}"
        );
    }
}
