use std::io;

/// Typed application errors for fail-closed handling and exit status mapping.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
    #[error("`{command}` is not implemented yet (scheduled for {stage})")]
    NotImplemented {
        command: &'static str,
        stage: &'static str,
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
    let mut message = String::new();
    for character in error.to_string().chars() {
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

    use super::{AppError, diagnostic};

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
    }
}
