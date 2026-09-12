// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning a command line into a request.

use thiserror::Error;

/// What the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Scan a directory for agent surfaces.
    Path {
        /// The scan root.
        root: String,
    },
    /// Scan the home directory for agent surfaces kept outside any
    /// repository.
    System,
    /// Print usage.
    Help,
    /// Print the version.
    Version,
}

/// Why a command line could not be understood.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// The first argument is not a known command.
    #[error("unknown command '{0}'")]
    UnknownCommand(String),
}

/// Parse arguments, excluding the program name.
///
/// # Errors
///
/// Returns [`ParseError::UnknownCommand`] when the first argument names no
/// known command.
pub fn parse<I, S>(args: I) -> Result<Command, ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();

    match args.first().map(String::as_str) {
        None | Some("--help" | "-h" | "help") => Ok(Command::Help),
        Some("--version" | "-V") => Ok(Command::Version),
        Some("path") => Ok(Command::Path {
            root: args.get(1).cloned().unwrap_or_else(|| ".".to_owned()),
        }),
        Some("system") => Ok(Command::System),
        Some(other) => Err(ParseError::UnknownCommand(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_takes_no_root() {
        assert_eq!(parse(["system"]), Ok(Command::System));
        assert_eq!(parse(["system", "/tmp"]), Ok(Command::System));
    }

    #[test]
    fn no_arguments_is_help() {
        assert_eq!(parse(Vec::<String>::new()), Ok(Command::Help));
    }

    #[test]
    fn path_defaults_to_the_current_directory() {
        assert_eq!(
            parse(["path"]),
            Ok(Command::Path {
                root: ".".to_owned()
            })
        );
    }

    #[test]
    fn path_accepts_an_explicit_root() {
        assert_eq!(
            parse(["path", "/tmp/x"]),
            Ok(Command::Path {
                root: "/tmp/x".to_owned()
            })
        );
    }

    #[test]
    fn both_version_flags_are_accepted() {
        assert_eq!(parse(["--version"]), Ok(Command::Version));
        assert_eq!(parse(["-V"]), Ok(Command::Version));
    }

    #[test]
    fn an_unknown_command_is_an_error_not_a_silent_default() {
        assert_eq!(
            parse(["scan"]),
            Err(ParseError::UnknownCommand("scan".to_owned()))
        );
    }
}
