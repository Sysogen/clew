// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning a command line into a request.

use thiserror::Error;

/// How a report is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// Aligned text, for a person.
    #[default]
    Text,
    /// One JSON document, for a tool.
    Json,
    /// A SARIF 2.1.0 log, for code scanning. Repository scans only.
    Sarif,
}

/// What the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Scan a directory for agent surfaces.
    Path {
        /// The scan root.
        root: String,
        /// How to write the report.
        format: Format,
    },
    /// Scan the home directory for agent surfaces kept outside any
    /// repository.
    System {
        /// How to write the report.
        format: Format,
    },
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
    /// An option the command does not take.
    #[error("unknown option '{0}'")]
    UnknownOption(String),
    /// `--format` with nothing after it.
    #[error("'--format' needs a value: text, json or sarif")]
    MissingFormat,
    /// `--format` naming no known format.
    #[error("unknown format '{0}': expected text, json or sarif")]
    UnknownFormat(String),
    /// SARIF asked of a scan with no repository to place results in.
    #[error("SARIF places results in a repository: use it with 'clew path'")]
    SarifNeedsRepository,
}

/// Parse arguments, excluding the program name.
///
/// # Errors
///
/// Returns a [`ParseError`] when the first argument names no known command, or
/// an option is unknown or has no valid value.
pub fn parse<I, S>(args: I) -> Result<Command, ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();

    match args.first().map(String::as_str) {
        None | Some("--help" | "-h" | "help") => Ok(Command::Help),
        Some("--version" | "-V") => Ok(Command::Version),
        Some("path") => {
            let (positional, format) = options(&args[1..])?;
            Ok(Command::Path {
                root: positional
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| ".".to_owned()),
                format,
            })
        }
        Some("system") => match options(&args[1..])?.1 {
            Format::Sarif => Err(ParseError::SarifNeedsRepository),
            format => Ok(Command::System { format }),
        },
        Some(other) => Err(ParseError::UnknownCommand(other.to_owned())),
    }
}

/// The arguments after a command: its positionals, and the format asked for.
fn options(args: &[String]) -> Result<(Vec<String>, Format), ParseError> {
    let mut positional = Vec::new();
    let mut format = Format::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let value = if arg == "--format" {
            rest.next().ok_or(ParseError::MissingFormat)?.as_str()
        } else if let Some(value) = arg.strip_prefix("--format=") {
            value
        } else if arg.len() > 1 && arg.starts_with('-') {
            return Err(ParseError::UnknownOption(arg.clone()));
        } else {
            positional.push(arg.clone());
            continue;
        };
        format = match value {
            "text" => Format::Text,
            "json" => Format::Json,
            "sarif" => Format::Sarif,
            other => return Err(ParseError::UnknownFormat(other.to_owned())),
        };
    }
    Ok((positional, format))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(root: &str, format: Format) -> Command {
        Command::Path {
            root: root.to_owned(),
            format,
        }
    }

    #[test]
    fn system_takes_no_root() {
        let text = Format::Text;
        assert_eq!(parse(["system"]), Ok(Command::System { format: text }));
        assert_eq!(
            parse(["system", "/tmp"]),
            Ok(Command::System { format: text })
        );
    }

    #[test]
    fn no_arguments_is_help() {
        assert_eq!(parse(Vec::<String>::new()), Ok(Command::Help));
    }

    #[test]
    fn path_defaults_to_the_current_directory() {
        assert_eq!(parse(["path"]), Ok(path(".", Format::Text)));
    }

    #[test]
    fn path_accepts_an_explicit_root() {
        assert_eq!(parse(["path", "/tmp/x"]), Ok(path("/tmp/x", Format::Text)));
    }

    #[test]
    fn json_is_asked_for_either_way_and_anywhere_after_the_command() {
        assert_eq!(
            parse(["path", "/tmp/x", "--format", "json"]),
            Ok(path("/tmp/x", Format::Json))
        );
        assert_eq!(
            parse(["path", "--format", "json", "/tmp/x"]),
            Ok(path("/tmp/x", Format::Json))
        );
        assert_eq!(
            parse(["path", "--format=json"]),
            Ok(path(".", Format::Json))
        );
        assert_eq!(
            parse(["system", "--format", "json"]),
            Ok(Command::System {
                format: Format::Json
            })
        );
    }

    #[test]
    fn a_bad_option_is_an_error_not_a_silent_default() {
        assert_eq!(parse(["path", "--format"]), Err(ParseError::MissingFormat));
        assert_eq!(
            parse(["path", "--format", "xml"]),
            Err(ParseError::UnknownFormat("xml".to_owned()))
        );
        assert_eq!(
            parse(["system", "--verbose"]),
            Err(ParseError::UnknownOption("--verbose".to_owned()))
        );
    }

    #[test]
    fn sarif_is_for_a_repository_scan_only() {
        assert_eq!(
            parse(["path", "--format", "sarif"]),
            Ok(path(".", Format::Sarif))
        );
        assert_eq!(
            parse(["system", "--format", "sarif"]),
            Err(ParseError::SarifNeedsRepository)
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
