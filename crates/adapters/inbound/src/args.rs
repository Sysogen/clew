// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning a command line into a request.

use std::slice::Iter;

use clew_domain::finding::Severity;
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
        /// The severity at which a finding fails the run, if any.
        fail_on: Option<Severity>,
    },
    /// Scan the home directory for agent surfaces kept outside any
    /// repository.
    System {
        /// How to write the report.
        format: Format,
        /// The severity at which a finding fails the run, if any.
        fail_on: Option<Severity>,
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
    /// `--fail-on` with nothing after it.
    #[error("'--fail-on' needs a severity: low, medium or high")]
    MissingSeverity,
    /// `--fail-on` naming no known severity.
    #[error("unknown severity '{0}': expected low, medium or high")]
    UnknownSeverity(String),
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
            let options = options(&args[1..])?;
            Ok(Command::Path {
                root: options
                    .positional
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| ".".to_owned()),
                format: options.format,
                fail_on: options.fail_on,
            })
        }
        Some("system") => {
            let options = options(&args[1..])?;
            if options.format == Format::Sarif {
                return Err(ParseError::SarifNeedsRepository);
            }
            Ok(Command::System {
                format: options.format,
                fail_on: options.fail_on,
            })
        }
        Some(other) => Err(ParseError::UnknownCommand(other.to_owned())),
    }
}

/// What follows a command.
struct Options {
    positional: Vec<String>,
    format: Format,
    fail_on: Option<Severity>,
}

fn options(args: &[String]) -> Result<Options, ParseError> {
    let mut options = Options {
        positional: Vec::new(),
        format: Format::default(),
        fail_on: None,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if let Some(value) = value_of("--format", arg, &mut rest, ParseError::MissingFormat)? {
            options.format = match value {
                "text" => Format::Text,
                "json" => Format::Json,
                "sarif" => Format::Sarif,
                other => return Err(ParseError::UnknownFormat(other.to_owned())),
            };
        } else if let Some(value) =
            value_of("--fail-on", arg, &mut rest, ParseError::MissingSeverity)?
        {
            options.fail_on = Some(
                Severity::from_name(value)
                    .ok_or_else(|| ParseError::UnknownSeverity(value.to_owned()))?,
            );
        } else if arg.len() > 1 && arg.starts_with('-') {
            return Err(ParseError::UnknownOption(arg.clone()));
        } else {
            options.positional.push(arg.clone());
        }
    }
    Ok(options)
}

/// The value `arg` gives the option `name`, written `name value` or
/// `name=value`, or `None` when `arg` is not that option.
fn value_of<'a>(
    name: &str,
    arg: &'a str,
    rest: &mut Iter<'a, String>,
    missing: ParseError,
) -> Result<Option<&'a str>, ParseError> {
    if arg == name {
        return rest.next().map(|v| Some(v.as_str())).ok_or(missing);
    }
    Ok(arg.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(root: &str, format: Format) -> Command {
        Command::Path {
            root: root.to_owned(),
            format,
            fail_on: None,
        }
    }

    #[test]
    fn system_takes_no_root() {
        let system = || {
            Ok(Command::System {
                format: Format::Text,
                fail_on: None,
            })
        };
        assert_eq!(parse(["system"]), system());
        assert_eq!(parse(["system", "/tmp"]), system());
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
                format: Format::Json,
                fail_on: None
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
        assert_eq!(
            parse(["path", "--formats=json"]),
            Err(ParseError::UnknownOption("--formats=json".to_owned()))
        );
    }

    #[test]
    fn fail_on_names_a_severity_either_way() {
        assert_eq!(
            parse(["path", "--fail-on", "high"]),
            Ok(Command::Path {
                root: ".".to_owned(),
                format: Format::Text,
                fail_on: Some(Severity::High),
            })
        );
        assert_eq!(
            parse(["system", "--format=json", "--fail-on=medium"]),
            Ok(Command::System {
                format: Format::Json,
                fail_on: Some(Severity::Medium),
            })
        );
    }

    #[test]
    fn a_bad_severity_is_an_error_not_a_silent_default() {
        assert_eq!(
            parse(["path", "--fail-on"]),
            Err(ParseError::MissingSeverity)
        );
        assert_eq!(
            parse(["path", "--fail-on", "critical"]),
            Err(ParseError::UnknownSeverity("critical".to_owned()))
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
