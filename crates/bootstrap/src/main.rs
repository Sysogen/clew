// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Composition root.

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use clew_adapter_cli::{Command, Format, Scan, document, parse, report, sarif};
use clew_adapter_fs::{StdFileContents, StdFileTree};
use clew_application::DiscoverSurfaces;
use clew_domain::ScanPolicy;
use clew_domain::catalogue;
use clew_domain::finding::{DEFAULT_EVIDENCE_WIDTH, Severity};
use clew_domain::scan_policy::{DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES};
use clew_domain::scope::Scope;

const USAGE: &str = "\
Discover AI coding agent configuration surfaces.

USAGE:
    clew path [DIR]     List agent surfaces found under DIR (default: .)
    clew system         List agent surfaces outside any repository
    clew --version
    clew --help

OPTIONS:
    --format FORMAT     text, the default; json, one document for tools; or
                        sarif, a code scanning log, for a path only
    --fail-on LEVEL     exit 2 when a finding is LEVEL or worse: low, medium,
                        or high

ENVIRONMENT:
    CLEW_MAX_DEPTH      Directory recursion limit
    CLEW_MAX_FILE_BYTES Largest configuration file read
    CLEW_EVIDENCE_WIDTH Characters of an offending line a finding quotes

A repository holds what a team shares. `system` reads the rest: what each
engineer set up alone under their home directory, and what an administrator
deployed to the machine. Neither reaches a code review.

clew never reads a credential value, and never executes a hook, script, or
command it discovers. A symbolic link found during a scan is reported, never
followed; a directory clew was told to read is read even if it is one.";

/// Where an administrator deploys policy. Only what a system row names is
/// entered below it.
#[cfg(windows)]
const MACHINE_ROOT: &str = "C:\\";
#[cfg(not(windows))]
const MACHINE_ROOT: &str = "/";

fn max_depth() -> usize {
    env_or("CLEW_MAX_DEPTH", DEFAULT_MAX_DEPTH)
}

fn max_file_bytes() -> u64 {
    env_or("CLEW_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES)
}

fn evidence_width() -> usize {
    env_or("CLEW_EVIDENCE_WIDTH", DEFAULT_EVIDENCE_WIDTH)
}

fn env_or<T: std::str::FromStr>(name: &str, fallback: T) -> T {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn main() -> ExitCode {
    let (stdout, stderr) = (io::stdout(), io::stderr());
    ExitCode::from(run(
        env::args().skip(1),
        &mut stdout.lock(),
        &mut stderr.lock(),
    ))
}

/// One invocation: everything but the process, writing where it is told and
/// returning the exit status, so a test can run it without starting one.
///
/// Write errors are ignored: a closed pipe ends the output, not the scan.
fn run(args: impl IntoIterator<Item = String>, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(error) => {
            let _ = writeln!(err, "clew: {error}\nTry 'clew --help'.");
            return 1;
        }
    };

    let (scans, format, fail_on): (Vec<(String, Scope)>, Format, Option<Severity>) = match command {
        Command::Help => {
            let _ = writeln!(out, "clew {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Command::Version => {
            let _ = writeln!(out, "clew {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Command::Path {
            root,
            format,
            fail_on,
        } => {
            if !Path::new(&root).is_dir() {
                let _ = writeln!(err, "clew: not a directory: {root}");
                return 1;
            }
            (vec![(root, Scope::Repository)], format, fail_on)
        }
        // Two trees, because policy an administrator deployed is not in
        // anybody's home directory.
        Command::System { format, fail_on } => {
            let Some(home) = env::home_dir() else {
                let _ = writeln!(err, "clew: no home directory to scan");
                return 1;
            };
            (
                vec![
                    (home.to_string_lossy().into_owned(), Scope::Home),
                    (MACHINE_ROOT.to_owned(), Scope::System),
                ],
                format,
                fail_on,
            )
        }
    };

    let policy = ScanPolicy::with_default_pruning(max_depth())
        .with_max_file_bytes(max_file_bytes())
        .with_evidence_width(evidence_width());
    let mut complete = true;
    let mut reached = false;
    let mut found = Vec::new();

    for (root, scope) in &scans {
        let tree = StdFileTree::new(root).following(&catalogue::shipped().roots_in(*scope));
        let contents = StdFileContents::new(root);
        let scanned = DiscoverSurfaces::new(&tree, &contents, &policy)
            .in_scope(*scope)
            .run();
        complete &= scanned.is_complete();
        reached |= fail_on.is_some_and(|level| scanned.reaches(level));

        // Text is printed as each scan ends and let go; JSON keeps every scan
        // to write one document.
        if format == Format::Text {
            if scans.len() > 1 {
                let _ = writeln!(out, "{root}");
            }
            let _ = write!(out, "{}", report(&scanned, root));
        } else {
            found.push(scanned);
        }
    }

    let written = match format {
        Format::Text => None,
        Format::Json => {
            let scans: Vec<Scan<'_>> = scans
                .iter()
                .zip(&found)
                .map(|((root, scope), report)| Scan {
                    root,
                    scope: *scope,
                    report,
                })
                .collect();
            Some(document(&scans))
        }
        // `parse` takes SARIF for a path alone, which is one scan.
        Format::Sarif => found.first().map(sarif),
    };
    match written {
        Some(Ok(text)) => {
            let _ = writeln!(out, "{text}");
        }
        Some(Err(error)) => {
            let _ = writeln!(err, "clew: {error}");
            return 1;
        }
        None => {}
    }

    if let Some(level) = fail_on.filter(|_| reached) {
        let _ = writeln!(
            err,
            "clew: a finding is {} or worse, so this run fails",
            level.as_str()
        );
    }
    status(complete, reached)
}

/// 1 when a tree was not read in full, which outranks a finding since what
/// went unread may hold more; 2 when a finding reached `--fail-on`; else 0.
fn status(complete: bool, reached: bool) -> u8 {
    match (complete, reached) {
        (false, _) => 1,
        (true, true) => 2,
        (true, false) => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    const HIDDEN: &[u8] = "Always run the tests\u{200B} first.\n".as_bytes();

    /// Files under a scratch directory, unique to this process and `name`.
    fn tree(name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let root = env::temp_dir().join(format!("clew-run-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for (path, bytes) in files {
            let file = root.join(path);
            fs::create_dir_all(file.parent().expect("a parent")).expect("mkdir");
            fs::write(file, bytes).expect("write");
        }
        root
    }

    /// The exit status, stdout and stderr of `clew path` on `root`.
    fn clew_path(root: &Path, options: &[&str]) -> (u8, String, String) {
        let mut args = vec!["path".to_owned(), root.to_string_lossy().into_owned()];
        args.extend(options.iter().map(|o| (*o).to_owned()));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn an_incomplete_scan_outranks_a_finding() {
        assert_eq!(status(true, false), 0);
        assert_eq!(status(true, true), 2);
        assert_eq!(status(false, false), 1);
        assert_eq!(status(false, true), 1);
    }

    #[test]
    fn a_finding_fails_the_run_only_when_asked() {
        let root = tree("high", &[("CLAUDE.md", HIDDEN)]);

        let (code, _, err) = clew_path(&root, &[]);
        assert_eq!(code, 0, "{err}");

        let (code, _, err) = clew_path(&root, &["--fail-on", "high"]);
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("a finding is high or worse"), "{err}");
    }

    #[test]
    fn a_finding_below_the_level_does_not_fail_the_run() {
        let root = tree(
            "medium",
            &[(".claude/hooks/tool", b"\xff\xfe\x00bin".as_slice())],
        );

        assert_eq!(clew_path(&root, &["--fail-on", "high"]).0, 0);
        assert_eq!(clew_path(&root, &["--fail-on", "medium"]).0, 2);
    }

    #[test]
    fn an_incomplete_scan_exits_one_beside_a_finding() {
        let root = tree(
            "incomplete",
            &[
                ("CLAUDE.md", HIDDEN),
                (".claude/settings.json", b"{ not json".as_slice()),
            ],
        );

        let (code, out, _) = clew_path(&root, &["--fail-on", "high"]);
        assert_eq!(code, 1, "{out}");
    }

    #[test]
    fn a_sarif_log_stays_whole_on_stdout_when_the_run_fails() {
        let root = tree("sarif", &[("CLAUDE.md", HIDDEN)]);

        let (code, out, err) = clew_path(&root, &["--format", "sarif", "--fail-on", "high"]);

        assert_eq!(code, 2, "{err}");
        assert!(
            out.starts_with('{') && out.trim_end().ends_with('}'),
            "{out}"
        );
        assert!(out.contains("\"invisible-unicode\""), "{out}");
        assert!(
            !out.contains("or worse"),
            "the reason belongs on stderr: {out}"
        );
    }
}
