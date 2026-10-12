// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What clew decides, recorded.
//!
//! The pack version and the catalogue revision name the *set*: which rules
//! exist, how each is graded, and which rows are read for what. They do not
//! promise that a rule decided the same way, because nothing pinned a
//! decision. This does. Each fixture is a small repository and
//! `corpus.snapshot` holds the findings clew reports in it, so a rule whose
//! logic changes fails here rather than passing quietly under the same number.
//!
//! Nine of the twenty-two fixtures are silent on purpose. Every rule's prose
//! promises cases it does not fire on, and a rule that starts firing on one of
//! those is as much a regression as one that stops firing at all.
//!
//! A fixture is a manifest rather than a directory of real files, for one
//! reason: clew scans its own repository in CI, and a directory of deliberate
//! findings would fail that run. The manifest is written to a temporary
//! directory and scanned there.

// Every line of this file is test code, and panicking is how a test reports
// failure. `allow-expect-in-tests` covers a `#[test]` function and a
// `#[cfg(test)]` module, neither of which an integration test's helpers are,
// so the allowance is written out here instead.
#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use clew_adapter_fs::{StdFileContents, StdFileTree};
use clew_application::DiscoverSurfaces;
use clew_domain::catalogue;
use clew_domain::scan_policy::ScanPolicy;
use clew_domain::scope::Scope;

/// Where a manifest names the file that follows it.
const FILE: &str = ">>> ";

/// Where a manifest names a file whose bytes follow as hex, for content a
/// text manifest cannot hold.
const BYTES: &str = ">>>bytes ";

#[test]
fn every_fixture_reports_what_the_snapshot_records() {
    let mut held: Vec<String> = Vec::new();
    for fixture in fixtures() {
        let name = fixture
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a fixture name")
            .to_owned();
        let source = fs::read_to_string(&fixture).expect("a readable fixture");
        let at = laid_out(&name, &source);
        let report = scanned(&at);
        let _ = fs::remove_dir_all(&at);

        if report.findings.is_empty() {
            held.push(format!("{name} -"));
        }
        for finding in &report.findings {
            let at = finding.at.map_or_else(
                || "-".to_owned(),
                |p| format!("{}:{}", finding.path.as_str(), p.line),
            );
            held.push(format!(
                "{name} {} {} {at}",
                finding.rule.as_str(),
                finding.severity.as_str()
            ));
        }
        // A gap is not a result: a fixture clew could not read whole would
        // record fewer findings for a reason this file would not show.
        assert!(
            report.is_complete() || name.starts_with("unreadable"),
            "{name}: {:?} {:?}",
            report.unreadable,
            report.unparsed
        );
    }

    let snapshot = include_str!("corpus.snapshot");
    let pinned: Vec<&str> = snapshot
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect();

    assert_eq!(
        pinned,
        held.iter().map(String::as_str).collect::<Vec<_>>(),
        "what clew decides changed; update tests/corpus.snapshot once every \
         line below is what the rules should say"
    );
}

/// Every rule has a fixture that fires it, so a rule cannot ship with nothing
/// pinning what it decides.
#[test]
fn every_rule_fires_in_some_fixture() {
    let snapshot = include_str!("corpus.snapshot");
    let fired: Vec<&str> = snapshot
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter(|held| *held != "-")
        .collect();

    for rule in clew_domain::finding::RuleId::all() {
        assert!(
            fired.contains(&rule.as_str()),
            "{} fires in no fixture, so nothing pins what it decides",
            rule.as_str()
        );
    }
}

/// The fixtures, in name order so the snapshot is stable.
fn fixtures() -> Vec<PathBuf> {
    let at = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut held: Vec<PathBuf> = fs::read_dir(&at)
        .expect("a corpus directory")
        .filter_map(|entry| {
            let path = entry.expect("a readable entry").path();
            (path.extension()?.to_str()? == "fixture").then_some(path)
        })
        .collect();
    held.sort();
    assert!(
        !held.is_empty(),
        "no fixtures, so this would pass vacuously"
    );
    held
}

/// Write a manifest out as a tree, and say where.
///
/// Nothing here is platform-dependent on purpose. A fixture that laid out
/// differently on one operating system would record a different snapshot
/// there, which is a corpus that agrees with itself and nothing else.
fn laid_out(name: &str, source: &str) -> PathBuf {
    let at = std::env::temp_dir().join(format!("clew-corpus-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&at);
    fs::create_dir_all(&at).expect("a temporary directory");

    let mut writing: Option<(PathBuf, String, bool)> = None;
    let write = |held: Option<(PathBuf, String, bool)>| {
        let Some((path, text, hex)) = held else {
            return;
        };
        fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        if hex {
            fs::write(&path, decoded(&text)).expect("a written file");
        } else {
            fs::write(&path, text).expect("a written file");
        }
    };
    for line in source.lines() {
        if let Some(path) = line.strip_prefix(BYTES) {
            write(writing.take());
            writing = Some((at.join(path.trim()), String::new(), true));
        } else if let Some(path) = line.strip_prefix(FILE) {
            write(writing.take());
            writing = Some((at.join(path.trim()), String::new(), false));
        } else if let Some((_, text, _)) = writing.as_mut() {
            text.push_str(line);
            text.push('\n');
        }
    }
    write(writing.take());
    at
}

/// Hex, whitespace ignored, as the bytes it names.
fn decoded(text: &str) -> Vec<u8> {
    let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        digits.len().is_multiple_of(2),
        "hex needs two digits a byte"
    );
    digits
        .chunks(2)
        .map(|pair| {
            let held: String = pair.iter().collect();
            u8::from_str_radix(&held, 16).expect("a hex byte")
        })
        .collect()
}

/// Scan a laid-out fixture the way the binary scans a repository.
fn scanned(at: &Path) -> clew_application::DiscoveryReport {
    let policy = ScanPolicy::with_default_pruning(64);
    let tree = StdFileTree::new(at).following(&catalogue::shipped().roots_in(Scope::Repository));
    let contents = StdFileContents::new(at);
    DiscoverSurfaces::new(&tree, &contents, &policy)
        .in_scope(Scope::Repository)
        .run()
}
