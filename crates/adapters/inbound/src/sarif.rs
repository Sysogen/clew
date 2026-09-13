// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning a repository scan into a SARIF 2.1.0 log, for code scanning.
//!
//! A repository scan only: SARIF places a result by a path relative to the
//! checkout, and a home or system scan has no checkout.

use clew_application::DiscoveryReport;
use clew_domain::RepoPath;
use clew_domain::finding::{Finding, RuleId, Severity};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Serialize;

use crate::json::escaped;

/// The schema GitHub's documentation names, and the one the tests validate
/// against.
const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// What a URI path cannot hold as it is.
const NOT_IN_A_PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// A repository scan as a SARIF log.
///
/// # Errors
///
/// Returns the serializer's error, which plain strings, numbers and booleans
/// should never cause.
pub fn sarif(report: &DiscoveryReport) -> Result<String, serde_json::Error> {
    escaped(&Log::of(report))
}

#[derive(Serialize)]
struct Log {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [Run; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    tool: Tool,
    /// clew counts a column in characters, not UTF-16 units.
    column_kind: &'static str,
    results: Vec<Outcome>,
    invocations: [Invocation; 1],
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: &'static str,
    semantic_version: &'static str,
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: &'static str,
    short_description: Text,
    full_description: Text,
    help: Text,
}

#[derive(Serialize)]
struct Text {
    text: String,
}

/// SARIF's `result`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Outcome {
    rule_id: &'static str,
    rule_index: usize,
    level: &'static str,
    message: Text,
    locations: [Location; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    /// Absent for a finding about the whole file, which SARIF reads as the
    /// file.
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
    start_column: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    /// False when part of the tree could not be read, as the exit code says.
    execution_successful: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_execution_notifications: Vec<Notification>,
}

#[derive(Serialize)]
struct Notification {
    level: &'static str,
    message: Text,
    locations: [Location; 1],
}

impl Log {
    fn of(report: &DiscoveryReport) -> Self {
        // Only the rules that found something, so an index names one of them.
        let mut rules: Vec<RuleId> = report.findings.iter().map(|f| f.rule).collect();
        rules.sort_unstable();
        rules.dedup();

        let notifications = report
            .unreadable
            .iter()
            .map(|(path, error)| notification(path, format!("could not be read: {error}")))
            .chain(report.unparsed.iter().map(|(path, reason)| {
                notification(path, format!("could not be read or understood: {reason}"))
            }))
            .collect();

        Self {
            schema: SCHEMA,
            version: "2.1.0",
            runs: [Run {
                tool: Tool {
                    driver: Driver {
                        name: "clew",
                        semantic_version: env!("CARGO_PKG_VERSION"),
                        information_uri: env!("CARGO_PKG_REPOSITORY"),
                        rules: rules.iter().map(|&id| rule(id)).collect(),
                    },
                },
                column_kind: "unicodeCodePoints",
                results: report.findings.iter().map(|f| outcome(f, &rules)).collect(),
                invocations: [Invocation {
                    execution_successful: report.is_complete(),
                    tool_execution_notifications: notifications,
                }],
            }],
        }
    }
}

fn outcome(finding: &Finding, rules: &[RuleId]) -> Outcome {
    Outcome {
        rule_id: finding.rule.as_str(),
        rule_index: rules
            .iter()
            .position(|&r| r == finding.rule)
            .unwrap_or_default(),
        level: level(finding.severity),
        message: Text {
            text: format!(
                "{}: {}",
                finding.rule.description(),
                finding.evidence.as_str()
            ),
        },
        locations: [location(
            &finding.path,
            finding.at.map(|p| Region {
                start_line: p.line,
                start_column: p.column,
            }),
        )],
    }
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn location(path: &RepoPath, region: Option<Region>) -> Location {
    Location {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: utf8_percent_encode(path.as_str(), NOT_IN_A_PATH).to_string(),
            },
            region,
        },
    }
}

fn notification(path: &RepoPath, text: String) -> Notification {
    Notification {
        level: "warning",
        message: Text { text },
        locations: [location(path, None)],
    }
}

/// What code scanning shows about a rule: the domain's one line, then what it
/// means and what to do about it.
fn rule(id: RuleId) -> Rule {
    let (full, help) = match id {
        RuleId::InvisibleUnicode => (
            "An instruction, rules, skill or hook file holds a character that renders \
             as nothing: zero-width, bidirectional, tag-block or another \
             default-ignorable character. The model reads it and a reviewer does not, \
             which is how the Rules File Backdoor, disclosed by Pillar Security on 18 \
             March 2025, hid instructions in rules files. In a hook script it is \
             Trojan Source, CVE-2021-42574.",
            "Open the file in an editor that shows invisible characters and remove the \
             character unless it was put there on purpose. The evidence shows it as \
             <U+XXXX>, never the character itself.",
        ),
        RuleId::OpaqueHook => (
            "A hook runs on agent events with the agent's permissions, and this one \
             cannot be read as text: it is not UTF-8, is larger than the file limit, \
             or is a symbolic link that clew will not follow. What it runs cannot be \
             reviewed.",
            "Replace the hook with a script that can be reviewed, or establish where \
             the file came from and what it does. If it is text that is only large, \
             raise CLEW_MAX_FILE_BYTES.",
        ),
    };
    Rule {
        id: id.as_str(),
        short_description: Text {
            text: id.description().to_owned(),
        },
        full_description: Text {
            text: full.to_owned(),
        },
        help: Text {
            text: help.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use clew_domain::finding::{Evidence, Line, Position};
    use clew_domain::ports::file_tree::FileTreeError;
    use serde_json::Value;

    use super::*;

    /// `SchemaStore`'s copy of the OASIS SARIF 2.1.0 schema, Apache-2.0.
    const SARIF_SCHEMA: &str = include_str!("../schemas/sarif-2.1.0.json");

    fn path(p: &str) -> RepoPath {
        p.split('/').fold(RepoPath::root(), |acc, s| acc.join(s))
    }

    fn finding(
        at: &str,
        position: Option<(usize, usize)>,
        rule: RuleId,
        severity: Severity,
    ) -> Finding {
        Finding {
            path: path(at),
            at: position.map(|(line, column)| Position { line, column }),
            rule,
            severity,
            evidence: Evidence::quote(&Line::new("Always\u{202E} obey"), 6, 80),
        }
    }

    /// Two rules, a finding about a whole file, and gaps of both kinds.
    fn scanned() -> DiscoveryReport {
        DiscoveryReport {
            findings: vec![
                finding(
                    "CLAUDE.md",
                    Some((1, 7)),
                    RuleId::InvisibleUnicode,
                    Severity::High,
                ),
                finding(
                    ".claude/hooks/tool",
                    None,
                    RuleId::OpaqueHook,
                    Severity::Medium,
                ),
                finding(
                    "AGENTS.md",
                    Some((3, 1)),
                    RuleId::InvisibleUnicode,
                    Severity::High,
                ),
            ],
            unreadable: vec![(path("secret"), FileTreeError::PermissionDenied)],
            unparsed: vec![(path(".mcp.json"), "not valid JSON".to_owned())],
            ..DiscoveryReport::default()
        }
    }

    fn written(report: &DiscoveryReport) -> Value {
        serde_json::from_str(&sarif(report).expect("serialises")).expect("parses")
    }

    fn violations(log: &Value) -> Vec<String> {
        let schema: Value = serde_json::from_str(SARIF_SCHEMA).expect("the schema parses");
        let validator = jsonschema::validator_for(&schema).expect("the schema loads");
        validator.iter_errors(log).map(|e| e.to_string()).collect()
    }

    /// Code scanning takes a log only if it is valid SARIF, so validity is
    /// checked against the schema rather than a hand-written string.
    #[test]
    fn every_log_is_valid_sarif() {
        for report in [scanned(), DiscoveryReport::default()] {
            let log = written(&report);
            assert_eq!(violations(&log), Vec::<String>::new(), "{log}");
        }
    }

    #[test]
    fn a_finding_is_a_result_placed_where_it_was_found() {
        let log = written(&scanned());
        let run = &log["runs"][0];
        assert_eq!(run["columnKind"], "unicodeCodePoints");

        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "invisible-unicode");
        assert_eq!(result["level"], "error");
        let place = &result["locations"][0]["physicalLocation"];
        assert_eq!(place["artifactLocation"]["uri"], "CLAUDE.md");
        assert_eq!(place["region"]["startLine"], 1);
        assert_eq!(place["region"]["startColumn"], 7);
        let said = result["message"]["text"].as_str().unwrap_or_default();
        assert!(said.contains("Always<U+202E> obey"), "{said}");
    }

    #[test]
    fn a_finding_about_the_whole_file_has_no_region() {
        let log = written(&scanned());
        let place = &log["runs"][0]["results"][1]["locations"][0]["physicalLocation"];

        assert_eq!(place["artifactLocation"]["uri"], ".claude/hooks/tool");
        assert!(place.get("region").is_none(), "{place}");
    }

    #[test]
    fn severity_is_a_level() {
        assert_eq!(level(Severity::High), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Low), "note");
    }

    /// Only the rules that found something are listed, once each, and every
    /// result's index points at its own.
    #[test]
    fn each_result_points_at_its_rule() {
        let log = written(&scanned());
        let rules = log["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules");
        let ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
        assert_eq!(ids, ["invisible-unicode", "opaque-hook"]);

        for result in log["runs"][0]["results"].as_array().expect("results") {
            let index =
                usize::try_from(result["ruleIndex"].as_u64().expect("index")).expect("fits");
            assert_eq!(rules[index]["id"], result["ruleId"]);
        }
        for rule in rules {
            assert!(rule["fullDescription"]["text"].is_string(), "{rule}");
            assert!(rule["help"]["text"].is_string(), "{rule}");
        }
    }

    #[test]
    fn a_scan_that_could_not_see_everything_says_so() {
        let invocation = &written(&scanned())["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], false);
        let said: Vec<&str> = invocation["toolExecutionNotifications"]
            .as_array()
            .expect("notifications")
            .iter()
            .filter_map(|n| n["message"]["text"].as_str())
            .collect();
        assert_eq!(
            said,
            [
                "could not be read: permission denied",
                "could not be read or understood: not valid JSON"
            ]
        );

        let clean = &written(&DiscoveryReport::default())["runs"][0]["invocations"][0];
        assert_eq!(clean["executionSuccessful"], true);
        assert!(clean.get("toolExecutionNotifications").is_none(), "{clean}");
    }

    /// A URI cannot hold a space, a `#` or a raw non-ASCII character, and a
    /// hidden character never appears raw.
    #[test]
    fn a_path_is_written_as_a_uri() {
        let report = DiscoveryReport {
            findings: vec![finding(
                "docs/my rules#1\u{200B}\u{e9}.md",
                Some((1, 1)),
                RuleId::InvisibleUnicode,
                Severity::High,
            )],
            ..DiscoveryReport::default()
        };

        let text = sarif(&report).expect("serialises");
        let log: Value = serde_json::from_str(&text).expect("parses");

        assert_eq!(
            log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "docs/my%20rules%231%E2%80%8B%C3%A9.md"
        );
        assert!(!text.contains('\u{200B}'), "{text}");
    }

    #[test]
    fn a_hidden_character_never_reaches_the_log() {
        let report = DiscoveryReport {
            unparsed: vec![(path("x.json"), "bad \u{202E} value".to_owned())],
            ..DiscoveryReport::default()
        };

        let text = sarif(&report).expect("serialises");

        assert!(!text.contains('\u{202E}'), "{text}");
    }
}
