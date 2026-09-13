// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning discovery reports into one JSON document.
//!
//! Tools read it, so it is a contract: [`VERSION`] is raised when a field
//! changes meaning or goes away. A hidden or control character in any string is
//! written as a `\u` escape, so the document decodes to exactly what was found
//! without carrying the character itself.

use std::io;

use clew_application::DiscoveryReport;
use clew_domain::hook::Action;
use clew_domain::mcp_server::Transport;
use clew_domain::rules::is_hidden;
use clew_domain::scope::Scope;
use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};

/// The document's shape, raised when a field changes meaning or goes away.
pub const VERSION: u32 = 1;

/// One scan: the tree it read, and what it found there.
#[derive(Debug, Clone, Copy)]
pub struct Scan<'a> {
    /// The directory it was rooted at.
    pub root: &'a str,
    /// Which tree that is.
    pub scope: Scope,
    /// What it found.
    pub report: &'a DiscoveryReport,
}

/// The scans as one JSON document.
///
/// # Errors
///
/// Returns the serializer's error, which plain strings, numbers and booleans
/// should never cause.
pub fn document(scans: &[Scan<'_>]) -> Result<String, serde_json::Error> {
    let mut out = Vec::new();
    Document::of(scans).serialize(&mut Serializer::with_formatter(&mut out, Escaping))?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Compact JSON, with every hidden or control character escaped.
struct Escaping;

impl Formatter for Escaping {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut start = 0;
        for (at, c) in fragment.char_indices() {
            if c.is_control() || is_hidden(c) {
                writer.write_all(&fragment.as_bytes()[start..at])?;
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(writer, "\\u{unit:04x}")?;
                }
                start = at + c.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct Document {
    version: u32,
    scans: Vec<ScanOut>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct ScanOut {
    root: String,
    scope: String,
    complete: bool,
    surfaces: Vec<SurfaceOut>,
    hooks: Vec<HookOut>,
    permissions: Vec<PermissionOut>,
    servers: Vec<ServerOut>,
    findings: Vec<FindingOut>,
    unreadable: Vec<Problem>,
    unparsed: Vec<Problem>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct SurfaceOut {
    path: String,
    kind: String,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct HookOut {
    source: String,
    event: String,
    action: String,
    text: String,
    #[serde(rename = "type")]
    kind: Option<String>,
    enabled: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct PermissionOut {
    source: String,
    tool: String,
    scope: Option<String>,
    unscoped: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct ServerOut {
    source: String,
    name: String,
    transport: TransportOut,
    env: Vec<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
#[serde(tag = "type", rename_all = "lowercase")]
enum TransportOut {
    Local { command: String, args: Vec<String> },
    Remote { url: String },
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct FindingOut {
    path: String,
    line: Option<usize>,
    column: Option<usize>,
    rule: String,
    severity: String,
    evidence: String,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct Problem {
    path: String,
    reason: String,
}

impl Document {
    fn of(scans: &[Scan<'_>]) -> Self {
        Self {
            version: VERSION,
            scans: scans.iter().map(ScanOut::of).collect(),
        }
    }
}

impl ScanOut {
    fn of(scan: &Scan<'_>) -> Self {
        let report = scan.report;
        Self {
            root: scan.root.to_owned(),
            scope: scan.scope.as_str().to_owned(),
            complete: report.is_complete(),
            surfaces: report
                .surfaces
                .iter()
                .map(|s| SurfaceOut {
                    path: s.path.as_str().to_owned(),
                    kind: s.kind.as_str().to_owned(),
                })
                .collect(),
            hooks: report
                .hooks
                .iter()
                .map(|h| HookOut {
                    source: h.source.as_str().to_owned(),
                    event: h.hook.event.clone(),
                    action: match h.hook.action {
                        Action::Command(_) => "command",
                        Action::Prompt(_) => "prompt",
                    }
                    .to_owned(),
                    text: h.hook.action.text().to_owned(),
                    kind: h.hook.kind.clone(),
                    enabled: h.hook.enabled,
                })
                .collect(),
            permissions: report
                .permissions
                .iter()
                .map(|g| PermissionOut {
                    source: g.source.as_str().to_owned(),
                    tool: g.permission.tool.clone(),
                    scope: g.permission.scope.clone(),
                    unscoped: g.permission.is_unscoped(),
                })
                .collect(),
            servers: report
                .servers
                .iter()
                .map(|d| ServerOut {
                    source: d.source.as_str().to_owned(),
                    name: d.server.name.clone(),
                    transport: match &d.server.transport {
                        Transport::Local { command, args } => TransportOut::Local {
                            command: command.clone(),
                            args: args.clone(),
                        },
                        Transport::Remote { url } => TransportOut::Remote { url: url.clone() },
                    },
                    env: d.server.env.clone(),
                })
                .collect(),
            findings: report
                .findings
                .iter()
                .map(|f| FindingOut {
                    path: f.path.as_str().to_owned(),
                    line: f.at.map(|p| p.line),
                    column: f.at.map(|p| p.column),
                    rule: f.rule.as_str().to_owned(),
                    severity: f.severity.as_str().to_owned(),
                    evidence: f.evidence.as_str().to_owned(),
                })
                .collect(),
            unreadable: report
                .unreadable
                .iter()
                .map(|(path, error)| Problem {
                    path: path.as_str().to_owned(),
                    reason: error.to_string(),
                })
                .collect(),
            unparsed: report
                .unparsed
                .iter()
                .map(|(path, reason)| Problem {
                    path: path.as_str().to_owned(),
                    reason: reason.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use clew_application::{DeclaredServer, GrantedPermission, RegisteredHook};
    use clew_domain::finding::{Evidence, Finding, Line, RuleId, Severity};
    use clew_domain::ports::file_tree::FileTreeError;
    use clew_domain::{Hook, McpServer, Permission, RepoPath, Surface, SurfaceKind};
    use serde_json::Value;

    use super::*;

    fn path(p: &str) -> RepoPath {
        p.split('/').fold(RepoPath::root(), |acc, s| acc.join(s))
    }

    /// One of everything a report can hold.
    fn full() -> DiscoveryReport {
        let settings = path(".claude/settings.json");
        let args = ["--api-key".to_owned(), "sk-live-SECRET".to_owned()];
        DiscoveryReport {
            surfaces: vec![Surface {
                path: settings.clone(),
                kind: SurfaceKind::ClaudeCode,
            }],
            hooks: vec![RegisteredHook {
                source: settings.clone(),
                hook: Hook {
                    event: "SessionStart".to_owned(),
                    action: Action::Prompt("Be brief".to_owned()),
                    kind: None,
                    enabled: false,
                },
            }],
            permissions: vec![GrantedPermission {
                source: settings,
                permission: Permission::parse("WebSearch").expect("valid entry"),
            }],
            servers: vec![DeclaredServer {
                source: path(".mcp.json"),
                server: McpServer {
                    name: "pg".to_owned(),
                    transport: Transport::local("npx".to_owned(), &args),
                    env: vec!["DATABASE_URL".to_owned()],
                },
            }],
            unreadable: vec![(path("secret"), FileTreeError::PermissionDenied)],
            unparsed: vec![],
            findings: vec![Finding {
                path: path(".claude/hooks/tool"),
                at: None,
                rule: RuleId::OpaqueHook,
                severity: Severity::Medium,
                evidence: Evidence::quote(&Line::new("not valid UTF-8"), 0, 80),
            }],
        }
    }

    fn repository(report: &DiscoveryReport) -> Scan<'_> {
        Scan {
            root: ".",
            scope: Scope::Repository,
            report,
        }
    }

    fn written(scans: &[Scan<'_>]) -> Value {
        serde_json::from_str(&document(scans).expect("serialises")).expect("parses")
    }

    #[test]
    fn a_report_is_written_whole() {
        let report = full();
        let json = written(&[repository(&report)]);

        assert_eq!(json["version"], 1);
        let scan = &json["scans"][0];
        assert_eq!(scan["scope"], "repository");
        assert_eq!(scan["complete"], false);
        assert_eq!(scan["surfaces"][0]["kind"], "claude-code");
        assert_eq!(scan["hooks"][0]["action"], "prompt");
        assert_eq!(scan["hooks"][0]["enabled"], false);
        assert_eq!(scan["permissions"][0]["unscoped"], true);
        assert_eq!(scan["servers"][0]["transport"]["type"], "local");
        assert_eq!(scan["servers"][0]["env"][0], "DATABASE_URL");
        assert_eq!(scan["findings"][0]["rule"], "opaque-hook");
        assert_eq!(scan["findings"][0]["severity"], "medium");
        assert!(scan["findings"][0]["line"].is_null(), "{scan}");
        assert_eq!(scan["unreadable"][0]["reason"], "permission denied");
    }

    #[test]
    fn a_complete_scan_says_so() {
        let report = DiscoveryReport::default();

        assert_eq!(
            written(&[repository(&report)])["scans"][0]["complete"],
            true
        );
    }

    #[test]
    fn each_scan_is_its_own_entry() {
        let (home, machine) = (DiscoveryReport::default(), full());
        let json = written(&[
            Scan {
                root: "/home/me",
                scope: Scope::Home,
                report: &home,
            },
            Scan {
                root: "/",
                scope: Scope::System,
                report: &machine,
            },
        ]);

        assert_eq!(json["scans"][0]["scope"], "home");
        assert_eq!(json["scans"][1]["scope"], "system");
        assert_eq!(json["scans"][1]["root"], "/");
    }

    #[test]
    fn the_document_reads_back_as_written() {
        let report = full();
        let scans = [repository(&report)];
        let text = document(&scans).expect("serialises");

        assert_eq!(
            serde_json::from_str::<Document>(&text).expect("parses"),
            Document::of(&scans)
        );
    }

    /// Bidirectional, tag-block and C1 control characters are escaped, and
    /// decode back to exactly what was found.
    #[test]
    fn a_hidden_or_control_character_is_escaped_not_written() {
        let found = "ok\u{202E}\u{E0041}\u{9B}";
        let mut report = full();
        report.hooks[0].hook.action = Action::Command(found.to_owned());

        let text = document(&[repository(&report)]).expect("serialises");

        for c in ['\u{202E}', '\u{E0041}', '\u{9B}'] {
            assert!(!text.contains(c), "U+{:04X} in {text}", c as u32);
        }
        let json: Value = serde_json::from_str(&text).expect("parses");
        assert_eq!(json["scans"][0]["hooks"][0]["text"], found);
    }

    #[test]
    fn a_credential_never_reaches_the_document() {
        let report = full();
        let text = document(&[repository(&report)]).expect("serialises");

        assert!(!text.contains("sk-live-SECRET"), "{text}");
    }
}
