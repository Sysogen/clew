// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning discovery reports into one JSON document.
//!
//! Tools read it, so it is a contract: [`VERSION`] is raised when a field
//! changes meaning or goes away. A control or default-ignorable character in
//! any string is written as a `\u` escape, so the document decodes to exactly
//! what was found without carrying the character itself.

use std::io;

use crate::explain::PackOut;
use clew_application::{DeclaredAutonomy, DeclaredServer, DeclaredTask, DiscoveryReport};
use clew_domain::catalogue;
use clew_domain::finding::Finding;
use clew_domain::hook::Action;
use clew_domain::mcp_server::Transport;
use clew_domain::rules::is_default_ignorable;
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
    escaped(&Document::of(scans))
}

/// A value as compact JSON, escaped as this module describes.
pub(crate) fn escaped<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut out = Vec::new();
    value.serialize(&mut Serializer::with_formatter(&mut out, Escaping))?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Compact JSON, with every control or default-ignorable character escaped.
/// Variation selectors too: harmless after an emoji, a run of them can carry
/// bytes.
struct Escaping;

impl Formatter for Escaping {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut start = 0;
        for (at, c) in fragment.char_indices() {
            if c.is_control() || is_default_ignorable(c) {
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
    packs: Vec<PackOut>,
    catalogue: u32,
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
    autonomy: Vec<AutonomyOut>,
    tasks: Vec<TaskOut>,
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
struct TaskOut {
    source: String,
    label: String,
    command: Option<String>,
    depends_on: Vec<String>,
    runs_on: Option<String>,
    on_open: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct AutonomyOut {
    source: String,
    key: String,
    value: String,
    unchecked: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
struct ServerOut {
    source: String,
    name: String,
    transport: TransportOut,
    env: Vec<String>,
    trusted: bool,
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

impl ServerOut {
    fn of(declared: &DeclaredServer) -> Self {
        Self {
            source: declared.source.as_str().to_owned(),
            name: declared.server.name.clone(),
            transport: match &declared.server.transport {
                Transport::Local { command, args } => TransportOut::Local {
                    command: command.clone(),
                    args: args.clone(),
                },
                Transport::Remote { url } => TransportOut::Remote { url: url.clone() },
            },
            env: declared.server.env.clone(),
            trusted: declared.server.trusted,
        }
    }
}

impl AutonomyOut {
    fn of(declared: &DeclaredAutonomy) -> Self {
        Self {
            source: declared.source.as_str().to_owned(),
            key: declared.autonomy.key.clone(),
            value: declared.autonomy.value.clone(),
            unchecked: declared.autonomy.is_unchecked(),
        }
    }
}

impl TaskOut {
    fn of(declared: &DeclaredTask) -> Self {
        Self {
            source: declared.source.as_str().to_owned(),
            label: declared.task.label.clone(),
            command: declared.task.command.clone(),
            depends_on: declared.task.depends_on.clone(),
            runs_on: declared.task.runs_on.clone(),
            on_open: declared.task.runs_on_open(),
        }
    }
}

impl FindingOut {
    fn of(finding: &Finding) -> Self {
        Self {
            path: finding.path.as_str().to_owned(),
            line: finding.at.map(|p| p.line),
            column: finding.at.map(|p| p.column),
            rule: finding.rule.as_str().to_owned(),
            severity: finding.severity.as_str().to_owned(),
            evidence: finding.evidence.as_str().to_owned(),
        }
    }
}

impl Document {
    fn of(scans: &[Scan<'_>]) -> Self {
        Self {
            version: VERSION,
            packs: PackOut::shipped(),
            catalogue: catalogue().revision(),
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
            servers: report.servers.iter().map(ServerOut::of).collect(),
            autonomy: report.autonomy.iter().map(AutonomyOut::of).collect(),
            tasks: report.tasks.iter().map(TaskOut::of).collect(),
            findings: report.findings.iter().map(FindingOut::of).collect(),
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
    use clew_application::{DeclaredAutonomy, DeclaredTask};
    use clew_domain::Autonomy;
    use clew_domain::Task;

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
                source: settings.clone(),
                permission: Permission::parse("WebSearch").expect("valid entry"),
            }],
            servers: vec![DeclaredServer {
                source: path(".mcp.json"),
                server: McpServer {
                    name: "pg".to_owned(),
                    transport: Transport::local("npx".to_owned(), &args),
                    env: vec!["DATABASE_URL".to_owned()],
                    trusted: true,
                },
            }],
            autonomy: vec![DeclaredAutonomy {
                source: settings.clone(),
                autonomy: Autonomy {
                    key: "permissions.defaultMode".to_owned(),
                    value: "bypassPermissions".to_owned(),
                },
            }],
            tasks: vec![DeclaredTask {
                source: path(".vscode/tasks.json"),
                task: Task::new(
                    Some("setup"),
                    Some("npm ci --token sk-live-SECRET"),
                    &[],
                    Some("folderOpen".to_owned()),
                ),
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
        assert_eq!(json["packs"][0]["name"], "core");
        assert_eq!(json["packs"][0]["version"], clew_domain::pack::CORE.version);
        assert_eq!(json["catalogue"], catalogue().revision());
        let scan = &json["scans"][0];
        assert_eq!(scan["scope"], "repository");
        assert_eq!(scan["complete"], false);
        assert_eq!(scan["surfaces"][0]["kind"], "claude-code");
        assert_eq!(scan["hooks"][0]["action"], "prompt");
        assert_eq!(scan["hooks"][0]["enabled"], false);
        assert_eq!(scan["permissions"][0]["unscoped"], true);
        assert_eq!(scan["servers"][0]["trusted"], true);
        assert_eq!(scan["autonomy"][0]["key"], "permissions.defaultMode");
        assert_eq!(scan["autonomy"][0]["value"], "bypassPermissions");
        assert_eq!(scan["autonomy"][0]["unchecked"], true);
        assert_eq!(scan["autonomy"][0]["source"], ".claude/settings.json");
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

    /// Bidirectional, tag-block, variation-selector and C1 control characters
    /// are escaped, and decode back to exactly what was found.
    #[test]
    fn a_hidden_or_control_character_is_escaped_not_written() {
        let found = "ok\u{202E}\u{E0041}\u{FE0F}\u{E0100}\u{9B}";
        let mut report = full();
        report.hooks[0].hook.action = Action::Command(found.to_owned());

        let text = document(&[repository(&report)]).expect("serialises");

        for c in ['\u{202E}', '\u{E0041}', '\u{FE0F}', '\u{E0100}', '\u{9B}'] {
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
