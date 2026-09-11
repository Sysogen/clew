// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Turning a discovery report into text.

use std::fmt::Write as _;

use clew_application::DiscoveryReport;

/// Render a report as an aligned table.
///
/// Unreadable directories are always rendered. A scan that could not see
/// everything must not read as a clean result.
#[must_use]
pub fn report(report: &DiscoveryReport, root: &str) -> String {
    let mut out = String::new();

    if report.surfaces.is_empty() {
        let _ = writeln!(out, "No agent surfaces found under {root}.");
    } else {
        let width = report
            .surfaces
            .iter()
            .map(|s| s.path.as_str().len())
            .max()
            .unwrap_or(0);
        for surface in &report.surfaces {
            let _ = writeln!(
                out,
                "{:<width$}  {}",
                surface.path.as_str(),
                surface.kind.label()
            );
            for registered in report.hooks.iter().filter(|h| h.source == surface.path) {
                let _ = writeln!(
                    out,
                    "  runs on {}: {}",
                    registered.hook.event, registered.hook.command
                );
            }

            // Summarised, not listed: a settings file routinely pre-approves
            // dozens, and an unscoped grant is the one worth reading.
            let granted: Vec<_> = report
                .permissions
                .iter()
                .filter(|g| g.source == surface.path)
                .collect();
            if !granted.is_empty() {
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
                    let _ = writeln!(out, "    any use of {tool}");
                }
            }
        }
        let _ = writeln!(
            out,
            "\n{} agent surface(s), {} hook(s).",
            report.surfaces.len(),
            report.hooks.len()
        );
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
            let _ = writeln!(out, "    {}  ({error})", path.as_str());
        }
    }

    if !report.unparsed.is_empty() {
        let _ = writeln!(
            out,
            "  {} file(s) could not be read or understood:",
            report.unparsed.len()
        );
        for (path, reason) in &report.unparsed {
            let _ = writeln!(out, "    {}  ({reason})", path.as_str());
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use clew_application::{GrantedPermission, RegisteredHook};
    use clew_domain::ports::file_tree::FileTreeError;
    use clew_domain::{Hook, Permission};
    use clew_domain::{RepoPath, Surface, SurfaceKind};

    use super::*;

    fn surface(path: &str, kind: SurfaceKind) -> Surface {
        let path = path
            .split('/')
            .fold(RepoPath::root(), |acc, seg| acc.join(seg));
        Surface { path, kind }
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
            unreadable: vec![],
            unparsed: vec![],
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
            unreadable: vec![(
                RepoPath::root().join("secret"),
                FileTreeError::PermissionDenied,
            )],
            unparsed: vec![],
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
            unreadable: vec![],
            unparsed: vec![],
        };

        assert!(!report(&found, ".").contains("incomplete"));
    }

    #[test]
    fn the_directory_count_is_pluralised() {
        let one = DiscoveryReport {
            surfaces: vec![],
            hooks: vec![],
            permissions: vec![],
            unreadable: vec![(RepoPath::root().join("a"), FileTreeError::NotFound)],
            unparsed: vec![],
        };
        assert!(report(&one, ".").contains("1 directory could not be read"));

        let two = DiscoveryReport {
            surfaces: vec![],
            hooks: vec![],
            permissions: vec![],
            unreadable: vec![
                (RepoPath::root().join("a"), FileTreeError::NotFound),
                (RepoPath::root().join("b"), FileTreeError::NotFound),
            ],
            unparsed: vec![],
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
                    command: "curl x | sh".to_owned(),
                    kind: Some("command".to_owned()),
                },
            }],
            permissions: vec![],
            unreadable: vec![],
            unparsed: vec![],
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
            unreadable: vec![],
            unparsed: vec![(
                RepoPath::root().join(".claude").join("settings.json"),
                "not valid JSON".to_owned(),
            )],
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
            unreadable: vec![],
            unparsed: vec![],
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
}
