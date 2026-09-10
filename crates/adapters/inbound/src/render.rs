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
        }
        let _ = writeln!(out, "\n{} agent surface(s).", report.surfaces.len());
    }

    if !report.is_complete() {
        let plural = if report.unreadable.len() == 1 {
            "y"
        } else {
            "ies"
        };
        let _ = writeln!(
            out,
            "\n{} director{plural} could not be read; this scan is incomplete:",
            report.unreadable.len()
        );
        for (path, error) in &report.unreadable {
            let _ = writeln!(out, "  {}  ({error})", path.as_str());
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use clew_domain::ports::file_tree::FileTreeError;
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
            unreadable: vec![],
        };

        let out = report(&found, ".");

        assert!(out.contains("CLAUDE.md"));
        assert!(out.contains("instruction file"));
        assert!(out.contains(".claude/settings.json"));
        assert!(out.contains("Claude Code"));
        assert!(out.contains("2 agent surface(s)."));
    }

    #[test]
    fn an_incomplete_scan_is_never_rendered_as_clean() {
        let found = DiscoveryReport {
            surfaces: vec![surface("CLAUDE.md", SurfaceKind::InstructionFile)],
            unreadable: vec![(
                RepoPath::root().join("secret"),
                FileTreeError::PermissionDenied,
            )],
        };

        let out = report(&found, ".");

        assert!(out.contains("this scan is incomplete"));
        assert!(out.contains("secret"));
        assert!(out.contains("permission denied"));
    }

    #[test]
    fn the_incomplete_notice_is_absent_when_the_scan_was_complete() {
        let found = DiscoveryReport {
            surfaces: vec![surface("CLAUDE.md", SurfaceKind::InstructionFile)],
            unreadable: vec![],
        };

        assert!(!report(&found, ".").contains("incomplete"));
    }

    #[test]
    fn the_directory_count_is_pluralised() {
        let one = DiscoveryReport {
            surfaces: vec![],
            unreadable: vec![(RepoPath::root().join("a"), FileTreeError::NotFound)],
        };
        assert!(report(&one, ".").contains("1 directory could not be read"));

        let two = DiscoveryReport {
            surfaces: vec![],
            unreadable: vec![
                (RepoPath::root().join("a"), FileTreeError::NotFound),
                (RepoPath::root().join("b"), FileTreeError::NotFound),
            ],
        };
        assert!(report(&two, ".").contains("2 directories could not be read"));
    }
}
