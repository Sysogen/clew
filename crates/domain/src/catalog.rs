// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Classification of a path as an agent surface.

use crate::repo_path::RepoPath;
use crate::surface::SurfaceKind;
use crate::tools::REGISTRY;

/// Surfaces not yet owned by a tool module in [`crate::tools`].
///
/// Each entry moves out of this list as its tool gains a module. When the list
/// is empty this constant and the fallback below go with it.
const UNMIGRATED: &[(&str, SurfaceKind)] = &[
    (".codex/config.toml", SurfaceKind::Codex),
    (".cursor/mcp.json", SurfaceKind::Cursor),
    (".cursorrules", SurfaceKind::Cursor),
    (".vscode/mcp.json", SurfaceKind::VsCode),
    (".continue/config.json", SurfaceKind::Continue),
    ("cline_mcp_settings.json", SurfaceKind::Cline),
    (".aider.conf.yml", SurfaceKind::Aider),
    (".github/copilot-instructions.md", SurfaceKind::Copilot),
    (".devcontainer/devcontainer.json", SurfaceKind::DevContainer),
    ("AGENTS.md", SurfaceKind::InstructionFile),
];

/// Classify a repository-relative path, if it is a recognised surface.
///
/// Matching is on the full path suffix at a segment boundary, never on the bare
/// file name, so an unrelated `settings.json` is not reported as Claude Code
/// configuration.
#[must_use]
pub fn classify(path: &RepoPath) -> Option<SurfaceKind> {
    REGISTRY
        .iter()
        .find_map(|tool| tool.classify(path))
        .or_else(|| {
            UNMIGRATED
                .iter()
                .find(|(suffix, _)| path.ends_with_segments(suffix))
                .map(|(_, kind)| *kind)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RepoPath {
        s.split('/')
            .fold(RepoPath::root(), |acc, seg| acc.join(seg))
    }

    #[test]
    fn classifies_a_directory_scoped_surface_at_any_depth() {
        assert_eq!(
            classify(&p(".claude/settings.json")),
            Some(SurfaceKind::ClaudeCode)
        );
        assert_eq!(
            classify(&p("packages/api/.claude/settings.json")),
            Some(SurfaceKind::ClaudeCode)
        );
    }

    #[test]
    fn a_bare_file_name_does_not_match_a_directory_scoped_surface() {
        assert_eq!(classify(&p("settings.json")), None);
        assert_eq!(classify(&p("config/settings.json")), None);
        assert_eq!(classify(&p("config/mcp.json")), None);
    }

    #[test]
    fn a_partial_segment_does_not_match() {
        assert_eq!(classify(&p("notclaude/settings.json")), None);
        assert_eq!(classify(&p("MYCLAUDE.md")), None);
    }

    #[test]
    fn root_level_instruction_files_are_recognised() {
        assert_eq!(
            classify(&p("CLAUDE.md")),
            Some(SurfaceKind::InstructionFile)
        );
        assert_eq!(
            classify(&p("AGENTS.md")),
            Some(SurfaceKind::InstructionFile)
        );
    }

    #[test]
    fn unrelated_files_are_not_surfaces() {
        assert_eq!(classify(&p("src/main.rs")), None);
        assert_eq!(classify(&p("README.md")), None);
        assert_eq!(classify(&p("Cargo.toml")), None);
    }
}
