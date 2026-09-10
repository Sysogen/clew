// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Claude Code.

use super::CodingTool;
use crate::repo_path::RepoPath;
use crate::surface::SurfaceKind;

/// The surfaces Claude Code reads, as the path suffix that identifies each.
const SURFACES: &[(&str, SurfaceKind)] = &[
    (".claude/settings.json", SurfaceKind::ClaudeCode),
    (".claude/settings.local.json", SurfaceKind::ClaudeCode),
    (".mcp.json", SurfaceKind::McpServers),
    ("CLAUDE.md", SurfaceKind::InstructionFile),
];

/// Claude Code: `.claude/`, the project MCP file, and `CLAUDE.md`.
pub struct ClaudeCode;

impl CodingTool for ClaudeCode {
    fn name(&self) -> &'static str {
        "claude-code"
    }

    fn classify(&self, path: &RepoPath) -> Option<SurfaceKind> {
        SURFACES
            .iter()
            .find(|(suffix, _)| path.ends_with_segments(suffix))
            .map(|(_, kind)| *kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RepoPath {
        s.split('/')
            .fold(RepoPath::root(), |acc, seg| acc.join(seg))
    }

    #[test]
    fn owns_its_settings_files_at_any_depth() {
        assert_eq!(
            ClaudeCode.classify(&p(".claude/settings.json")),
            Some(SurfaceKind::ClaudeCode)
        );
        assert_eq!(
            ClaudeCode.classify(&p("packages/api/.claude/settings.local.json")),
            Some(SurfaceKind::ClaudeCode)
        );
    }

    #[test]
    fn owns_the_project_mcp_file_and_the_instruction_file() {
        assert_eq!(
            ClaudeCode.classify(&p(".mcp.json")),
            Some(SurfaceKind::McpServers)
        );
        assert_eq!(
            ClaudeCode.classify(&p("CLAUDE.md")),
            Some(SurfaceKind::InstructionFile)
        );
    }

    #[test]
    fn a_bare_file_name_does_not_match_a_directory_scoped_surface() {
        assert_eq!(ClaudeCode.classify(&p("settings.json")), None);
        assert_eq!(ClaudeCode.classify(&p("config/settings.json")), None);
    }

    #[test]
    fn does_not_claim_another_tool_s_files() {
        assert_eq!(ClaudeCode.classify(&p(".codex/config.toml")), None);
        assert_eq!(ClaudeCode.classify(&p("AGENTS.md")), None);
        assert_eq!(ClaudeCode.classify(&p(".cursor/mcp.json")), None);
    }
}
