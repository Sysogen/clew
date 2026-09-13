// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What clew discovers: a configuration surface belonging to an AI coding agent.

use crate::repo_path::RepoPath;

/// The tool a surface configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SurfaceKind {
    /// Model Context Protocol server definitions.
    McpServers,
    /// Claude Code settings or hooks.
    ClaudeCode,
    /// Codex configuration.
    Codex,
    /// Cursor configuration or rules.
    Cursor,
    /// Visual Studio Code agent configuration.
    VsCode,
    /// Gemini CLI configuration.
    Gemini,
    /// Kiro configuration, steering, or hooks.
    Kiro,
    /// Zed configuration, skills, or rules.
    Zed,
    /// Windsurf rules.
    Windsurf,
    /// A file holding environment values.
    EnvFile,
    /// Continue configuration.
    Continue,
    /// Cline configuration.
    Cline,
    /// Aider configuration.
    Aider,
    /// GitHub Copilot instructions.
    Copilot,
    /// Development container lifecycle configuration.
    DevContainer,
    /// A natural-language instruction file read by an agent.
    InstructionFile,
    /// A script an agent hook can invoke.
    HookScript,
    /// A skill definition an agent loads.
    Skill,
}

impl SurfaceKind {
    /// The kind a catalogue row names, if it names one that exists.
    #[must_use]
    pub fn from_catalogue(name: &str) -> Option<Self> {
        Some(match name {
            "mcp-servers" => Self::McpServers,
            "claude-code" => Self::ClaudeCode,
            "codex" => Self::Codex,
            "cursor" => Self::Cursor,
            "vscode" => Self::VsCode,
            "gemini" => Self::Gemini,
            "kiro" => Self::Kiro,
            "zed" => Self::Zed,
            "windsurf" => Self::Windsurf,
            "env" => Self::EnvFile,
            "continue" => Self::Continue,
            "cline" => Self::Cline,
            "aider" => Self::Aider,
            "copilot" => Self::Copilot,
            "devcontainer" => Self::DevContainer,
            "instruction" => Self::InstructionFile,
            "hook-script" => Self::HookScript,
            "skill" => Self::Skill,
            _ => return None,
        })
    }

    /// The name a catalogue row gives this kind, which a JSON report uses too.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::McpServers => "mcp-servers",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::VsCode => "vscode",
            Self::Gemini => "gemini",
            Self::Kiro => "kiro",
            Self::Zed => "zed",
            Self::Windsurf => "windsurf",
            Self::EnvFile => "env",
            Self::Continue => "continue",
            Self::Cline => "cline",
            Self::Aider => "aider",
            Self::Copilot => "copilot",
            Self::DevContainer => "devcontainer",
            Self::InstructionFile => "instruction",
            Self::HookScript => "hook-script",
            Self::Skill => "skill",
        }
    }

    /// Short human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::McpServers => "MCP servers",
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::VsCode => "VS Code",
            Self::Gemini => "Gemini CLI",
            Self::Kiro => "Kiro",
            Self::Zed => "Zed",
            Self::Windsurf => "Windsurf",
            Self::EnvFile => "Environment file",
            Self::Continue => "Continue",
            Self::Cline => "Cline",
            Self::Aider => "Aider",
            Self::Copilot => "Copilot",
            Self::DevContainer => "devcontainer",
            Self::InstructionFile => "instruction file",
            Self::HookScript => "hook script",
            Self::Skill => "skill",
        }
    }
}

/// One discovered surface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Surface {
    /// Where it was found, relative to the scan root.
    pub path: RepoPath,
    /// What it configures.
    pub kind: SurfaceKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report names a kind the way its catalogue row does, so the two must
    /// agree for every kind.
    #[test]
    fn every_kind_reads_back_from_its_name() {
        for kind in [
            SurfaceKind::McpServers,
            SurfaceKind::ClaudeCode,
            SurfaceKind::Codex,
            SurfaceKind::Cursor,
            SurfaceKind::VsCode,
            SurfaceKind::Gemini,
            SurfaceKind::Kiro,
            SurfaceKind::Zed,
            SurfaceKind::Windsurf,
            SurfaceKind::EnvFile,
            SurfaceKind::Continue,
            SurfaceKind::Cline,
            SurfaceKind::Aider,
            SurfaceKind::Copilot,
            SurfaceKind::DevContainer,
            SurfaceKind::InstructionFile,
            SurfaceKind::HookScript,
            SurfaceKind::Skill,
        ] {
            assert_eq!(SurfaceKind::from_catalogue(kind.as_str()), Some(kind));
        }
    }
}
