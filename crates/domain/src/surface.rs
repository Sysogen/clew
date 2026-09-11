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

    /// Short human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::McpServers => "MCP servers",
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::VsCode => "VS Code",
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
