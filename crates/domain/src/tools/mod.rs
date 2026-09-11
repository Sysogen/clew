// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Per-tool knowledge: what each AI coding tool configures, and where.
mod claude_code;

pub use claude_code::ClaudeCode;

use thiserror::Error;

use crate::hook::Hook;
use crate::mcp_server::McpServer;
use crate::permission::Permission;
use crate::repo_path::RepoPath;

/// Why a configuration file could not be understood.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseError {
    /// The file is not valid JSON.
    #[error("not valid JSON")]
    NotJson,
}

/// One AI coding tool, and the surfaces it configures.
pub trait CodingTool: Sync {
    /// Stable identifier. Appears in output and in rule identifiers, so
    /// renaming one is a breaking change.
    fn name(&self) -> &'static str;

    /// Whether this tool parses `path`, so a caller knows not to read a file
    /// nothing will look at. A hook script is a surface, not a configuration.
    fn reads(&self, path: &RepoPath) -> bool {
        let _ = path;
        false
    }

    /// Hooks registered by `contents`, the text of `path`.
    ///
    /// A shape this tool does not recognise yields no hooks rather than an
    /// error: configuration files carry keys clew knows nothing about, and a
    /// scan must not stop at the first one.
    ///
    /// # Errors
    ///
    /// Only when the file cannot be parsed at all.
    fn hooks(&self, path: &RepoPath, contents: &str) -> Result<Vec<Hook>, ParseError> {
        let _ = (path, contents);
        Ok(Vec::new())
    }

    /// Operations `contents` pre-approves, so the agent performs them without
    /// asking.
    ///
    /// # Errors
    ///
    /// Only when the file cannot be parsed at all.
    fn permissions(&self, path: &RepoPath, contents: &str) -> Result<Vec<Permission>, ParseError> {
        let _ = (path, contents);
        Ok(Vec::new())
    }

    /// MCP servers `contents` declares.
    ///
    /// # Errors
    ///
    /// Only when the file cannot be parsed at all.
    fn mcp_servers(&self, path: &RepoPath, contents: &str) -> Result<Vec<McpServer>, ParseError> {
        let _ = (path, contents);
        Ok(Vec::new())
    }
}

/// Every tool this build knows about.
///
/// Ordered by nothing in particular: a path belongs to at most one tool, so a
/// caller may stop at the first match.
pub const REGISTRY: &[&dyn CodingTool] = &[&ClaudeCode];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_has_a_distinct_name() {
        let mut names: Vec<&str> = REGISTRY.iter().map(|t| t.name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "two tools share a name");
    }

    #[test]
    fn the_catalogue_never_names_a_tool_that_cannot_parse_its_surface() {
        let implemented: Vec<&str> = REGISTRY.iter().map(|t| t.name()).collect();
        for rule in crate::catalogue::shipped().rules() {
            if rule.kind == "settings" || rule.kind == "mcp-servers" {
                assert!(
                    implemented.contains(&rule.tool.as_str()) || rule.tool != "claude-code",
                    "{} names {}, which has no implementation",
                    rule.glob,
                    rule.tool
                );
            }
        }
    }
}
