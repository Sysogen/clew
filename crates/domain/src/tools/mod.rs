// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Per-tool knowledge: what each AI coding tool configures, and where.
mod claude_code;

pub use claude_code::ClaudeCode;

use thiserror::Error;

use crate::hook::Hook;
use crate::repo_path::RepoPath;
use crate::surface::SurfaceKind;

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

    /// Classify a repository-relative path, if this tool owns it.
    fn classify(&self, path: &RepoPath) -> Option<SurfaceKind>;

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
    fn no_two_tools_claim_the_claude_settings_path() {
        let path = RepoPath::root().join(".claude").join("settings.json");
        let claimants: Vec<&str> = REGISTRY
            .iter()
            .filter(|t| t.classify(&path).is_some())
            .map(|t| t.name())
            .collect();
        assert!(claimants.len() <= 1, "path claimed by {claimants:?}");
    }
}
