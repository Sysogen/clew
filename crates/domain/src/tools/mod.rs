// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Per-tool knowledge: what each AI coding tool configures, and where.
mod claude_code;

pub use claude_code::ClaudeCode;

use crate::repo_path::RepoPath;
use crate::surface::SurfaceKind;

/// One AI coding tool, and the surfaces it configures.
pub trait CodingTool: Sync {
    /// Stable identifier. Appears in output and in rule identifiers, so
    /// renaming one is a breaking change.
    fn name(&self) -> &'static str;

    /// Classify a repository-relative path, if this tool owns it.
    fn classify(&self, path: &RepoPath) -> Option<SurfaceKind>;
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
    fn no_two_tools_claim_the_same_path() {
        let path = RepoPath::root().join(".claude").join("settings.json");
        let claimants: Vec<&str> = REGISTRY
            .iter()
            .filter(|t| t.classify(&path).is_some())
            .map(|t| t.name())
            .collect();
        assert!(claimants.len() <= 1, "path claimed by {claimants:?}");
    }
}
