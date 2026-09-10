// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! How far a scan descends and what it refuses to enter.

use crate::ports::file_tree::{DirEntry, EntryKind};
use crate::repo_path::RepoPath;

/// Directories skipped by default because they hold dependencies or build
/// output rather than a project's own configuration.
pub const DEFAULT_PRUNED: &[&str] = &[".git", "node_modules", "target", "vendor", "dist", ".venv"];

/// The default recursion limit when the operator sets none.
pub const DEFAULT_MAX_DEPTH: usize = 12;

/// The bounds of a single scan.
#[derive(Debug, Clone)]
pub struct ScanPolicy {
    max_depth: usize,
    pruned: Vec<String>,
}

impl ScanPolicy {
    /// A policy with an explicit depth limit and pruning set.
    #[must_use]
    pub fn new(max_depth: usize, pruned: Vec<String>) -> Self {
        Self { max_depth, pruned }
    }

    /// A policy with the given depth limit and [`DEFAULT_PRUNED`].
    #[must_use]
    pub fn with_default_pruning(max_depth: usize) -> Self {
        Self::new(
            max_depth,
            DEFAULT_PRUNED.iter().map(|s| (*s).to_owned()).collect(),
        )
    }

    /// The recursion limit.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Whether the scan should descend into `entry`.
    ///
    /// Symbolic links are never followed: a link can point outside the scan
    /// root, and a cycle of links would not terminate.
    #[must_use]
    pub fn should_descend(&self, entry: &DirEntry) -> bool {
        entry.kind == EntryKind::Directory
            && entry.path.depth() < self.max_depth
            && !self.is_pruned(&entry.path)
    }

    fn is_pruned(&self, path: &RepoPath) -> bool {
        self.pruned.iter().any(|p| p == path.file_name())
    }
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self::with_default_pruning(DEFAULT_MAX_DEPTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, kind: EntryKind) -> DirEntry {
        let path = path
            .split('/')
            .fold(RepoPath::root(), |acc, seg| acc.join(seg));
        DirEntry { path, kind }
    }

    #[test]
    fn descends_into_an_ordinary_directory() {
        let policy = ScanPolicy::default();
        assert!(policy.should_descend(&entry("src", EntryKind::Directory)));
    }

    #[test]
    fn never_descends_into_a_symlink() {
        let policy = ScanPolicy::default();
        assert!(!policy.should_descend(&entry("linked", EntryKind::Symlink)));
    }

    #[test]
    fn never_descends_into_a_file() {
        let policy = ScanPolicy::default();
        assert!(!policy.should_descend(&entry("README.md", EntryKind::File)));
    }

    #[test]
    fn prunes_by_final_segment_only() {
        let policy = ScanPolicy::default();
        assert!(!policy.should_descend(&entry("node_modules", EntryKind::Directory)));
        assert!(!policy.should_descend(&entry("a/b/node_modules", EntryKind::Directory)));
        assert!(policy.should_descend(&entry("node_modules_helper", EntryKind::Directory)));
    }

    #[test]
    fn stops_at_the_depth_limit() {
        let policy = ScanPolicy::new(2, vec![]);
        assert!(policy.should_descend(&entry("a", EntryKind::Directory)));
        assert!(!policy.should_descend(&entry("a/b", EntryKind::Directory)));
        assert!(!policy.should_descend(&entry("a/b/c", EntryKind::Directory)));
    }

    #[test]
    fn a_zero_depth_limit_descends_into_nothing() {
        let policy = ScanPolicy::new(0, vec![]);
        assert!(!policy.should_descend(&entry("a", EntryKind::Directory)));
    }
}
