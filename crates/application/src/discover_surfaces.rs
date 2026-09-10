// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Walk a repository and report the agent surfaces it configures.

use clew_domain::ports::file_tree::{FileTree, FileTreeError};
use clew_domain::{RepoPath, ScanPolicy, Surface, classify};

/// What a scan found, and where it could not look.
///
/// Unreadable directories are reported rather than swallowed. A scan that
/// silently skipped half a tree would read as a clean result, which is the
/// worst outcome this tool can produce.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiscoveryReport {
    /// Surfaces found, in path order.
    pub surfaces: Vec<Surface>,
    /// Directories that could not be listed, with the reason.
    pub unreadable: Vec<(RepoPath, FileTreeError)>,
}

impl DiscoveryReport {
    /// Whether every directory in scope was successfully listed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unreadable.is_empty()
    }
}

/// Discovers agent surfaces beneath a scan root.
pub struct DiscoverSurfaces<'a, T: FileTree> {
    tree: &'a T,
    policy: &'a ScanPolicy,
}

impl<'a, T: FileTree> DiscoverSurfaces<'a, T> {
    /// Bind the use case to a file tree and a policy.
    pub fn new(tree: &'a T, policy: &'a ScanPolicy) -> Self {
        Self { tree, policy }
    }

    /// Run the scan.
    #[must_use]
    pub fn run(&self) -> DiscoveryReport {
        let mut report = DiscoveryReport::default();
        let mut queue = vec![RepoPath::root()];

        while let Some(dir) = queue.pop() {
            let entries = match self.tree.read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) => {
                    report.unreadable.push((dir, error));
                    continue;
                }
            };

            for entry in entries {
                if self.policy.should_descend(&entry) {
                    queue.push(entry.path);
                    continue;
                }
                if let Some(kind) = classify(&entry.path) {
                    report.surfaces.push(Surface {
                        path: entry.path,
                        kind,
                    });
                }
            }
        }

        report.surfaces.sort();
        report.unreadable.sort_by(|a, b| a.0.cmp(&b.0));
        report
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use clew_domain::SurfaceKind;
    use clew_domain::ports::file_tree::{DirEntry, EntryKind};

    use super::*;

    /// An in-memory tree. The whole point of the port is that this exists.
    #[derive(Default)]
    struct FakeTree {
        dirs: BTreeMap<String, Vec<DirEntry>>,
        denied: Vec<String>,
    }

    impl FakeTree {
        fn dir(mut self, at: &str, entries: &[(&str, EntryKind)]) -> Self {
            let base = path(at);
            let listing = entries
                .iter()
                .map(|(name, kind)| DirEntry {
                    path: base.join(name),
                    kind: *kind,
                })
                .collect();
            self.dirs.insert(at.to_owned(), listing);
            self
        }

        fn deny(mut self, at: &str) -> Self {
            self.denied.push(at.to_owned());
            self
        }
    }

    impl FileTree for FakeTree {
        fn read_dir(&self, path: &RepoPath) -> Result<Vec<DirEntry>, FileTreeError> {
            let key = path.as_str().to_owned();
            if self.denied.contains(&key) {
                return Err(FileTreeError::PermissionDenied);
            }
            self.dirs.get(&key).cloned().ok_or(FileTreeError::NotFound)
        }
    }

    fn path(s: &str) -> RepoPath {
        if s.is_empty() {
            return RepoPath::root();
        }
        s.split('/')
            .fold(RepoPath::root(), |acc, seg| acc.join(seg))
    }

    #[test]
    fn finds_a_surface_at_the_root() {
        let tree = FakeTree::default().dir("", &[("CLAUDE.md", EntryKind::File)]);
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &policy).run();

        assert!(report.is_complete());
        assert_eq!(report.surfaces.len(), 1);
        assert_eq!(report.surfaces[0].kind, SurfaceKind::InstructionFile);
    }

    #[test]
    fn finds_a_surface_nested_in_a_directory() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("settings.json", EntryKind::File)]);
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &policy).run();

        assert_eq!(report.surfaces.len(), 1);
        assert_eq!(report.surfaces[0].path.as_str(), ".claude/settings.json");
        assert_eq!(report.surfaces[0].kind, SurfaceKind::ClaudeCode);
    }

    #[test]
    fn does_not_descend_into_a_pruned_directory() {
        let tree = FakeTree::default()
            .dir("", &[("node_modules", EntryKind::Directory)])
            .dir("node_modules", &[("CLAUDE.md", EntryKind::File)]);
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &policy).run();

        assert!(report.surfaces.is_empty());
    }

    #[test]
    fn does_not_follow_a_symlink() {
        let tree = FakeTree::default()
            .dir("", &[("escape", EntryKind::Symlink)])
            .dir("escape", &[("CLAUDE.md", EntryKind::File)]);
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &policy).run();

        assert!(report.surfaces.is_empty());
        assert!(report.is_complete());
    }

    #[test]
    fn an_unreadable_directory_is_reported_not_swallowed() {
        let tree = FakeTree::default()
            .dir("", &[("secret", EntryKind::Directory)])
            .deny("secret");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &policy).run();

        assert!(!report.is_complete());
        assert_eq!(report.unreadable.len(), 1);
        assert_eq!(report.unreadable[0].0.as_str(), "secret");
        assert_eq!(report.unreadable[0].1, FileTreeError::PermissionDenied);
    }

    #[test]
    fn a_scan_continues_past_an_unreadable_directory() {
        let tree = FakeTree::default()
            .dir(
                "",
                &[
                    ("secret", EntryKind::Directory),
                    ("CLAUDE.md", EntryKind::File),
                ],
            )
            .deny("secret");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &policy).run();

        assert_eq!(report.surfaces.len(), 1);
        assert_eq!(report.unreadable.len(), 1);
    }

    #[test]
    fn results_are_ordered_by_path_regardless_of_traversal_order() {
        let tree = FakeTree::default()
            .dir(
                "",
                &[
                    ("z", EntryKind::Directory),
                    ("a", EntryKind::Directory),
                    ("CLAUDE.md", EntryKind::File),
                ],
            )
            .dir("z", &[("AGENTS.md", EntryKind::File)])
            .dir("a", &[("AGENTS.md", EntryKind::File)]);
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &policy).run();

        let paths: Vec<&str> = report.surfaces.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, vec!["CLAUDE.md", "a/AGENTS.md", "z/AGENTS.md"]);
    }
}
