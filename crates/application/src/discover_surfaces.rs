// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Walk a repository and report the agent surfaces it configures.

use clew_domain::ports::file_contents::FileContents;
use clew_domain::ports::file_tree::{FileTree, FileTreeError};
use clew_domain::tools::REGISTRY;
use clew_domain::{Hook, Permission, RepoPath, ScanPolicy, Surface, classify};

/// A pre-approved operation, and the file that granted it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrantedPermission {
    /// The configuration file it was read from.
    pub source: RepoPath,
    /// The permission itself.
    pub permission: Permission,
}

/// A hook, and the file that registered it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegisteredHook {
    /// The configuration file it was read from.
    pub source: RepoPath,
    /// The hook itself.
    pub hook: Hook,
}

/// What a scan found, and where it could not look.
///
/// Unreadable directories are reported rather than swallowed. A scan that
/// silently skipped half a tree would read as a clean result, which is the
/// worst outcome this tool can produce.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiscoveryReport {
    /// Surfaces found, in path order.
    pub surfaces: Vec<Surface>,
    /// Hooks the surfaces register, in path order.
    pub hooks: Vec<RegisteredHook>,
    /// Operations the surfaces pre-approve, in path order.
    pub permissions: Vec<GrantedPermission>,
    /// Directories that could not be listed, with the reason.
    pub unreadable: Vec<(RepoPath, FileTreeError)>,
    /// Surfaces that could not be read or understood, with the reason.
    pub unparsed: Vec<(RepoPath, String)>,
}

impl DiscoveryReport {
    /// Whether everything in scope was read and understood.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unreadable.is_empty() && self.unparsed.is_empty()
    }
}

/// Discovers agent surfaces beneath a scan root.
pub struct DiscoverSurfaces<'a, T: FileTree, C: FileContents> {
    tree: &'a T,
    contents: &'a C,
    policy: &'a ScanPolicy,
}

impl<'a, T: FileTree, C: FileContents> DiscoverSurfaces<'a, T, C> {
    /// Bind the use case to its ports and a policy.
    pub fn new(tree: &'a T, contents: &'a C, policy: &'a ScanPolicy) -> Self {
        Self {
            tree,
            contents,
            policy,
        }
    }

    /// Read every surface and collect the hooks it registers.
    fn collect_hooks(&self, report: &mut DiscoveryReport) {
        let paths: Vec<RepoPath> = report.surfaces.iter().map(|s| s.path.clone()).collect();
        for path in paths {
            // One tool owns a path, so ask that one. Asking all of them would
            // duplicate any failure once a second tool exists.
            let Some(tool) = REGISTRY.iter().find(|t| t.classify(&path).is_some()) else {
                continue;
            };
            if !tool.reads(&path) {
                continue;
            }

            let text = match self.contents.read(&path, self.policy.max_file_bytes()) {
                Ok(text) => text,
                Err(error) => {
                    report.unparsed.push((path, error.to_string()));
                    continue;
                }
            };
            match tool.hooks(&path, &text) {
                Ok(hooks) => {
                    for hook in hooks {
                        report.hooks.push(RegisteredHook {
                            source: path.clone(),
                            hook,
                        });
                    }
                }
                Err(error) => {
                    report.unparsed.push((path, error.to_string()));
                    continue;
                }
            }

            match tool.permissions(&path, &text) {
                Ok(permissions) => {
                    for permission in permissions {
                        report.permissions.push(GrantedPermission {
                            source: path.clone(),
                            permission,
                        });
                    }
                }
                Err(error) => report.unparsed.push((path, error.to_string())),
            }
        }
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
        self.collect_hooks(&mut report);
        report.hooks.sort();
        report.permissions.sort();
        report.unreadable.sort_by(|a, b| a.0.cmp(&b.0));
        report.unparsed.sort_by(|a, b| a.0.cmp(&b.0));
        report
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use clew_domain::SurfaceKind;
    use clew_domain::ports::file_contents::{FileContents, FileContentsError};
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

    /// In-memory file contents. An absent path reads as an empty JSON object,
    /// not an empty string, so a traversal-only test does not silently produce
    /// a parse failure for a settings surface it never populated.
    #[derive(Default)]
    struct FakeContents {
        files: BTreeMap<String, String>,
        denied: Vec<String>,
    }

    impl FakeContents {
        fn file(mut self, at: &str, body: &str) -> Self {
            self.files.insert(at.to_owned(), body.to_owned());
            self
        }

        fn deny(mut self, at: &str) -> Self {
            self.denied.push(at.to_owned());
            self
        }
    }

    impl FileContents for FakeContents {
        fn read(&self, path: &RepoPath, _max: u64) -> Result<String, FileContentsError> {
            let key = path.as_str().to_owned();
            if self.denied.contains(&key) {
                return Err(FileContentsError::PermissionDenied);
            }
            Ok(self
                .files
                .get(&key)
                .cloned()
                .unwrap_or_else(|| "{}".to_owned()))
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

        let report = DiscoverSurfaces::new(&tree, &FakeContents::default(), &policy).run();

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

        let report = DiscoverSurfaces::new(&tree, &FakeContents::default(), &policy).run();

        assert_eq!(report.surfaces.len(), 1);
        assert_eq!(report.surfaces[0].path.as_str(), ".claude/settings.json");
        assert_eq!(report.surfaces[0].kind, SurfaceKind::ClaudeCode);
        assert!(report.is_complete(), "{report:?}");
    }

    #[test]
    fn does_not_descend_into_a_pruned_directory() {
        let tree = FakeTree::default()
            .dir("", &[("node_modules", EntryKind::Directory)])
            .dir("node_modules", &[("CLAUDE.md", EntryKind::File)]);
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &FakeContents::default(), &policy).run();

        assert!(report.surfaces.is_empty());
    }

    #[test]
    fn does_not_follow_a_symlink() {
        let tree = FakeTree::default()
            .dir("", &[("escape", EntryKind::Symlink)])
            .dir("escape", &[("CLAUDE.md", EntryKind::File)]);
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &FakeContents::default(), &policy).run();

        assert!(report.surfaces.is_empty());
        assert!(report.is_complete());
    }

    #[test]
    fn an_unreadable_directory_is_reported_not_swallowed() {
        let tree = FakeTree::default()
            .dir("", &[("secret", EntryKind::Directory)])
            .deny("secret");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &FakeContents::default(), &policy).run();

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

        let report = DiscoverSurfaces::new(&tree, &FakeContents::default(), &policy).run();

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

        let report = DiscoverSurfaces::new(&tree, &FakeContents::default(), &policy).run();

        let paths: Vec<&str> = report.surfaces.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, vec!["CLAUDE.md", "a/AGENTS.md", "z/AGENTS.md"]);
    }

    #[test]
    fn reports_the_hooks_a_settings_file_registers() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".claude/settings.json",
            r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"x.sh"}]}]}}"#,
        );
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.hooks.len(), 1, "{report:?}");
        assert_eq!(report.hooks[0].source.as_str(), ".claude/settings.json");
        assert_eq!(report.hooks[0].hook.event, "SessionStart");
        assert_eq!(report.hooks[0].hook.command, "x.sh");
        assert!(report.is_complete());
    }

    #[test]
    fn a_surface_with_no_hooks_yields_none() {
        let tree = FakeTree::default().dir("", &[("CLAUDE.md", EntryKind::File)]);
        let contents = FakeContents::default().file("CLAUDE.md", "# instructions");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.surfaces.len(), 1);
        assert!(report.hooks.is_empty());
        assert!(report.is_complete());
    }

    #[test]
    fn an_unreadable_surface_is_reported_not_swallowed() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().deny(".claude/settings.json");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.surfaces.len(), 1, "the surface is still found");
        assert_eq!(report.unparsed.len(), 1);
        assert!(
            !report.is_complete(),
            "a scan that could not read must say so"
        );
    }

    #[test]
    fn malformed_settings_are_reported_not_swallowed() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().file(".claude/settings.json", "{not json");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.unparsed.len(), 1);
        assert!(!report.is_complete());
    }

    #[test]
    fn a_surface_no_tool_reads_is_never_opened() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("hooks", EntryKind::Directory)])
            .dir(".claude/hooks", &[("compiled", EntryKind::File)]);
        // Denied on read, so any attempt to open it shows up as unparsed.
        let contents = FakeContents::default().deny(".claude/hooks/compiled");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.surfaces.len(), 1, "the hook script is still found");
        assert!(
            report.unparsed.is_empty(),
            "a hook script must not be opened: {report:?}"
        );
        assert!(report.is_complete());
    }

    #[test]
    fn a_skill_is_found_without_being_read() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("skills", EntryKind::Directory)])
            .dir(".claude/skills", &[("prose", EntryKind::Directory)])
            .dir(".claude/skills/prose", &[("SKILL.md", EntryKind::File)]);
        let contents = FakeContents::default().deny(".claude/skills/prose/SKILL.md");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.surfaces.len(), 1);
        assert!(report.unparsed.is_empty());
        assert!(report.is_complete());
    }

    #[test]
    fn permissions_are_attributed_to_their_file() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".claude/settings.json",
            r#"{"permissions":{"allow":["Bash(ls)","WebSearch"]}}"#,
        );
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.permissions.len(), 2, "{report:?}");
        assert!(
            report
                .permissions
                .iter()
                .all(|g| g.source.as_str() == ".claude/settings.json")
        );
        assert!(
            report
                .permissions
                .iter()
                .any(|g| g.permission.is_unscoped())
        );
        assert!(report.is_complete());
    }

    #[test]
    fn a_malformed_file_is_reported_once_not_once_per_parser() {
        let tree = FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().file(".claude/settings.json", "{not json");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(
            report.unparsed.len(),
            1,
            "hooks and permissions both fail on the same file: {report:?}"
        );
    }
}
