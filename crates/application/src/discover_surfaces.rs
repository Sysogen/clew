// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Walk a repository and report the agent surfaces it configures.

use clew_domain::extract;
use clew_domain::ports::file_contents::FileContents;
use clew_domain::ports::file_tree::{FileTree, FileTreeError};
use clew_domain::{Hook, McpServer, Permission, RepoPath, ScanPolicy, Surface, catalogue};

/// An MCP server, and the file that declared it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeclaredServer {
    /// The configuration file it was read from.
    pub source: RepoPath,
    /// The server itself.
    pub server: McpServer,
}

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
    /// MCP servers the surfaces declare, in path order.
    pub servers: Vec<DeclaredServer>,
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
            // A row declaring no extractions is inventory: never opened, which
            // matters when the file may be a compiled binary.
            let Some(matched) = catalogue().lookup(&path) else {
                continue;
            };
            if matched.extract.is_empty() {
                continue;
            }

            let text = match self.contents.read(&path, self.policy.max_file_bytes()) {
                Ok(text) => text,
                Err(error) => {
                    report.unparsed.push((path, error.to_string()));
                    continue;
                }
            };

            // Parsed once, however many extractions the row declares.
            let found = match extract::run(matched.extract, matched.format, &text) {
                Ok(found) => found,
                Err(error) => {
                    report.unparsed.push((path, error.to_string()));
                    continue;
                }
            };

            for hook in found.hooks {
                report.hooks.push(RegisteredHook {
                    source: path.clone(),
                    hook,
                });
            }
            for permission in found.permissions {
                report.permissions.push(GrantedPermission {
                    source: path.clone(),
                    permission,
                });
            }
            for server in found.servers {
                report.servers.push(DeclaredServer {
                    source: path.clone(),
                    server,
                });
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
                if let Some(matched) = catalogue().lookup(&entry.path) {
                    report.surfaces.push(Surface {
                        path: entry.path,
                        kind: matched.kind,
                    });
                }
            }
        }

        report.surfaces.sort();
        self.collect_hooks(&mut report);
        report.hooks.sort();
        report.permissions.sort();
        report.servers.sort();
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
        assert_eq!(report.hooks[0].hook.action.text(), "x.sh");
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

    /// The shape Gemini's own configuration reference shows, kept verbatim so a
    /// change to it surfaces here rather than as a silent zero.
    #[test]
    fn a_gemini_config_reports_its_servers() {
        let tree = FakeTree::default()
            .dir("", &[(".gemini", EntryKind::Directory)])
            .dir(".gemini", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".gemini/settings.json",
            r#"{
              "mcpServers": {
                "mainServer": { "command": "bin/mcp_server.py" },
                "anotherServer": {
                  "command": "node",
                  "args": ["mcp_server.js", "--verbose"],
                  "trust": true
                }
              }
            }"#,
        );

        let report = DiscoverSurfaces::new(&tree, &contents, &ScanPolicy::default()).run();

        assert_eq!(report.servers.len(), 2, "{report:?}");
        assert!(
            report
                .servers
                .iter()
                .any(|s| s.server.invocation() == "node mcp_server.js --verbose")
        );
        assert!(report.is_complete());
    }

    /// A new surface must not open a new way for a credential to escape.
    #[test]
    fn a_gemini_config_reports_no_credential() {
        let tree = FakeTree::default()
            .dir("", &[(".gemini", EntryKind::Directory)])
            .dir(".gemini", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".gemini/settings.json",
            r#"{"mcpServers":{
                 "a":{"command":"npx","args":["srv","--api-key","sk-live-SECRET"]},
                 "b":{"url":"https://u:pw@mcp.example.invalid/sse?token=TOKENV"},
                 "c":{"command":"x","env":{"API_KEY":"ENVV"}}}}"#,
        );

        let report = DiscoverSurfaces::new(&tree, &contents, &ScanPolicy::default()).run();

        let rendered = format!("{report:?}");
        for secret in ["sk-live-SECRET", "TOKENV", "ENVV", "pw@"] {
            assert!(!rendered.contains(secret), "{secret} reached the report");
        }
        assert_eq!(report.servers.len(), 3, "the servers are still reported");
    }

    /// Kiro's own example, kept verbatim. Its env values are hard-coded
    /// credentials in the documentation itself.
    #[test]
    fn a_kiro_config_reports_servers_without_their_secrets() {
        let tree = FakeTree::default()
            .dir("", &[(".kiro", EntryKind::Directory)])
            .dir(".kiro", &[("settings", EntryKind::Directory)])
            .dir(".kiro/settings", &[("mcp.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".kiro/settings/mcp.json",
            r#"{"mcpServers":{
                 "local":{"command":"uvx","args":["mcp-server-fetch"],
                          "env":{"ENV_VAR1":"hard-coded-variable"},
                          "autoApprove":["*"]},
                 "remote":{"url":"https://endpoint.to.connect.to"}}}"#,
        );

        let report = DiscoverSurfaces::new(&tree, &contents, &ScanPolicy::default()).run();

        assert_eq!(report.servers.len(), 2, "{report:?}");
        assert!(
            report
                .servers
                .iter()
                .any(|s| s.server.invocation() == "uvx mcp-server-fetch")
        );
        assert!(
            !format!("{report:?}").contains("hard-coded-variable"),
            "a value in env is a credential whatever the tool calls it"
        );
        assert!(report.is_complete());
    }

    /// Kiro's documented hook file, reported end to end.
    #[test]
    fn a_kiro_hook_file_reports_its_command() {
        let tree = FakeTree::default()
            .dir("", &[(".kiro", EntryKind::Directory)])
            .dir(".kiro", &[("hooks", EntryKind::Directory)])
            .dir(".kiro/hooks", &[("lint-on-save.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".kiro/hooks/lint-on-save.json",
            r#"{"version":"v1","hooks":[
                 {"name":"Lint on save","trigger":"PostFileSave",
                  "action":{"type":"command","command":"npx eslint --fix"}},
                 {"name":"Brief","trigger":"Stop",
                  "action":{"type":"agent","prompt":"Summarise the diff"}}]}"#,
        );

        let report = DiscoverSurfaces::new(&tree, &contents, &ScanPolicy::default()).run();

        assert_eq!(report.hooks.len(), 2, "{report:?}");
        assert!(
            report
                .hooks
                .iter()
                .any(|h| h.hook.action.text() == "npx eslint --fix"
                    && h.hook.event == "PostFileSave")
        );
        assert!(
            report
                .hooks
                .iter()
                .any(|h| h.hook.kind.as_deref() == Some("agent"))
        );
        assert!(report.is_complete());
    }

    #[test]
    fn a_zed_config_reports_its_context_servers() {
        let tree = FakeTree::default()
            .dir("", &[(".zed", EntryKind::Directory)])
            .dir(".zed", &[("settings.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".zed/settings.json",
            r#"{"tab_size":2,
                "context_servers":{"pg":{"command":"npx","args":["-y","server-postgres"]}}}"#,
        );

        let report = DiscoverSurfaces::new(&tree, &contents, &ScanPolicy::default()).run();

        assert_eq!(report.servers.len(), 1, "{report:?}");
        assert_eq!(
            report.servers[0].server.invocation(),
            "npx -y server-postgres"
        );
        assert!(report.is_complete());
    }

    fn skill_tree() -> FakeTree {
        FakeTree::default()
            .dir("", &[(".claude", EntryKind::Directory)])
            .dir(".claude", &[("skills", EntryKind::Directory)])
            .dir(".claude/skills", &[("prose", EntryKind::Directory)])
            .dir(".claude/skills/prose", &[("SKILL.md", EntryKind::File)])
    }

    #[test]
    fn a_skill_declares_its_grants_in_frontmatter() {
        let contents = FakeContents::default().file(
            ".claude/skills/prose/SKILL.md",
            "---\nname: prose\nallowed-tools: Bash(rg:*), Read\n---\n\n# Prose\n",
        );

        let report = DiscoverSurfaces::new(&skill_tree(), &contents, &ScanPolicy::default()).run();

        assert_eq!(report.surfaces.len(), 1);
        assert_eq!(report.permissions.len(), 2, "{report:?}");
        assert!(
            report
                .permissions
                .iter()
                .all(|g| g.source.as_str() == ".claude/skills/prose/SKILL.md")
        );
        assert!(
            report
                .permissions
                .iter()
                .any(|g| g.permission.tool == "Bash")
        );
        assert!(report.is_complete());
    }

    /// Most Markdown carries no frontmatter. That is a complete answer, not a
    /// failed read, so the scan stays clean rather than reporting a gap.
    #[test]
    fn a_skill_without_frontmatter_scans_clean() {
        let contents = FakeContents::default().file(
            ".claude/skills/prose/SKILL.md",
            "# Prose\n\nUse short sentences.\n",
        );

        let report = DiscoverSurfaces::new(&skill_tree(), &contents, &ScanPolicy::default()).run();

        assert_eq!(report.surfaces.len(), 1, "the file is still inventoried");
        assert!(report.permissions.is_empty(), "{report:?}");
        assert!(
            report.unparsed.is_empty(),
            "no frontmatter is not a failure"
        );
        assert!(report.is_complete());
    }

    /// A skill is read now that it can declare grants, so a read that fails is
    /// a gap in the scan and must be said rather than counted as nothing.
    #[test]
    fn a_skill_that_cannot_be_read_is_reported() {
        let contents = FakeContents::default().deny(".claude/skills/prose/SKILL.md");

        let report = DiscoverSurfaces::new(&skill_tree(), &contents, &ScanPolicy::default()).run();

        assert_eq!(report.surfaces.len(), 1);
        assert_eq!(report.unparsed.len(), 1, "{report:?}");
        assert!(!report.is_complete());
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

    #[test]
    fn servers_are_attributed_and_carry_no_secret() {
        let tree = FakeTree::default().dir("", &[(".mcp.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".mcp.json",
            r#"{"mcpServers":{"pg":{"command":"npx","env":{"DATABASE_URL":"postgres://u:hunter2@h/d"}}}}"#,
        );
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.servers.len(), 1, "{report:?}");
        assert_eq!(report.servers[0].source.as_str(), ".mcp.json");
        assert_eq!(report.servers[0].server.env, vec!["DATABASE_URL"]);
        assert!(
            !format!("{report:?}").contains("hunter2"),
            "a credential must never reach the report"
        );
        assert!(report.is_complete());
    }

    /// The Cursor row declares `mcp-servers`. Without an end-to-end case the
    /// row could lose that and every other test would still pass.
    #[test]
    fn a_cursor_mcp_file_reaches_the_report() {
        let tree = FakeTree::default()
            .dir("", &[(".cursor", EntryKind::Directory)])
            .dir(".cursor", &[("mcp.json", EntryKind::File)]);
        let contents = FakeContents::default().file(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"pg":{"command":"npx","env":{"DATABASE_URL":"x"}}}}"#,
        );
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.servers.len(), 1, "{report:?}");
        assert_eq!(report.servers[0].source.as_str(), ".cursor/mcp.json");
        assert_eq!(report.servers[0].server.env, vec!["DATABASE_URL"]);
        assert!(report.is_complete());
    }

    #[test]
    fn a_malformed_file_is_still_reported_once_with_three_parsers() {
        let tree = FakeTree::default().dir("", &[(".mcp.json", EntryKind::File)]);
        let contents = FakeContents::default().file(".mcp.json", "{not json");
        let policy = ScanPolicy::default();

        let report = DiscoverSurfaces::new(&tree, &contents, &policy).run();

        assert_eq!(report.unparsed.len(), 1, "{report:?}");
    }
}
