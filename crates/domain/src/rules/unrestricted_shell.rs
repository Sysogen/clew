// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `unrestricted-shell` rule.

use super::{GRANT_LISTS, about_file, after_key, found_at};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct UnrestrictedShell;

impl Rule for UnrestrictedShell {
    fn id(&self) -> RuleId {
        RuleId::UnrestrictedShell
    }

    fn name(&self) -> &'static str {
        "unrestricted-shell"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "A pre-approved shell grant with nothing restricting the commands it runs"
    }

    fn detail(&self) -> &'static str {
        "A configuration file pre-approves the shell with nothing restricting what \
                it runs: Claude Code's Bash, Bash() or Bash(*), or Gemini CLI's \
                run_shell_command, in permissions.allow, tools.allowed, or a skill's \
                allowed-tools. Every command the agent chooses then runs without being \
                shown to anyone, which is the grant the other entries in those lists \
                exist to avoid needing. A tool that takes no argument restriction, such \
                as WebSearch or an MCP tool, is not flagged: a bare entry is the only way \
                to write that grant."
    }

    fn remediation(&self) -> &'static str {
        "Replace the entry with the commands the project actually runs, scoped, as \
                Bash(cargo test:*) and run_shell_command(git) are. Where a broad grant is \
                genuinely wanted, keeping it in a personal settings.local.json rather than \
                the file the repository ships limits it to the person who chose it."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Grant]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Grant {
            path,
            grant,
            source,
            occurrence,
        } = at
        else {
            return Vec::new();
        };
        if !grant.is_unrestricted_shell() {
            return Vec::new();
        }
        let entry = grant.written();
        vec![
            GRANT_LISTS
                .iter()
                .find_map(|key| after_key(source, key, &entry, *occurrence))
                .and_then(|at| found_at(path, self.id(), source, at, width))
                .unwrap_or_else(|| about_file(path, self.id(), &entry, width)),
        ]
    }
}
