// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `bypass-permissions` rule.

use super::{about_file, after_key, found_at};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct BypassPermissions;

impl Rule for BypassPermissions {
    fn id(&self) -> RuleId {
        RuleId::BypassPermissions
    }

    fn name(&self) -> &'static str {
        "bypass-permissions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "A mode that starts an agent with neither a permission prompt nor a sandbox"
    }

    fn detail(&self) -> &'static str {
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

    fn remediation(&self) -> &'static str {
        "Remove the mode and let the agent ask, or narrow what may happen without \
                asking: permissions.allow in Claude Code, chat.tools.terminal.autoApprove \
                in VS Code and a per-tool always_allow in Zed each pre-approve named \
                operations rather than every one. Where a machine genuinely runs \
                unattended, setting the mode in that machine's own user settings rather \
                than in a file the repository ships keeps it to the machine that meant it."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Mode]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Mode { path, mode, source } = at else {
            return Vec::new();
        };
        if !mode.is_unchecked() {
            return Vec::new();
        }
        vec![
            after_key(source, &mode.key, &mode.value, 0)
                .and_then(|at| found_at(path, self.id(), source, at, width))
                .unwrap_or_else(|| about_file(path, self.id(), &mode.value, width)),
        ]
    }
}
