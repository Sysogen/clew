// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `unpinned-remote-package` rule.

use super::{SHELL, shell_sites};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};
use crate::shell;

/// See [`Rule::detail`] for what this flags and why.
pub struct UnpinnedRemotePackage;

impl Rule for UnpinnedRemotePackage {
    fn id(&self) -> RuleId {
        RuleId::UnpinnedRemotePackage
    }

    fn name(&self) -> &'static str {
        "unpinned-remote-package"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &'static str {
        "A registry package run at a tag that moves, such as @latest"
    }

    fn detail(&self) -> &'static str {
        "A hook runs a package from a registry at a tag that moves, as npx \
                claude-flow@latest does, so it runs whichever version was published last, \
                every time it fires, with the agent's permissions. In the Shai-Hulud \
                attack (StepSecurity, 15 September 2025), compromised versions of \
                @ctrl/tinycolor and 40 other npm packages carried a postinstall payload; \
                a runner fetching the latest release at that moment fetched it."
    }

    fn remediation(&self) -> &'static str {
        "Pin the package to an exact version (npx tool@1.4.2), or add it to the \
                project's dependencies so the lockfile decides the version and checks its \
                integrity."
    }

    fn reads(&self) -> &'static [Subject] {
        SHELL
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        shell_sites(at, shell::unpinned_packages, self.id(), width)
    }
}
