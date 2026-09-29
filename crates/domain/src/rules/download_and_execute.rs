// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `download-and-execute` rule.

use super::{SHELL, shell_sites};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};
use crate::shell;

/// See [`Rule::detail`] for what this flags and why.
pub struct DownloadAndExecute;

impl Rule for DownloadAndExecute {
    fn id(&self) -> RuleId {
        RuleId::DownloadAndExecute
    }

    fn name(&self) -> &'static str {
        "download-and-execute"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "Code fetched from the network and handed straight to an interpreter"
    }

    fn detail(&self) -> &'static str {
        "A hook downloads code and hands it straight to an interpreter, as \
                curl ... | bash does. What runs is whatever the server returns at that \
                moment, with the agent's permissions, every time the hook fires. The \
                compromised tj-actions/changed-files action (CVE-2025-30066, 14 March \
                2025) ran curl ... memdump.py | sudo python3."
    }

    fn remediation(&self) -> &'static str {
        "Download to a file, check it against a pinned checksum or signature, and \
                run the checked file, or install the tool through a package manager with \
                a lockfile. If the hook came from someone else, find out why it fetches \
                code each time it runs."
    }

    fn reads(&self) -> &'static [Subject] {
        SHELL
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        shell_sites(at, shell::downloads_run, self.id(), width)
    }
}
