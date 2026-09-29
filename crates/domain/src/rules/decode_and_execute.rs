// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `decode-and-execute` rule.

use super::{SHELL, shell_sites};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};
use crate::shell;

/// See [`Rule::detail`] for what this flags and why.
pub struct DecodeAndExecute;

impl Rule for DecodeAndExecute {
    fn id(&self) -> RuleId {
        RuleId::DecodeAndExecute
    }

    fn name(&self) -> &'static str {
        "decode-and-execute"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "Code decoded from base64, hex or a compressed blob and handed straight to an interpreter"
    }

    fn detail(&self) -> &'static str {
        "A hook decodes code, from base64, hex or a compressed blob, and hands it \
                straight to an interpreter, as echo ... | base64 -d | sh does. What runs \
                is not what the hook shows: a review, a diff or a scanner sees only the \
                encoded form. The xz-utils backdoor (CVE-2024-3094, disclosed by Andres \
                Freund on 29 March 2024) kept its script in a test file and ran it during \
                the build with ... | xz -d | /bin/bash."
    }

    fn remediation(&self) -> &'static str {
        "Keep the code a hook runs in the hook, or in a script beside it, as text. \
                If the hook came from someone else, decode the payload into a file without \
                running it, and read what it does before anything runs it."
    }

    fn reads(&self) -> &'static [Subject] {
        SHELL
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        shell_sites(at, shell::decodes_run, self.id(), width)
    }
}
