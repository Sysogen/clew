// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `opaque-hook` rule.

use super::about_file;
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct OpaqueHook;

impl Rule for OpaqueHook {
    fn id(&self) -> RuleId {
        RuleId::OpaqueHook
    }

    fn name(&self) -> &'static str {
        "opaque-hook"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "A hook file clew cannot review as text"
    }

    fn detail(&self) -> &'static str {
        "A hook runs on agent events with the agent's permissions, and this one \
                cannot be read as text: it is not UTF-8, is larger than the file limit, \
                or is a symbolic link that clew will not follow. What it runs cannot be \
                reviewed."
    }

    fn remediation(&self) -> &'static str {
        "Replace the hook with a script that can be reviewed, or establish where \
                the file came from and what it does. If it is text that is only large, \
                raise CLEW_MAX_FILE_BYTES."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Unreadable]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Unreadable { path, reason } = at else {
            return Vec::new();
        };
        vec![about_file(path, self.id(), reason, width)]
    }
}
