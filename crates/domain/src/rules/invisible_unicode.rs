// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `invisible-unicode` rule.

use super::hidden_characters;
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct InvisibleUnicode;

impl Rule for InvisibleUnicode {
    fn id(&self) -> RuleId {
        RuleId::InvisibleUnicode
    }

    fn name(&self) -> &'static str {
        "invisible-unicode"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "Non-printing Unicode in a file an agent reads as instructions"
    }

    fn detail(&self) -> &'static str {
        "An instruction, rules, skill or hook file holds a character that renders \
                as nothing: zero-width, bidirectional, tag-block or another \
                default-ignorable character. The model reads it and a reviewer does not, \
                which is how the Rules File Backdoor, disclosed by Pillar Security on 18 \
                March 2025, hid instructions in rules files. In a hook script it is \
                Trojan Source, CVE-2021-42574."
    }

    fn remediation(&self) -> &'static str {
        "Open the file in an editor that shows invisible characters and remove the \
                character unless it was put there on purpose. The evidence shows it as \
                <U+XXXX>, never the character itself."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Text]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Text { path, text } = at else {
            return Vec::new();
        };
        hidden_characters(path, text, width)
    }
}
