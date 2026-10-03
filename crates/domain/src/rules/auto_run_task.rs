// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `auto-run-task` rule.

use super::{about_file, after_key, found_at};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct AutoRunTask;

impl Rule for AutoRunTask {
    fn id(&self) -> RuleId {
        RuleId::AutoRunTask
    }

    fn name(&self) -> &'static str {
        "auto-run-task"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "A task a workspace runs when the folder is opened"
    }

    fn detail(&self) -> &'static str {
        "A task sets runOptions.runOn to folderOpen, which VS Code documents as running \
                it when the containing folder is opened. Opening a repository is what a \
                reviewer does before reading any of it, so the command runs before anyone \
                has looked at what it is. Two limits apply and neither is a reason to ignore \
                this: an automatic task never runs in a workspace that is not trusted, and \
                task.allowAutomaticTasks defaults to off, which prompts once rather than \
                running. What the file asks for is still arbitrary execution on open, in a \
                repository anyone may clone, and one Allow is all that stands in the way. \
                CVE-2026-10591 is where this led: AWS fixed Kiro IDE 0.11 because its file \
                write tool let crafted instructions write this very trigger, rated 8.8 high \
                under CVSS 3.1 by AWS as the assigning authority."
    }

    fn remediation(&self) -> &'static str {
        "Take the trigger out and leave the task to be chosen, which is what runOn \
                default means and what omitting runOptions already does. Where a workspace \
                genuinely needs setup on open, read the command first and keep it to \
                something whose source you control, since every later change to it runs on \
                the same trigger. Leaving task.allowAutomaticTasks at off keeps the prompt, \
                and not trusting a workspace you are only reading stops the task outright."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Task]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Task { path, task, source } = at else {
            return Vec::new();
        };
        if !task.runs_on_open() {
            return Vec::new();
        }
        vec![
            after_key(
                source,
                "runOn",
                task.runs_on.as_deref().unwrap_or_default(),
                0,
            )
            .and_then(|at| found_at(path, self.id(), source, at, width))
            .unwrap_or_else(|| about_file(path, self.id(), &task.label, width)),
        ]
    }
}
