// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A task a workspace declares, and when it runs.

use crate::credential;

/// Where a task's trigger says the folder opening is enough to start it.
///
/// VS Code's schema names two triggers, `default` and `folderOpen`, and the
/// spelling is what the editor matches. A value spelled any other way does not
/// select this trigger, so it is recorded and left alone.
const ON_OPEN: &str = "folderOpen";

/// A task declared in a workspace, as the file writes it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Task {
    /// The label it is listed under.
    pub label: String,
    /// The command it runs, with any credential value taken out. Never
    /// executed.
    pub command: String,
    /// When it runs, verbatim. `None` when the file sets no trigger, which
    /// leaves the task to be chosen by hand.
    pub runs_on: Option<String>,
}

impl Task {
    /// A task with any credential in its command taken out.
    ///
    /// Redacted on the way in, as a server's arguments are, so no later
    /// formatter or log can put the value back.
    #[must_use]
    pub fn new(label: String, command: &str, runs_on: Option<String>) -> Self {
        Self {
            label,
            command: credential::mask(&command.chars().collect::<Vec<char>>())
                .into_iter()
                .collect(),
            runs_on,
        }
    }

    /// Whether opening the folder is what starts it.
    #[must_use]
    pub fn runs_on_open(&self) -> bool {
        self.runs_on.as_deref() == Some(ON_OPEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(runs_on: Option<&str>) -> Task {
        Task::new(
            "build".to_owned(),
            "npm run build",
            runs_on.map(ToOwned::to_owned),
        )
    }

    #[test]
    fn a_task_triggered_by_the_folder_opening_says_so() {
        assert!(task(Some("folderOpen")).runs_on_open());
    }

    /// The other documented trigger, and the absence of one, both wait to be
    /// chosen by hand.
    #[test]
    fn a_task_run_by_hand_does_not() {
        assert!(!task(Some("default")).runs_on_open());
        assert!(!task(None).runs_on_open());
    }

    /// The spelling is what the editor matches, so a value written any other
    /// way selects no trigger and starts nothing.
    #[test]
    fn a_trigger_spelled_differently_is_not_the_trigger() {
        for spelling in ["folderopen", "FolderOpen", "folder-open", " folderOpen"] {
            assert!(!task(Some(spelling)).runs_on_open(), "{spelling}");
        }
    }

    #[test]
    fn a_credential_in_a_command_is_never_recorded() {
        let held = Task::new(
            "deploy".to_owned(),
            "curl -H 'Authorization: Bearer sk-live-ABCDEFGHIJKLMNOP' https://h.invalid",
            None,
        );

        assert!(
            !held.command.contains("sk-live-ABCDEFGHIJKLMNOP"),
            "{held:?}"
        );
        assert!(held.command.contains("curl"), "{held:?}");
    }
}
