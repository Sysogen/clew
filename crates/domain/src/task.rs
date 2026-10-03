// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A task a workspace declares, and when it runs.

use crate::credential;

/// Where a task's trigger says the folder opening is enough to start it.
///
/// VS Code's schema names two triggers, `default` and `folderOpen`, and the
/// spelling is what the editor matches. A value spelled any other way, padding
/// included, does not select this trigger.
const ON_OPEN: &str = "folderOpen";

/// A task declared in a workspace, as the file writes it.
///
/// A task runs a command, or depends on other tasks, or both: VS Code's own
/// examples show a compound task with only `dependsOn`, and one that lists
/// dependencies before running a command of its own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Task {
    /// The label it is listed under, with any credential value taken out.
    pub label: String,
    /// The command it runs, with any credential value taken out. `None` when
    /// it runs nothing of its own. Never executed.
    pub command: Option<String>,
    /// The tasks it runs first, with any credential value taken out.
    pub depends_on: Vec<String>,
    /// When it runs, exactly as written. `None` when the file sets no
    /// trigger, which leaves the task to be chosen by hand.
    pub runs_on: Option<String>,
}

impl Task {
    /// A task with any credential in it taken out.
    ///
    /// Redacted on the way in, as a server's arguments are, so no later
    /// formatter or log can put the value back. The label too: a task without
    /// one is listed by what it runs, and what it runs can carry a token.
    #[must_use]
    pub fn new(
        label: Option<&str>,
        command: Option<&str>,
        depends_on: &[String],
        runs_on: Option<String>,
    ) -> Self {
        // The label a file leaves out is what the task runs, so both come
        // from the same text and both are redacted here, once.
        let listed = label.map_or_else(|| fallback_label(command, depends_on), ToOwned::to_owned);
        Self {
            label: redacted(&listed),
            command: command.map(redacted),
            depends_on: depends_on.iter().map(|name| redacted(name)).collect(),
            runs_on,
        }
    }

    /// Whether opening the folder is what starts it.
    #[must_use]
    pub fn runs_on_open(&self) -> bool {
        self.runs_on.as_deref() == Some(ON_OPEN)
    }

    /// What it does, for display.
    #[must_use]
    pub fn invocation(&self) -> String {
        match (&self.command, self.depends_on.is_empty()) {
            (Some(command), true) => command.clone(),
            (Some(command), false) => {
                format!("{command}, after {}", self.depends_on.join(", "))
            }
            (None, false) => format!("runs {}", self.depends_on.join(", ")),
            (None, true) => String::new(),
        }
    }
}

/// Text a report may carry: every credential value's visible characters
/// replaced by `*`.
///
/// Local to this module for now. The branch that redacts what a report already
/// carried adds the same thing to `credential`, and this collapses into it.
fn redacted(text: &str) -> String {
    credential::mask(&text.chars().collect::<Vec<char>>())
        .into_iter()
        .collect()
}

/// How a task with no label of its own is listed: by what it runs.
fn fallback_label(command: Option<&str>, depends_on: &[String]) -> String {
    command.map_or_else(|| depends_on.join(", "), ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAT: &str = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");

    fn task(runs_on: Option<&str>) -> Task {
        Task::new(
            Some("build"),
            Some("npm run build"),
            &[],
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
    /// way selects no trigger and starts nothing. Padding included: the schema
    /// names the value, not a value with room around it.
    #[test]
    fn a_trigger_spelled_differently_is_not_the_trigger() {
        for spelling in [
            "folderopen",
            "FolderOpen",
            "folder-open",
            " folderOpen",
            "folderOpen ",
            "\tfolderOpen",
        ] {
            assert!(!task(Some(spelling)).runs_on_open(), "{spelling:?}");
        }
    }

    #[test]
    fn a_credential_in_a_command_is_never_recorded() {
        let held = Task::new(
            Some("deploy"),
            Some(&format!(
                "curl -H 'Authorization: Bearer {PAT}' https://h.invalid"
            )),
            &[],
            None,
        );

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
        assert!(
            held.command.as_deref().is_some_and(|c| c.contains("curl")),
            "{held:?}"
        );
    }

    /// A task without a label is listed by what it runs, so the label is a
    /// second place the same command reaches a report.
    #[test]
    fn a_credential_in_an_unlabelled_task_is_never_recorded() {
        let labelled = Task::new(
            Some(&format!("deploy with {PAT}")),
            Some("echo ok"),
            &[],
            None,
        );
        let unlabelled = Task::new(None, Some(&format!("npm publish --token {PAT}")), &[], None);

        assert!(
            !format!("{labelled:?}").contains(PAT),
            "a label written out carries one too: {labelled:?}"
        );
        assert!(labelled.label.contains("deploy with"), "{labelled:?}");
        assert!(
            !format!("{unlabelled:?}").contains(PAT),
            "and so does the label standing in for a command: {unlabelled:?}"
        );
        assert!(unlabelled.label.contains("npm publish"), "{unlabelled:?}");
    }

    #[test]
    fn a_credential_in_a_dependency_is_never_recorded() {
        let held = Task::new(None, None, &[format!("build {PAT}")], None);

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
    }

    /// A compound task runs its dependencies and nothing of its own, which is
    /// VS Code's own example.
    #[test]
    fn a_compound_task_is_listed_by_what_it_depends_on() {
        let held = Task::new(
            Some("Build"),
            None,
            &["Client Build".to_owned(), "Server Build".to_owned()],
            Some("folderOpen".to_owned()),
        );

        assert_eq!(held.invocation(), "runs Client Build, Server Build");
        assert!(held.runs_on_open());
    }

    /// And one may do both, dependencies first.
    #[test]
    fn a_task_with_dependencies_and_a_command_shows_both() {
        let held = Task::new(
            Some("One"),
            Some("echo Hello"),
            &["Two".to_owned(), "Three".to_owned()],
            None,
        );

        assert_eq!(held.invocation(), "echo Hello, after Two, Three");
    }
}
