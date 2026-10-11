// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A step a CI workflow runs, and the shell it runs.

use crate::credential;

/// One step of one job, as the workflow writes it.
///
/// A step that runs nothing of its own is not one of these: a workflow's other
/// steps name an action to use rather than a command to run, and what those do
/// is decided by the action rather than by this file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Step {
    /// The job it belongs to, as the file names it.
    pub job: String,
    /// The shell it runs, with any credential value taken out. Never executed.
    pub run: String,
}

impl Step {
    /// A step with any credential in it taken out.
    ///
    /// Redacted on the way in, as a task's command is, so no later formatter
    /// or log can put the value back. A CI step is the likeliest place in a
    /// repository for a token to be written out, which is the reason this
    /// cannot wait until the report is rendered.
    #[must_use]
    pub fn new(job: &str, run: &str) -> Self {
        Self {
            job: redacted(job),
            run: redacted(run),
        }
    }
}

/// Text a report may carry: every credential value's visible characters
/// replaced by `*`.
fn redacted(text: &str) -> String {
    credential::mask(&text.chars().collect::<Vec<char>>())
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAT: &str = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");

    #[test]
    fn a_credential_in_a_step_is_never_recorded() {
        let held = Step::new(
            "deploy",
            &format!("curl -H 'Authorization: Bearer {PAT}' https://h.invalid"),
        );

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
        assert!(held.run.contains("curl"), "{held:?}");
    }

    /// A job's name reaches a report too, and a workflow may name a job after
    /// what it deploys with.
    #[test]
    fn a_credential_in_a_job_name_is_never_recorded() {
        let held = Step::new(&format!("push-{PAT}"), "echo ok");

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
        assert!(held.job.starts_with("push-"), "{held:?}");
    }
}
