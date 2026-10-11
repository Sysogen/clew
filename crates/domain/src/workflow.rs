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
    /// The shell it runs under, as the workflow decides it: the step's own
    /// `shell`, the nearest `defaults.run.shell`, or the runner's default.
    pub shell: String,
}

impl Step {
    /// A step with any credential in it taken out.
    ///
    /// Redacted on the way in, as a task's command is, so no later formatter
    /// or log can put the value back. A CI step is the likeliest place in a
    /// repository for a token to be written out, which is the reason this
    /// cannot wait until the report is rendered.
    #[must_use]
    pub fn new(job: &str, run: &str, shell: &str) -> Self {
        Self {
            job: redacted(job),
            run: redacted(run),
            shell: shell.to_owned(),
        }
    }

    /// Whether what it runs is a POSIX shell, and so readable as one.
    ///
    /// A workflow may run PowerShell, Python or a shell of its own choosing,
    /// and Windows runners default to PowerShell. Reading those as Bash would
    /// judge one language by another's syntax, so they are reported and left
    /// unjudged rather than guessed at. The first word is what decides it: a
    /// custom `shell` is a command line, and `bash -e {0}` is still Bash.
    #[must_use]
    pub fn is_posix_shell(&self) -> bool {
        self.shell
            .split_whitespace()
            .next()
            .map(|word| word.rsplit(['/', '\\']).next().unwrap_or(word))
            .is_some_and(|name| matches!(name, "bash" | "sh"))
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

    /// Only a POSIX shell is read as one. A step running PowerShell or Python
    /// is reported and left unjudged: reading it as Bash would judge one
    /// language by another's syntax.
    #[test]
    fn only_a_posix_shell_is_read_as_shell() {
        for shell in ["bash", "sh", "bash -e {0}", "/bin/bash", "/usr/bin/sh"] {
            assert!(Step::new("a", "echo ok", shell).is_posix_shell(), "{shell}");
        }
        for shell in [
            "pwsh",
            "powershell",
            "python",
            "python3",
            "cmd",
            "C:\\Windows\\pwsh.exe",
            "",
        ] {
            assert!(
                !Step::new("a", "echo ok", shell).is_posix_shell(),
                "{shell}"
            );
        }
    }

    #[test]
    fn a_credential_in_a_step_is_never_recorded() {
        let held = Step::new(
            "deploy",
            &format!("curl -H 'Authorization: Bearer {PAT}' https://h.invalid"),
            "bash",
        );

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
        assert!(held.run.contains("curl"), "{held:?}");
    }

    /// A job's name reaches a report too, and a workflow may name a job after
    /// what it deploys with.
    #[test]
    fn a_credential_in_a_job_name_is_never_recorded() {
        let held = Step::new(&format!("push-{PAT}"), "echo ok", "bash");

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
        assert!(held.job.starts_with("push-"), "{held:?}");
    }
}
