// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `unverified-download` rule.

use super::{SHELL, shell_sites};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};
use crate::shell;

/// See [`Rule::detail`] for what this flags and why.
pub struct UnverifiedDownload;

impl Rule for UnverifiedDownload {
    fn id(&self) -> RuleId {
        RuleId::UnverifiedDownload
    }

    fn name(&self) -> &'static str {
        "unverified-download"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "A downloaded file run with no checksum or signature checked first"
    }

    fn detail(&self) -> &'static str {
        "A hook downloads a file and later runs it, or unpacks it and runs what it \
                held, without checking a checksum or a signature first. A moved tag, a \
                mutable URL or a compromised host changes what runs, with the agent's \
                permissions, the next time the hook fires. The loader in the keyv and \
                cacheable compromise (Socket, 4 August 2026) downloaded a Bun release over \
                HTTPS with no checksum or signature verification and ran it."
    }

    fn remediation(&self) -> &'static str {
        "Pin the download to a version and check it against a published checksum or \
                signature before running it (sha256sum -c, gpg --verify, cosign \
                verify-blob), or install the tool through a package manager with a \
                lockfile."
    }

    fn reads(&self) -> &'static [Subject] {
        SHELL
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        shell_sites(at, shell::downloads_run_later, self.id(), width)
    }
}
