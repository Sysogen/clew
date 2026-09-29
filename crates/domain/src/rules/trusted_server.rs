// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `trusted-server` rule.

use super::{SERVER_BLOCKS, about_file, after_key, found_at};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct TrustedServer;

impl Rule for TrustedServer {
    fn id(&self) -> RuleId {
        RuleId::TrustedServer
    }

    fn name(&self) -> &'static str {
        "trusted-server"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "An MCP server whose tool calls run without being confirmed"
    }

    fn detail(&self) -> &'static str {
        "An MCP server is declared with trust: true, which Gemini CLI's reference \
                lists under \"Security bypass setting\" and documents as bypassing all tool \
                call confirmations for that server. Every tool it offers then runs unseen, \
                and a server decides for itself what it offers: one added after the trust was \
                granted is trusted too, and a tool whose description changes is never shown \
                again. The agent takes the server's word for what it is being asked to do."
    }

    fn remediation(&self) -> &'static str {
        "Remove trust and confirm the calls, or keep it only for a server whose code \
                you control and whose tool list you pin. Where the confirmations are too \
                noisy, includeTools names the ones a project actually uses, which bounds the \
                server without turning the prompt off. Cline's autoApprove and VS Code's \
                chat.tools.eligibleForAutoApproval do the same by naming tools rather than \
                trusting all of them."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Server]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Server {
            path,
            server,
            source,
        } = at
        else {
            return Vec::new();
        };
        if !server.trusted {
            return Vec::new();
        }
        vec![
            SERVER_BLOCKS
                .iter()
                .find_map(|key| after_key(source, key, &server.name, 0))
                .and_then(|at| found_at(path, self.id(), source, at, width))
                .unwrap_or_else(|| about_file(path, self.id(), &server.name, width)),
        ]
    }
}
