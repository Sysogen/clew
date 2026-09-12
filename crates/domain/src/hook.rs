// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Commands an agent runs on an event.

/// A command registered to run when an agent reaches some event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hook {
    /// The event that triggers it, verbatim from the configuration. Not an
    /// enum: tools add events, and an unknown one still runs code.
    pub event: String,
    /// The command line, verbatim. Never executed.
    pub command: String,
    /// The declared type, when the entry states one. Recorded rather than
    /// filtered on: a type clew does not recognise may still execute.
    pub kind: Option<String>,
    /// Whether it fires as configured.
    ///
    /// A hook switched off is still reported. It is complete, committed, and
    /// one edit from running, so hiding it would leave the reader believing
    /// the file holds nothing.
    pub enabled: bool,
}

impl Hook {
    /// Whether the action injects a prompt rather than running a command.
    #[must_use]
    pub fn injects(&self) -> bool {
        self.kind.as_deref() == Some("agent")
    }
}
