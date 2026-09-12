// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What an agent does when it reaches an event.

/// What a hook does when it fires.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// A shell command. Never executed.
    Command(String),
    /// Text put into the model's context.
    Prompt(String),
}

impl Action {
    /// What it runs or injects, verbatim.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Command(text) | Self::Prompt(text) => text,
        }
    }

    /// Whether it reaches the model rather than a shell.
    #[must_use]
    pub fn injects(&self) -> bool {
        matches!(self, Self::Prompt(_))
    }
}

/// Something registered to happen when an agent reaches an event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hook {
    /// The event that triggers it, verbatim. Not an enum: tools add events,
    /// and an unknown one still runs code.
    pub event: String,
    /// What it does.
    pub action: Action,
    /// The declared type, when the entry states one. Recorded rather than
    /// filtered on: a type clew does not recognise may still execute.
    pub kind: Option<String>,
    /// Whether it fires as configured. A hook switched off is still reported,
    /// being one edit from running.
    pub enabled: bool,
}
