// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Where a surface lives.

/// The tree a row is matched against.
///
/// A tool keeps per-project configuration in the repository and personal
/// configuration under the home directory. The second never reaches a code
/// review, so it is the half a scan of a checkout cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum Scope {
    /// A repository being scanned.
    #[default]
    Repository,
    /// The home directory of whoever runs the agent.
    Home,
}

impl Scope {
    /// The scope a catalogue row names, if it names one that exists.
    #[must_use]
    pub fn from_catalogue(name: &str) -> Option<Self> {
        Some(match name {
            "repository" => Self::Repository,
            "home" => Self::Home,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_naming_no_scope_is_a_repository_row() {
        assert_eq!(Scope::default(), Scope::Repository);
    }

    #[test]
    fn an_unknown_scope_is_not_guessed_at() {
        assert_eq!(Scope::from_catalogue("system"), None);
        assert_eq!(Scope::from_catalogue("Home"), None);
    }
}
