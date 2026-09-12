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
    /// The machine, where an administrator deploys policy nobody can edit.
    System,
}

impl Scope {
    /// The scope a catalogue row names, if it names one that exists.
    #[must_use]
    pub fn from_catalogue(name: &str) -> Option<Self> {
        Some(match name {
            "repository" => Self::Repository,
            "home" => Self::Home,
            "system" => Self::System,
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
        assert_eq!(Scope::from_catalogue("machine"), None);
        assert_eq!(Scope::from_catalogue("Home"), None);
    }

    #[test]
    fn each_tree_has_its_own_name() {
        assert_eq!(Scope::from_catalogue("system"), Some(Scope::System));
        assert_eq!(Scope::from_catalogue("home"), Some(Scope::Home));
        assert_eq!(Scope::from_catalogue("repository"), Some(Scope::Repository));
    }
}
