// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A named permissions profile, which is how Codex writes a sandbox apart
//! from the file that selects it.

/// A named permissions profile a configuration file defines.
///
/// Recorded as found, not judged: what a profile grants is read out of it and
/// which profile is in force is a question for whoever selected one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Profile {
    /// The name the file gave it, as `default_permissions` selects it.
    pub name: String,
    /// The profile applied before this one, when it names one.
    pub extends: Option<String>,
    /// Whether any filesystem rule in it grants a write.
    pub writes: bool,
}

/// The built-in profile that permits writes, as `extends` and
/// `default_permissions` both spell it.
pub const WORKSPACE: &str = ":workspace";

/// The built-in that bounds nothing.
///
/// The reference gives `extends` three values and this is not among them, so
/// a profile naming it here is naming something the documentation does not
/// describe. It is read as what it says rather than passed over: the two
/// answers are a finding on a configuration that may be unbounded, and
/// silence on one that is, and silence is the worse of them.
pub const FULL_ACCESS: &str = ":danger-full-access";

impl Profile {
    /// Whether the profile `selected` names permits a write.
    ///
    /// `extends` applies a parent before the profile itself, so a profile
    /// that grants nothing of its own still writes where its parent does.
    /// The chain is walked rather than assumed one deep, and a profile is
    /// visited once: a file is free to write a cycle, and a scan that
    /// followed one would not finish.
    #[must_use]
    pub fn selected(defined: &[&Self], selected: &str) -> bool {
        let mut name = selected.to_owned();
        let mut seen: Vec<String> = Vec::new();
        loop {
            if name == WORKSPACE || name == FULL_ACCESS {
                return true;
            }
            if seen.contains(&name) {
                return false;
            }
            let Some(held) = defined.iter().find(|p| p.name == name) else {
                return false;
            };
            if held.writes {
                return true;
            }
            seen.push(name);
            let Some(parent) = held.extends.clone() else {
                return false;
            };
            name = parent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, extends: Option<&str>, writes: bool) -> Profile {
        Profile {
            name: name.to_owned(),
            extends: extends.map(str::to_owned),
            writes,
        }
    }

    #[test]
    fn the_built_in_that_writes_writes() {
        assert!(Profile::selected(&[], WORKSPACE));
    }

    #[test]
    fn a_profile_granting_a_write_writes() {
        let ours = profile("ours", None, true);

        assert!(Profile::selected(&[&ours], "ours"));
    }

    #[test]
    fn a_profile_granting_nothing_does_not() {
        let ours = profile("ours", None, false);

        assert!(!Profile::selected(&[&ours], "ours"));
    }

    /// `extends` applies a parent first, so what the parent grants is in
    /// force whatever the profile itself says.
    #[test]
    fn a_profile_extending_one_that_writes_writes() {
        let ours = profile("ours", Some(WORKSPACE), false);

        assert!(Profile::selected(&[&ours], "ours"));
    }

    /// And through a chain, which the reference allows by letting a profile
    /// extend another named one.
    #[test]
    fn a_chain_reaching_a_write_writes() {
        let base = profile("base", None, true);
        let middle = profile("middle", Some("base"), false);
        let ours = profile("ours", Some("middle"), false);

        assert!(Profile::selected(&[&ours, &middle, &base], "ours"));
    }

    /// A profile extending the built-in that bounds nothing writes, and
    /// nothing else would say so: `bypass-permissions` reads the key that
    /// selected the profile, which says `ours` rather than the parent, so a
    /// profile is where that rule stops being able to see.
    #[test]
    fn a_profile_extending_the_unbounded_built_in_writes() {
        let ours = profile("ours", Some(FULL_ACCESS), false);

        assert!(Profile::selected(&[&ours], "ours"));
    }

    /// And through a chain, since a parent is applied before its child
    /// whatever sits between them.
    #[test]
    fn a_chain_reaching_the_unbounded_built_in_writes() {
        let base = profile("base", Some(FULL_ACCESS), false);
        let ours = profile("ours", Some("base"), false);

        assert!(Profile::selected(&[&ours, &base], "ours"));
    }

    /// A chain that bottoms out at the read-only built-in writes nothing.
    #[test]
    fn a_chain_reaching_read_only_does_not_write() {
        let ours = profile("ours", Some(":read-only"), false);

        assert!(!Profile::selected(&[&ours], "ours"));
    }

    /// A file is free to write a cycle, and a scan that followed one would
    /// not finish. The answer is no, not a hang.
    #[test]
    fn a_cycle_answers_rather_than_runs() {
        let a = profile("a", Some("b"), false);
        let b = profile("b", Some("a"), false);

        assert!(!Profile::selected(&[&a, &b], "a"));
    }

    /// A profile that extends itself is the shortest cycle there is.
    #[test]
    fn a_profile_extending_itself_answers() {
        let ours = profile("ours", Some("ours"), false);

        assert!(!Profile::selected(&[&ours], "ours"));
    }

    /// A name nothing defines grants nothing, which is what a typo gets.
    #[test]
    fn an_undefined_name_grants_nothing() {
        assert!(!Profile::selected(&[], "ours"));
    }
}
