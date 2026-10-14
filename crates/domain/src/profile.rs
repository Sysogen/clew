// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A named permissions profile, which is how Codex writes a sandbox apart
//! from the file that selects it.

use std::collections::{BTreeMap, BTreeSet};

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
    /// Its filesystem rules as written: what each path is given.
    pub filesystem: BTreeMap<String, Access>,
}

/// What a filesystem rule gives a path.
///
/// The reference gives a path a grant or a table of rules of its own, and
/// `:workspace_roots` always holds a table. What a child profile or a nearer
/// layer writes at a path replaces what sat there, whole: a grant over a
/// table takes the table away, and a table over a table is overlaid rule by
/// rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    /// A grant, as the file wrote it: `"read"`, `"write"`, or another word.
    Granted(String),
    /// A table of rules under the path.
    Nested(BTreeMap<String, Access>),
    /// Neither, such as the glob depth, which sits beside the grants as a
    /// number.
    Other,
}

/// Whether any rule in a table grants a write.
fn writes(rules: &BTreeMap<String, Access>) -> bool {
    rules.values().any(|given| match given {
        Access::Granted(grant) => grant == "write",
        Access::Nested(under) => writes(under),
        Access::Other => false,
    })
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
    /// Resolved the way the reference applies profiles. A nearer layer
    /// overlays a farther one rule by rule rather than replacing its table,
    /// and `extends` applies a parent before the profile itself the same way,
    /// so what a child or a nearer file says at a path is what holds there
    /// and what it says nothing about is left as it was. A child setting its
    /// parent's write back to read has no write, and one overriding another
    /// path keeps it. The chain is walked rather than assumed one deep, and
    /// a profile is visited once: a file is free to write a cycle, and a
    /// scan that followed it would never answer.
    ///
    /// `defined` is nearest first, which is the order the rule gathers the
    /// layers in. A built-in that writes ends the walk: its rules are not in
    /// the file, so nothing in the file is read as overriding them.
    #[must_use]
    pub fn selected(defined: &[&Self], selected: &str) -> bool {
        // The farthest layer laid down first and each nearer one over it.
        let mut by_name: BTreeMap<&str, Self> = BTreeMap::new();
        for held in defined.iter().rev() {
            by_name
                .entry(held.name.as_str())
                .and_modify(|under| under.overlay(held))
                .or_insert_with(|| (*held).clone());
        }

        let mut chain: Vec<&Self> = Vec::new();
        let mut name = selected;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        loop {
            if name == WORKSPACE || name == FULL_ACCESS {
                return true;
            }
            if !seen.insert(name) {
                break;
            }
            let Some(held) = by_name.get(name) else {
                break;
            };
            chain.push(held);
            let Some(parent) = held.extends.as_deref() else {
                break;
            };
            name = parent;
        }

        // Root first and the selected profile last, each over what came
        // before.
        let mut effective: BTreeMap<String, Access> = BTreeMap::new();
        for held in chain.iter().rev() {
            overlaid(&mut effective, &held.filesystem);
        }
        writes(&effective)
    }

    /// `over` laid on this profile: its parent where `over` names one, and
    /// its rules overlaid.
    fn overlay(&mut self, over: &Self) {
        if over.extends.is_some() {
            self.extends.clone_from(&over.extends);
        }
        overlaid(&mut self.filesystem, &over.filesystem);
    }
}

/// `over` laid on `under`, rule by rule. A table over a table is overlaid
/// the same way, and anything else replaces what sat at the path, whole.
fn overlaid(under: &mut BTreeMap<String, Access>, over: &BTreeMap<String, Access>) {
    for (path, given) in over {
        match (under.get_mut(path), given) {
            (Some(Access::Nested(beneath)), Access::Nested(laid)) => overlaid(beneath, laid),
            _ => {
                under.insert(path.clone(), given.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A profile granting `rules`, each a path and the word the file gave it.
    fn profile(name: &str, extends: Option<&str>, rules: &[(&str, &str)]) -> Profile {
        Profile {
            name: name.to_owned(),
            extends: extends.map(str::to_owned),
            filesystem: granted(rules),
        }
    }

    fn granted(rules: &[(&str, &str)]) -> BTreeMap<String, Access> {
        rules
            .iter()
            .map(|(path, grant)| ((*path).to_owned(), Access::Granted((*grant).to_owned())))
            .collect()
    }

    /// A child setting a parent's path back to read takes that write away:
    /// the reference applies the parent and then the child, rule by rule, and
    /// a scan reading the parent's grant on its own would report a write the
    /// agent does not have.
    #[test]
    fn a_child_overriding_a_parents_write_does_not_write() {
        let base = profile("base", None, &[("/srv", "write")]);
        let ours = profile("ours", Some("base"), &[("/srv", "read")]);

        assert!(!Profile::selected(&[&ours, &base], "ours"));
    }

    /// And a child saying nothing about a path leaves the parent's grant
    /// there: overriding one path is not replacing the table.
    #[test]
    fn a_child_keeps_a_parents_write_it_does_not_mention() {
        let base = profile("base", None, &[("/srv", "write")]);
        let ours = profile("ours", Some("base"), &[("/tmp", "read")]);

        assert!(Profile::selected(&[&ours, &base], "ours"));
    }

    /// A grant written over a table replaces the table whole, so a child
    /// turning `:workspace_roots` to read leaves nothing writable beneath it.
    #[test]
    fn a_grant_over_a_table_takes_the_table_away() {
        let base = Profile {
            name: "base".to_owned(),
            extends: None,
            filesystem: BTreeMap::from([(
                ":workspace_roots".to_owned(),
                Access::Nested(granted(&[(".", "write")])),
            )]),
        };
        let ours = profile("ours", Some("base"), &[(":workspace_roots", "read")]);

        assert!(!Profile::selected(&[&ours, &base], "ours"));
    }

    /// A table over a table is overlaid rule by rule, so a child adding a
    /// read beneath `:workspace_roots` leaves the parent's write there, and
    /// one setting the same path back to read takes it away.
    #[test]
    fn a_table_over_a_table_is_overlaid_rule_by_rule() {
        let roots = |rules: &[(&str, &str)]| {
            BTreeMap::from([(
                ":workspace_roots".to_owned(),
                Access::Nested(granted(rules)),
            )])
        };
        let base = Profile {
            name: "base".to_owned(),
            extends: None,
            filesystem: roots(&[(".", "write")]),
        };
        let beside = Profile {
            name: "ours".to_owned(),
            extends: Some("base".to_owned()),
            filesystem: roots(&[("sub", "read")]),
        };
        let same = Profile {
            name: "ours".to_owned(),
            extends: Some("base".to_owned()),
            filesystem: roots(&[(".", "read")]),
        };

        assert!(Profile::selected(&[&beside, &base], "ours"));
        assert!(!Profile::selected(&[&same, &base], "ours"));
    }

    /// Layers overlay the same way, nearest over farthest: a nearer file
    /// setting one path to read leaves the farther file's other write, and
    /// one setting both to read leaves none. `defined` is nearest first, as
    /// the rule gathers it.
    #[test]
    fn a_nearer_layer_overlays_a_farther_one() {
        let root = profile("ours", None, &[("/srv", "write"), ("/data", "write")]);
        let one = profile("ours", None, &[("/srv", "read")]);
        let both = profile("ours", None, &[("/srv", "read"), ("/data", "read")]);

        assert!(Profile::selected(&[&one, &root], "ours"));
        assert!(!Profile::selected(&[&both, &root], "ours"));
    }

    /// `extends` is a key like any other: the nearer layer's wins where it
    /// names one, and a nearer layer naming none keeps the farther one's.
    #[test]
    fn a_nearer_layer_keeps_the_parent_it_does_not_name() {
        let root = profile("ours", Some(WORKSPACE), &[]);
        let silent = profile("ours", None, &[]);
        let bounded = profile("ours", Some(":read-only"), &[]);

        assert!(Profile::selected(&[&silent, &root], "ours"));
        assert!(!Profile::selected(&[&bounded, &root], "ours"));
    }

    #[test]
    fn the_built_in_that_writes_writes() {
        assert!(Profile::selected(&[], WORKSPACE));
    }

    #[test]
    fn a_profile_granting_a_write_writes() {
        let ours = profile("ours", None, &[("/srv", "write")]);

        assert!(Profile::selected(&[&ours], "ours"));
    }

    #[test]
    fn a_profile_granting_nothing_does_not() {
        let ours = profile("ours", None, &[]);

        assert!(!Profile::selected(&[&ours], "ours"));
    }

    /// `extends` applies a parent first, so what the parent grants is in
    /// force whatever the profile itself says.
    #[test]
    fn a_profile_extending_one_that_writes_writes() {
        let ours = profile("ours", Some(WORKSPACE), &[]);

        assert!(Profile::selected(&[&ours], "ours"));
    }

    /// And through a chain, which the reference allows by letting a profile
    /// extend another named one.
    #[test]
    fn a_chain_reaching_a_write_writes() {
        let base = profile("base", None, &[("/srv", "write")]);
        let middle = profile("middle", Some("base"), &[]);
        let ours = profile("ours", Some("middle"), &[]);

        assert!(Profile::selected(&[&ours, &middle, &base], "ours"));
    }

    /// A profile extending the built-in that bounds nothing writes, and
    /// nothing else would say so: `bypass-permissions` reads the key that
    /// selected the profile, which says `ours` rather than the parent, so a
    /// profile is where that rule stops being able to see.
    #[test]
    fn a_profile_extending_the_unbounded_built_in_writes() {
        let ours = profile("ours", Some(FULL_ACCESS), &[]);

        assert!(Profile::selected(&[&ours], "ours"));
    }

    /// And through a chain, since a parent is applied before its child
    /// whatever sits between them.
    #[test]
    fn a_chain_reaching_the_unbounded_built_in_writes() {
        let base = profile("base", Some(FULL_ACCESS), &[]);
        let ours = profile("ours", Some("base"), &[]);

        assert!(Profile::selected(&[&ours, &base], "ours"));
    }

    /// A chain that bottoms out at the read-only built-in writes nothing.
    #[test]
    fn a_chain_reaching_read_only_does_not_write() {
        let ours = profile("ours", Some(":read-only"), &[]);

        assert!(!Profile::selected(&[&ours], "ours"));
    }

    /// A file is free to write a cycle, and a scan that followed one would
    /// not finish. The answer is no, not a hang.
    #[test]
    fn a_cycle_answers_rather_than_runs() {
        let a = profile("a", Some("b"), &[]);
        let b = profile("b", Some("a"), &[]);

        assert!(!Profile::selected(&[&a, &b], "a"));
    }

    /// A profile that extends itself is the shortest cycle there is.
    #[test]
    fn a_profile_extending_itself_answers() {
        let ours = profile("ours", Some("ours"), &[]);

        assert!(!Profile::selected(&[&ours], "ours"));
    }

    /// A name nothing defines grants nothing, which is what a typo gets.
    #[test]
    fn an_undefined_name_grants_nothing() {
        assert!(!Profile::selected(&[], "ours"));
    }
}
