// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A rule pack: a named set of rules, versioned on its own.
//!
//! One pack ships today. A second is a second [`Pack`] and a line in
//! [`shipped`], which is what lets a set of rules be added and cited without
//! renumbering the rules already there.

use crate::finding::RuleId;
use crate::rule::Rule;
use crate::rules::{
    auto_run_task, bypass_permissions, credential_exfiltration, decode_and_execute,
    download_and_execute, invisible_unicode, opaque_hook, plaintext_transport, trusted_server,
    unpinned_remote_package, unrestricted_shell, unverified_download,
};

/// A named set of rules, with a version of its own.
///
/// The version is what a finding is cited against. It covers this pack alone,
/// so adding a rule to one pack leaves another's number, and the runs that
/// named it, alone.
/// Not `Debug` or `PartialEq`: a trait object is neither, and a pack is
/// compared by its name.
#[derive(Clone, Copy)]
pub struct Pack {
    /// What it is called, in a report and on the command line.
    pub name: &'static str,
    /// Raised when this pack's rules change: one added or removed, an id
    /// changing meaning, or a severity changing.
    pub version: u32,
    /// Its rules, in the order a listing shows them.
    pub rules: &'static [&'static dyn Rule],
}

/// The rules clew was built around: everything it judges today.
pub const CORE: Pack = Pack {
    name: "core",
    version: 3,
    rules: &[
        &invisible_unicode::InvisibleUnicode,
        &opaque_hook::OpaqueHook,
        &download_and_execute::DownloadAndExecute,
        &decode_and_execute::DecodeAndExecute,
        &credential_exfiltration::CredentialExfiltration,
        &unverified_download::UnverifiedDownload,
        &unpinned_remote_package::UnpinnedRemotePackage,
        &bypass_permissions::BypassPermissions,
        &unrestricted_shell::UnrestrictedShell,
        &trusted_server::TrustedServer,
        &plaintext_transport::PlaintextTransport,
        &auto_run_task::AutoRunTask,
    ],
};

/// Every pack clew ships.
#[must_use]
pub fn shipped() -> &'static [&'static Pack] {
    &[&CORE]
}

/// The pack a rule belongs to.
///
/// `None` only for a rule in no pack, which is a wiring mistake
/// `every_rule_belongs_to_one_pack` refuses.
#[must_use]
pub fn of(id: RuleId) -> Option<&'static Pack> {
    shipped()
        .iter()
        .copied()
        .find(|pack| pack.rules.iter().any(|rule| rule.id() == id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule in no pack is never run; a rule in two makes a citation
    /// ambiguous.
    ///
    /// Walks `RuleId::all`, not `rule::shipped`: the latter is built from the
    /// packs, so a rule dropped from one would simply not appear and this
    /// would pass.
    #[test]
    fn every_rule_belongs_to_one_pack() {
        for id in RuleId::all() {
            let holding: Vec<&str> = shipped()
                .iter()
                .filter(|pack| pack.rules.iter().any(|held| held.id() == *id))
                .map(|pack| pack.name)
                .collect();

            assert_eq!(holding.len(), 1, "{} is in {holding:?}", id.as_str());
        }
    }

    #[test]
    fn a_pack_holds_the_rules_it_says_it_does() {
        for pack in shipped() {
            for rule in pack.rules {
                assert_eq!(of(rule.id()).map(|p| p.name), Some(pack.name));
            }
        }
    }

    #[test]
    fn no_two_packs_share_a_name() {
        let mut names: Vec<&str> = shipped().iter().map(|pack| pack.name).collect();
        names.sort_unstable();
        let listed = names.len();
        names.dedup();
        assert_eq!(names.len(), listed, "{names:?}");
    }

    /// The order a listing shows is the order the packs hold, so a report and
    /// `clew rules` agree.
    #[test]
    fn the_packs_hold_every_rule_in_listing_order() {
        let held: Vec<RuleId> = shipped()
            .iter()
            .flat_map(|pack| pack.rules.iter().map(|rule| rule.id()))
            .collect();

        assert_eq!(held, RuleId::all());
    }
}
