// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What each rule means, and what to do about it.
//!
//! Beside the model rather than in whichever adapter prints it: the same words
//! reach a code scanning alert, a terminal and a documentation page, and four
//! copies of a sentence is how one rule comes to mean three things.

use crate::finding::RuleId;

/// The rule pack, as a number a finding can be cited against.
///
/// Raised when a rule is added or removed, an id changes meaning, or a severity
/// changes. Not for a wording change, which leaves every finding the same. It
/// names the set, not the logic inside a rule: see CONTRIBUTING.
pub const RULE_PACK_VERSION: u32 = 1;

impl RuleId {
    /// Every rule, in the order a listing shows them.
    ///
    /// Rust cannot enumerate a fieldless enum without a macro or a crate, so
    /// this is written out and `all_lists_every_rule` keeps it honest: a new
    /// variant fails that test's match to compile.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::InvisibleUnicode,
            Self::OpaqueHook,
            Self::DownloadAndExecute,
            Self::DecodeAndExecute,
            Self::CredentialExfiltration,
            Self::UnverifiedDownload,
            Self::UnpinnedRemotePackage,
            Self::BypassPermissions,
            Self::UnrestrictedShell,
            Self::TrustedServer,
        ]
    }

    /// What the rule means, and the incident behind it.
    #[must_use]
    pub fn detail(self) -> &'static str {
        crate::rule::of(self).detail()
    }

    /// Where the rule is written up, for a finding to cite.
    ///
    /// Names `main`, so a log kept for a year links to what the page says
    /// later. Pinning it to the release is deferred, not dismissed.
    #[must_use]
    pub fn page(self) -> String {
        format!(
            "{}/blob/main/docs/rules/{}.md",
            env!("CARGO_PKG_REPOSITORY"),
            self.as_str()
        )
    }

    /// What to do about a finding under the rule.
    #[must_use]
    pub fn remediation(self) -> &'static str {
        crate::rule::of(self).remediation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new variant fails this match to compile, which is the reminder to add
    /// it to `all()`; the count then fails until it is there.
    #[test]
    fn all_lists_every_rule() {
        for rule in RuleId::all() {
            match rule {
                RuleId::InvisibleUnicode
                | RuleId::OpaqueHook
                | RuleId::DownloadAndExecute
                | RuleId::DecodeAndExecute
                | RuleId::CredentialExfiltration
                | RuleId::UnverifiedDownload
                | RuleId::UnpinnedRemotePackage
                | RuleId::BypassPermissions
                | RuleId::UnrestrictedShell
                | RuleId::TrustedServer => {}
            }
        }

        assert_eq!(RuleId::all().len(), 10, "{:?}", RuleId::all());
    }

    #[test]
    fn every_rule_says_what_it_means_and_what_to_do() {
        for rule in RuleId::all() {
            assert!(rule.detail().len() > 80, "{rule:?} has no detail");
            assert!(rule.remediation().len() > 80, "{rule:?} has no remediation");
        }
    }

    /// The set, pinned. A rule added, removed, or re-graded shows up here in
    /// review rather than only in a diff of match arms, and PR 2 hangs the
    /// rule pack version off this file.
    #[test]
    fn the_rule_pack_matches_its_snapshot() {
        let snapshot = include_str!("../rule-pack.snapshot");
        let pinned: Vec<&str> = snapshot
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect();

        let mut held = vec![format!("version {RULE_PACK_VERSION}")];
        held.extend(
            RuleId::all()
                .iter()
                .map(|r| format!("{} {}", r.as_str(), r.severity().as_str())),
        );

        assert_eq!(
            pinned,
            held.iter().map(String::as_str).collect::<Vec<_>>(),
            "the rule pack changed; update rule-pack.snapshot and raise \
             RULE_PACK_VERSION if what a scan finds changed"
        );
    }

    #[test]
    fn a_page_is_named_for_the_rule() {
        for rule in RuleId::all() {
            let page = rule.page();
            assert!(page.starts_with("https://"), "{page}");
            assert!(page.ends_with(&format!("/{}.md", rule.as_str())), "{page}");
        }
    }

    /// Every id `all` holds reads back, so `explain` can take one.
    #[test]
    fn every_listed_rule_reads_back_from_its_id() {
        for rule in RuleId::all() {
            assert_eq!(RuleId::from_catalogue(rule.as_str()), Some(*rule));
        }
    }

    /// An id is a promise, so a listing may not hold one twice.
    #[test]
    fn no_rule_is_listed_twice() {
        let mut ids: Vec<&str> = RuleId::all().iter().map(|r| r.as_str()).collect();
        ids.sort_unstable();
        let listed = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), listed, "{ids:?}");
    }
}
