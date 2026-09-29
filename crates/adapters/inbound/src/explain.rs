// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The rule pack, for a person to read and for a tool to parse.

use std::fmt::Write as _;

use clew_domain::finding::RuleId;
use clew_domain::pack;
use serde::Serialize;

/// One rule, as a machine reads it.
#[derive(Serialize)]
pub struct RuleOut {
    id: &'static str,
    pack: Option<PackOut>,
    severity: &'static str,
    description: &'static str,
    detail: &'static str,
    remediation: &'static str,
    page: String,
}

impl RuleOut {
    fn of(id: RuleId) -> Self {
        Self {
            id: id.as_str(),
            pack: PackOut::of(id),
            severity: id.severity().as_str(),
            description: id.description(),
            detail: id.detail(),
            remediation: id.remediation(),
            page: id.page(),
        }
    }
}

/// A pack, as a report names it: what judged, and at which version.
///
/// Owned, so a document reads back as it was written. Built once per report,
/// not per finding.
#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
pub struct PackOut {
    name: String,
    version: u32,
}

impl PackOut {
    /// Every pack clew ships.
    #[must_use]
    pub fn shipped() -> Vec<Self> {
        pack::shipped()
            .iter()
            .map(|held| Self {
                name: held.name.to_owned(),
                version: held.version,
            })
            .collect()
    }

    fn of(id: RuleId) -> Option<Self> {
        pack::of(id).map(|held| Self {
            name: held.name.to_owned(),
            version: held.version,
        })
    }
}

/// Every pack, and every rule in them.
#[derive(Serialize)]
struct RulesOut {
    packs: Vec<PackOut>,
    rules: Vec<RuleOut>,
}

/// Every rule, as an aligned listing, a pack at a time.
#[must_use]
pub fn rules() -> String {
    let width = RuleId::all()
        .iter()
        .map(|r| r.as_str().len())
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for pack in pack::shipped() {
        let _ = writeln!(out, "{} {}\n", pack.name, pack.version);
        for rule in pack.rules {
            let _ = writeln!(
                out,
                "  {:<width$}  {:<6}  {}",
                rule.name(),
                rule.severity().as_str(),
                rule.description()
            );
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "{} rule(s) in {} pack(s).",
        RuleId::all().len(),
        pack::shipped().len()
    );
    out
}

/// Every rule as one document, so a study can record what judged.
///
/// # Errors
///
/// Only when serialisation fails.
pub fn rules_json() -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&RulesOut {
        packs: PackOut::shipped(),
        rules: RuleId::all().iter().copied().map(RuleOut::of).collect(),
    })
}

/// One rule, at length.
#[must_use]
pub fn explain(id: RuleId) -> String {
    format!(
        "{}  {}  {}\n\n{}\n\n{}\n\nWhat to do\n\n{}\n\n{}\n",
        id.as_str(),
        id.severity().as_str(),
        pack::of(id).map_or_else(String::new, |held| format!(
            "({} {})",
            held.name, held.version
        )),
        id.description(),
        id.detail(),
        id.remediation(),
        id.page()
    )
}

/// One rule as a document, naming the pack that judged it and its version.
///
/// # Errors
///
/// Only when serialisation fails.
pub fn explain_json(id: RuleId) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&RuleOut::of(id))
}

/// What to say when a rule id names nothing.
#[must_use]
pub fn no_such_rule(id: &str) -> String {
    let known: Vec<&str> = RuleId::all().iter().map(|r| r.as_str()).collect();
    format!(
        "no such rule '{id}'. Known rules:\n  {}",
        known.join("\n  ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_holds_every_rule_under_its_pack() {
        let said = rules();

        for rule in RuleId::all() {
            assert!(said.contains(rule.as_str()), "{} missing", rule.as_str());
        }
        for held in pack::shipped() {
            assert!(
                said.contains(&format!("{} {}", held.name, held.version)),
                "{said}"
            );
        }
        assert!(said.contains("1 pack(s)"), "{said}");
    }

    #[test]
    fn a_document_names_the_pack_a_rule_belongs_to() {
        let written = explain_json(RuleId::TrustedServer).expect("serialises");
        let rule: serde_json::Value = serde_json::from_str(&written).expect("parses");

        assert_eq!(rule["pack"]["name"], "core");
        assert_eq!(rule["pack"]["version"], clew_domain::pack::CORE.version);
    }

    #[test]
    fn an_explanation_says_what_it_means_and_what_to_do() {
        for rule in RuleId::all() {
            let said = explain(*rule);

            assert!(said.contains(rule.as_str()), "{said}");
            assert!(said.contains(rule.severity().as_str()), "{said}");
            assert!(said.contains(rule.detail()), "{said}");
            assert!(said.contains(rule.remediation()), "{said}");
            assert!(said.contains(&rule.page()), "{said}");
        }
    }

    #[test]
    fn a_document_carries_the_pack_and_every_rule() {
        let written = rules_json().expect("serialises");
        let pack: serde_json::Value = serde_json::from_str(&written).expect("parses");

        assert_eq!(pack["packs"][0]["name"], "core");
        assert_eq!(pack["packs"][0]["version"], clew_domain::pack::CORE.version);
        let listed = pack["rules"].as_array().expect("an array");
        assert_eq!(listed.len(), RuleId::all().len());
        assert_eq!(listed[0]["id"], RuleId::all()[0].as_str());
        assert_eq!(listed[0]["page"], RuleId::all()[0].page());
    }

    #[test]
    fn one_rule_reads_back_as_a_document() {
        let written = explain_json(RuleId::TrustedServer).expect("serialises");
        let rule: serde_json::Value = serde_json::from_str(&written).expect("parses");

        assert_eq!(rule["pack"]["name"], "core");
        assert_eq!(rule["id"], "trusted-server");
        assert_eq!(rule["severity"], "medium");
        assert_eq!(rule["remediation"], RuleId::TrustedServer.remediation());
    }

    /// An id is a promise, so a near miss is refused rather than guessed at.
    #[test]
    fn an_unknown_rule_is_answered_with_the_known_ones() {
        let said = no_such_rule("trusted-servers");

        assert!(said.contains("no such rule 'trusted-servers'"), "{said}");
        for rule in RuleId::all() {
            assert!(said.contains(rule.as_str()), "{said}");
        }
    }
}
