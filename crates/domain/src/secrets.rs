// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Recognising a secret by its shape, with gitleaks' rules.
//!
//! `vendor/gitleaks/gitleaks.toml` is gitleaks v8.30.1's default config,
//! unedited, under the MIT licence beside it. Allowlists are not read: they
//! keep a scanner from reporting too much, and masking too much costs only a
//! few characters of evidence.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use regex::{Captures, Match, Regex, RegexBuilder};
use serde::Deserialize;

const SOURCE: &str = include_str!("../vendor/gitleaks/gitleaks.toml");

/// Some gitleaks patterns compile past `regex`'s default size limit.
const PATTERN_LIMIT: usize = 64 << 20;

/// Byte ranges of the secrets in `text`.
#[must_use]
pub fn find(text: &str) -> Vec<Range<usize>> {
    shipped().find(text)
}

#[derive(Deserialize)]
struct Config {
    rules: Vec<RuleSource>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleSource {
    regex: Option<String>,
    #[serde(default)]
    keywords: Vec<String>,
    entropy: Option<f64>,
    #[serde(default)]
    secret_group: usize,
}

struct Rule {
    pattern: String,
    entropy: Option<f64>,
    secret_group: usize,
    /// Compiled on first use: all of them take seconds, and most never run.
    regex: OnceLock<Option<Regex>>,
}

struct Corpus {
    rules: Vec<Rule>,
    keywords: AhoCorasick,
    /// The rule each keyword lets through.
    owner: Vec<usize>,
    /// Rules with no keyword, which read everything.
    ungated: Vec<usize>,
}

#[derive(Debug, thiserror::Error)]
enum LoadError {
    #[error("{0}")]
    Config(#[from] toml::de::Error),
    #[error("{0}")]
    Keywords(#[from] aho_corasick::BuildError),
}

impl Corpus {
    fn load(source: &str) -> Result<Self, LoadError> {
        let config: Config = toml::from_str(source)?;
        let (mut rules, mut keywords, mut owner, mut ungated) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        // A rule with no pattern matches file paths, which masking has no use for.
        for rule in config.rules {
            let Some(pattern) = rule.regex else {
                continue;
            };
            if rule.keywords.is_empty() {
                ungated.push(rules.len());
            }
            for keyword in rule.keywords {
                keywords.push(keyword);
                owner.push(rules.len());
            }
            rules.push(Rule {
                pattern,
                entropy: rule.entropy,
                secret_group: rule.secret_group,
                regex: OnceLock::new(),
            });
        }
        let keywords = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&keywords)?;
        Ok(Self {
            rules,
            keywords,
            owner,
            ungated,
        })
    }

    fn find(&self, text: &str) -> Vec<Range<usize>> {
        // gitleaks' order: a rule runs only where one of its keywords is.
        let mut gated: Vec<usize> = self
            .keywords
            .find_overlapping_iter(text)
            .map(|m| self.owner[m.pattern().as_usize()])
            .collect();
        gated.extend(&self.ungated);
        gated.sort_unstable();
        gated.dedup();

        let mut found = Vec::new();
        for rule in gated.into_iter().map(|at| &self.rules[at]) {
            let Some(regex) = rule.regex() else {
                continue;
            };
            for captures in regex.captures_iter(text) {
                let Some(secret) = rule.secret(&captures) else {
                    continue;
                };
                if rule
                    .entropy
                    .is_some_and(|floor| entropy(secret.as_str()) <= floor)
                {
                    continue;
                }
                found.push(secret.range());
            }
        }
        found
    }

    #[cfg(test)]
    fn compiled(&self) -> usize {
        self.rules
            .iter()
            .filter(|r| r.regex.get().is_some())
            .count()
    }
}

impl Rule {
    fn regex(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| {
                RegexBuilder::new(&self.pattern)
                    .size_limit(PATTERN_LIMIT)
                    .build()
                    .ok()
            })
            .as_ref()
    }

    /// The part that is secret, as gitleaks chooses it: the rule's group, else
    /// the first group that matched anything, else the whole match.
    fn secret<'t>(&self, captures: &Captures<'t>) -> Option<Match<'t>> {
        if self.secret_group > 0 {
            return captures.get(self.secret_group);
        }
        captures
            .iter()
            .skip(1)
            .flatten()
            .find(|m| !m.is_empty())
            .or_else(|| captures.get(0))
    }
}

/// Shannon entropy in bits per character, as gitleaks measures it.
#[allow(clippy::cast_precision_loss)] // counts far below 2^52
fn entropy(text: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in text.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let length = text.chars().count() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / length;
            -p * p.log2()
        })
        .sum()
}

// Vendored and tested, so a malformed file is a build defect, as with the
// catalogue.
#[allow(clippy::panic)]
fn shipped() -> &'static Corpus {
    static SHIPPED: OnceLock<Corpus> = OnceLock::new();
    SHIPPED.get_or_init(|| match Corpus::load(SOURCE) {
        Ok(corpus) => corpus,
        Err(error) => panic!("the vendored gitleaks config is malformed: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GITHUB_PAT: &str = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");

    fn found_by<'t>(corpus: &Corpus, text: &'t str) -> Vec<&'t str> {
        corpus.find(text).into_iter().map(|r| &text[r]).collect()
    }

    fn secrets_in(text: &str) -> Vec<&str> {
        found_by(shipped(), text)
    }

    #[test]
    fn every_rule_compiles() {
        let corpus = Corpus::load(SOURCE).expect("the vendored config loads");

        assert!(corpus.rules.len() > 200, "{}", corpus.rules.len());
        for rule in &corpus.rules {
            assert!(rule.regex().is_some(), "{}", rule.pattern);
        }
    }

    #[test]
    fn an_issued_token_is_found() {
        let text = format!("export GH={GITHUB_PAT} now");

        assert_eq!(secrets_in(&text), [GITHUB_PAT]);
    }

    /// The key names the secret and is not part of it.
    #[test]
    fn only_the_secret_group_is_the_secret() {
        let found = secrets_in(r#"api_key = "q8Z3vW1xY7tR4uP0mK2n""#);

        assert!(!found.is_empty());
        assert!(
            found.iter().all(|s| *s == "q8Z3vW1xY7tR4uP0mK2n"),
            "{found:?}"
        );
    }

    #[test]
    fn a_shape_below_its_entropy_floor_is_not_a_secret() {
        assert!(find(&format!("AKIA{}", "A".repeat(16))).is_empty());

        let issued = concat!("AKIA", "Q7ZK3M2XW5RT6PLN");
        assert_eq!(secrets_in(issued), [issued]);
    }

    #[test]
    fn the_keyword_gate_ignores_case() {
        assert!(!find(r#"API_KEY = "q8Z3vW1xY7tR4uP0mK2n""#).is_empty());
    }

    #[test]
    fn a_rule_runs_only_where_its_keyword_is() {
        let corpus = Corpus::load(SOURCE).expect("the vendored config loads");

        assert!(corpus.find("Indent with tabs").is_empty());
        assert_eq!(corpus.compiled(), 0);
    }

    #[test]
    fn a_rule_without_keywords_reads_everything() {
        let corpus = Corpus::load("[[rules]]\nregex = 'tok_[a-z]{4}'\n").expect("loads");

        assert_eq!(found_by(&corpus, "x tok_abcd y"), ["tok_abcd"]);
    }

    #[test]
    fn the_rules_own_group_is_the_secret_over_an_earlier_one() {
        let corpus =
            Corpus::load("[[rules]]\nregex = '(id)=(\\w+)'\nsecretGroup = 2\nkeywords = ['id']\n")
                .expect("loads");

        assert_eq!(found_by(&corpus, "id=s3cr3t"), ["s3cr3t"]);
    }

    #[test]
    fn ordinary_text_holds_no_secret() {
        for text in [
            "# Rules\n\nUse the shared config.",
            "npx -y @modelcontextprotocol/server-postgres@latest",
            "keep the token cache warm",
        ] {
            assert!(find(text).is_empty(), "{text}: {:?}", secrets_in(text));
        }
    }
}
