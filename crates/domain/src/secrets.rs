// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Recognising a secret by its shape, with betterleaks' rules.
//!
//! `vendor/betterleaks` holds betterleaks v1.8.1's default config and the
//! wordlist its readable-text check uses, unedited, under the MIT licence beside
//! them. betterleaks is gitleaks' successor, by the same author.
//!
//! A rule's `filter` is Expr, run with `expr-lang`. `validate` is never run: it
//! sends the credential to its issuer. A `skipReport` rule only supports
//! another rule, and is not read.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::{Mutex, OnceLock};

use aho_corasick::AhoCorasick;
use expr::{Context, Environment, Program, Value};
use indexmap::IndexMap;
use regex::{Captures, Match, Regex, RegexBuilder};
use serde::Deserialize;

const SOURCE: &str = include_str!("../vendor/betterleaks/betterleaks.toml");
const WORDS: &str = include_str!("../vendor/betterleaks/words.txt");

/// Some patterns compile past `regex`'s default size limit.
const PATTERN_LIMIT: usize = 64 << 20;

/// The functions betterleaks' filters call, each also spelt `filter.name`.
const FUNCTIONS: [&str; 7] = [
    "entropy",
    "tokenRatio",
    "containsAny",
    "matchesAny",
    "findMatch",
    "failsTokenEfficiency",
    "setConfidence",
];

/// Byte ranges of the secrets in `text`.
#[must_use]
pub fn find(text: &str) -> Vec<Range<usize>> {
    shipped().find(text)
}

#[derive(Deserialize)]
struct Config {
    filter: Option<String>,
    rules: Vec<RuleSource>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleSource {
    regex: Option<String>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    secret_group: usize,
    filter: Option<String>,
    #[serde(default)]
    skip_report: bool,
}

struct Rule {
    pattern: String,
    secret_group: usize,
    filter: Option<String>,
    /// Compiled on first use: all of them take seconds, and most never run.
    compiled: OnceLock<Option<Compiled>>,
}

struct Compiled {
    regex: Regex,
    filter: Option<Program>,
}

struct Corpus {
    rules: Vec<Rule>,
    keywords: AhoCorasick,
    /// The rule each keyword lets through.
    owner: Vec<usize>,
    /// Rules with no keyword, which read everything.
    ungated: Vec<usize>,
    /// Asked of every candidate, before its rule's own filter.
    global: Option<Program>,
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
        for rule in config.rules.into_iter().filter(|r| !r.skip_report) {
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
                secret_group: rule.secret_group,
                filter: rule.filter,
                compiled: OnceLock::new(),
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
            global: config.filter.as_deref().and_then(program),
        })
    }

    fn find(&self, text: &str) -> Vec<Range<usize>> {
        // betterleaks' order: a rule runs only where one of its keywords is.
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
            let Some(compiled) = rule.compiled() else {
                continue;
            };
            for captures in compiled.regex.captures_iter(text) {
                let (Some(whole), Some(secret)) = (captures.get(0), rule.secret(&captures)) else {
                    continue;
                };
                if self.global.is_some() || compiled.filter.is_some() {
                    let context = context(text, whole, secret);
                    if rejects(self.global.as_ref(), &context)
                        || rejects(compiled.filter.as_ref(), &context)
                    {
                        continue;
                    }
                }
                found.push(secret.range());
            }
        }
        found
    }

    #[cfg(test)]
    fn compiled_rules(&self) -> usize {
        self.rules
            .iter()
            .filter(|r| r.compiled.get().is_some())
            .count()
    }
}

impl Rule {
    fn compiled(&self) -> Option<&Compiled> {
        self.compiled
            .get_or_init(|| {
                Some(Compiled {
                    regex: pattern(&self.pattern)?,
                    filter: self.filter.as_deref().and_then(program),
                })
            })
            .as_ref()
    }

    /// The part that is secret, as betterleaks chooses it: the rule's group,
    /// else the first group that matched anything, else the whole match.
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

/// Whether a filter says a candidate is not a secret. One that fails to run
/// keeps it, as betterleaks does.
fn rejects(filter: Option<&Program>, context: &Context) -> bool {
    filter
        .is_some_and(|program| matches!(environment().run(program, context), Ok(Value::Bool(true))))
}

/// What a filter can read about a candidate. There is no path, so an exception
/// for one never applies: more is masked, not less.
fn context(text: &str, whole: Match, secret: Match) -> Context {
    let line_start = text[..whole.start()]
        .rfind(['\r', '\n'])
        .map_or(0, |at| at + 1);
    let line_end = text[whole.end()..]
        .find(['\r', '\n'])
        .map_or(text.len(), |at| whole.end() + at);

    let mut finding = IndexMap::new();
    for (key, value) in [
        ("secret", Value::from(secret.as_str())),
        ("match", Value::from(whole.as_str())),
        ("line", Value::from(&text[line_start..line_end])),
        ("fragment_raw", Value::from(text)),
        ("match_start_idx", Value::from(whole.start())),
        ("match_end_idx", Value::from(whole.end())),
        ("match_line_start_idx", Value::from(line_start)),
        ("match_line_end_idx", Value::from(line_end)),
    ] {
        finding.insert(key.to_owned(), value);
    }
    let mut attributes = IndexMap::new();
    attributes.insert("path".to_owned(), Value::from(""));

    let mut context = Context::default();
    context.insert("finding", Value::from(finding));
    context.insert("attributes", Value::from(attributes));
    context
}

/// A filter as expr-lang runs it. betterleaks reads `filter.entropy(x)` and
/// `entropy(x)` alike; expr-lang reads the first as a field of a variable.
fn program(source: &str) -> Option<Program> {
    let mut source = source.to_owned();
    for name in FUNCTIONS {
        source = source.replace(&format!("filter.{name}("), &format!("{name}("));
    }
    expr::compile(&source).ok()
}

fn environment() -> &'static Environment<'static> {
    static ENVIRONMENT: OnceLock<Environment<'static>> = OnceLock::new();
    ENVIRONMENT.get_or_init(|| {
        let mut env = Environment::new();
        env.add_function("entropy", |call| {
            Ok(Value::Float(entropy(text(call.args.first()))))
        });
        env.add_function("tokenRatio", |call| {
            Ok(Value::Float(token_ratio(text(call.args.first()))))
        });
        env.add_function("containsAny", |call| {
            let haystack = text(call.args.first());
            Ok(Value::Bool(
                texts(call.args.get(1))
                    .iter()
                    .any(|term| haystack.contains(term)),
            ))
        });
        env.add_function("matchesAny", |call| {
            let haystack = text(call.args.first());
            Ok(Value::Bool(texts(call.args.get(1)).iter().any(|source| {
                cached(source).is_some_and(|regex| regex.is_match(haystack))
            })))
        });
        env.add_function("findMatch", |call| {
            let haystack = text(call.args.first());
            let found = cached(text(call.args.get(1)))
                .and_then(|regex| regex.find(haystack).map(|m| m.as_str().to_owned()));
            Ok(Value::String(found.unwrap_or_default()))
        });
        env.add_function("failsTokenEfficiency", |call| {
            Ok(Value::Bool(reads_as_text(text(call.args.first()))))
        });
        // Confidence is for reporting, which masking does not do.
        env.add_function("setConfidence", |_| Ok(Value::Nil));
        env
    })
}

fn text(value: Option<&Value>) -> &str {
    value.and_then(Value::as_string).unwrap_or("")
}

fn texts(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().map(|v| v.as_string().unwrap_or("")).collect())
        .unwrap_or_default()
}

fn pattern(source: &str) -> Option<Regex> {
    RegexBuilder::new(&go_braces(source))
        .size_limit(PATTERN_LIMIT)
        .build()
        .ok()
}

/// A filter's pattern, compiled once however many candidates ask for it.
fn cached(source: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Mutex::default).lock().ok()?;
    cache
        .entry(source.to_owned())
        .or_insert_with(|| pattern(source))
        .clone()
}

/// Go reads a `{` that opens no valid repetition as a literal, where `regex`
/// rejects it. Escaping those gives a pattern the meaning betterleaks sees.
fn go_braces(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut escaped = false;
    for (at, c) in source.char_indices() {
        if c == '{' && !escaped && !opens_repetition(&source[at..]) {
            out.push('\\');
        }
        escaped = c == '\\' && !escaped;
        out.push(c);
    }
    out
}

/// Whether text starts `{n}`, `{n,}` or `{n,m}`.
fn opens_repetition(text: &str) -> bool {
    let Some(body) = text
        .strip_prefix('{')
        .and_then(|rest| rest.split_once('}'))
        .map(|(body, _)| body)
    else {
        return false;
    };
    let (low, high) = body.split_once(',').unwrap_or((body, ""));
    !low.is_empty()
        && low.bytes().all(|b| b.is_ascii_digit())
        && high.bytes().all(|b| b.is_ascii_digit())
}

/// Shannon entropy in bits per character.
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

/// Bytes per cl100k token. Readable text packs into few long tokens; a
/// generated secret does not.
#[allow(clippy::cast_precision_loss)] // lengths far below 2^52
fn token_ratio(text: &str) -> f64 {
    let tokens = tiktoken_rs::cl100k_base_singleton()
        .encode_ordinary(text)
        .len();
    if tokens == 0 {
        0.0
    } else {
        text.len() as f64 / tokens as f64
    }
}

/// betterleaks' check that a candidate reads as text: it holds a dictionary
/// word, or packs into tokens too well to have been generated.
fn reads_as_text(candidate: &str) -> bool {
    if candidate.is_empty() {
        return false;
    }
    if holds_word(candidate, 5) {
        return true;
    }
    let threshold = if candidate.len() < 12 && holds_word(candidate, 4) {
        2.1
    } else {
        2.5
    };
    token_ratio(candidate) >= threshold
}

/// Whether any stretch of at least `shortest` bytes is a dictionary word.
fn holds_word(candidate: &str, shortest: usize) -> bool {
    let (words, longest) = words();
    let lower = candidate.to_lowercase();
    (0..lower.len()).any(|start| {
        (shortest..=*longest)
            .filter_map(|length| lower.get(start..start + length))
            .any(|stretch| words.contains(stretch))
    })
}

fn words() -> &'static (HashSet<&'static str>, usize) {
    static WORDS_SET: OnceLock<(HashSet<&'static str>, usize)> = OnceLock::new();
    WORDS_SET.get_or_init(|| {
        let words: HashSet<&str> = WORDS.lines().filter(|w| !w.is_empty()).collect();
        let longest = words.iter().map(|w| w.len()).max().unwrap_or(0);
        (words, longest)
    })
}

// Vendored and tested, so a malformed file is a build defect, as with the
// catalogue.
#[allow(clippy::panic)]
fn shipped() -> &'static Corpus {
    static SHIPPED: OnceLock<Corpus> = OnceLock::new();
    SHIPPED.get_or_init(|| match Corpus::load(SOURCE) {
        Ok(corpus) => corpus,
        Err(error) => panic!("the vendored betterleaks config is malformed: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GITHUB_PAT: &str = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");

    fn corpus(source: &str) -> Corpus {
        Corpus::load(source).expect("the config loads")
    }

    fn found_by<'t>(corpus: &Corpus, text: &'t str) -> Vec<&'t str> {
        corpus.find(text).into_iter().map(|r| &text[r]).collect()
    }

    fn secrets_in(text: &str) -> Vec<&str> {
        found_by(shipped(), text)
    }

    /// A pattern or filter that `regex` or expr-lang cannot read would drop a
    /// rule, or its exceptions, without a word.
    #[test]
    fn every_rule_and_filter_compiles() {
        let corpus = corpus(SOURCE);
        assert!(corpus.rules.len() > 350, "{}", corpus.rules.len());
        assert!(corpus.global.is_some(), "the global filter parses");
        for rule in &corpus.rules {
            let compiled = rule.compiled();
            assert!(compiled.is_some(), "{}", rule.pattern);
            if rule.filter.is_some() {
                assert!(
                    compiled.and_then(|c| c.filter.as_ref()).is_some(),
                    "{}'s filter",
                    rule.pattern
                );
            }
        }

        let config: Config = toml::from_str(SOURCE).expect("parses");
        let literal = Regex::new(r"`([^`]*)`").expect("compiles");
        let filters = config
            .rules
            .iter()
            .filter_map(|r| r.filter.as_deref())
            .chain(config.filter.as_deref());
        for filter in filters {
            for found in literal.captures_iter(filter) {
                assert!(pattern(&found[1]).is_some(), "{}", &found[1]);
            }
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

    /// AWS's rule rejects a low-entropy key and AWS's documented example.
    #[test]
    fn a_match_its_filter_rejects_is_not_a_secret() {
        assert!(find(&format!("AKIA{}", "A".repeat(16))).is_empty());
        assert!(find(concat!("AKIA", "IOSFODNN7EXAMPLE")).is_empty());

        let issued = concat!("AKIA", "Q7ZK3M2XW5RT6PLN");
        assert_eq!(secrets_in(issued), [issued]);
    }

    #[test]
    fn the_keyword_gate_ignores_case() {
        assert!(!find(r#"API_KEY = "q8Z3vW1xY7tR4uP0mK2n""#).is_empty());
    }

    #[test]
    fn a_rule_runs_only_where_its_keyword_is() {
        let corpus = corpus(SOURCE);

        assert!(corpus.find("Indent with tabs").is_empty());
        assert_eq!(corpus.compiled_rules(), 0);
    }

    #[test]
    fn a_rule_without_keywords_reads_everything() {
        let corpus = corpus("[[rules]]\nregex = 'tok_[a-z]{4}'\n");

        assert_eq!(found_by(&corpus, "x tok_abcd y"), ["tok_abcd"]);
    }

    #[test]
    fn the_rules_own_group_is_the_secret_over_an_earlier_one() {
        let corpus =
            corpus("[[rules]]\nregex = '(id)=(\\w+)'\nsecretGroup = 2\nkeywords = ['id']\n");

        assert_eq!(found_by(&corpus, "id=s3cr3t"), ["s3cr3t"]);
    }

    #[test]
    fn a_dotted_filter_call_reaches_its_function() {
        let corpus = corpus(
            "[[rules]]\nregex = 'tok_\\w+'\nkeywords = ['tok_']\n\
             filter = 'filter.entropy(finding[\"secret\"]) <= 2.0'\n",
        );

        assert_eq!(found_by(&corpus, "tok_aaaa tok_q8Z3vW1x"), ["tok_q8Z3vW1x"]);
    }

    #[test]
    fn the_global_filter_is_asked_of_every_rule() {
        let corpus = corpus(
            "filter = 'finding[\"secret\"] == \"tok_drop\"'\n\
             [[rules]]\nregex = 'tok_\\w+'\nkeywords = ['tok_']\n",
        );

        assert_eq!(found_by(&corpus, "tok_drop tok_keep"), ["tok_keep"]);
    }

    #[test]
    fn a_filter_that_fails_to_run_keeps_the_match() {
        let corpus =
            corpus("[[rules]]\nregex = 'tok_\\w+'\nkeywords = ['tok_']\nfilter = 'nosuch > 1'\n");

        assert_eq!(found_by(&corpus, "tok_keep"), ["tok_keep"]);
    }

    #[test]
    fn a_rule_that_only_supports_another_is_not_read() {
        let corpus =
            corpus("[[rules]]\nregex = 'tok_\\w+'\nkeywords = ['tok_']\nskipReport = true\n");

        assert!(corpus.find("tok_keep").is_empty());
    }

    #[test]
    fn a_brace_opening_no_repetition_is_a_literal() {
        let placeholder = pattern(r"^\${(?:[A-Z_]+)}$").expect("compiles");
        assert!(placeholder.is_match("${API_KEY}"));

        let template = pattern(r"^{{[^}]+}}$").expect("compiles");
        assert!(template.is_match("{{ name }}"));

        let repeated = pattern(r"^a{2}$").expect("compiles");
        assert!(repeated.is_match("aa") && !repeated.is_match("a{2}"));

        let escaped = pattern(r"^\{x}$").expect("compiles");
        assert!(escaped.is_match("{x}"));
    }

    #[test]
    fn token_ratio_is_bytes_per_token() {
        assert!((token_ratio("Hello World") - 5.5).abs() < 1e-9);
        assert!(token_ratio("q8Z3vW1xY7tR4uP0mK2n") < 1.5);
    }

    #[test]
    fn a_dictionary_word_reads_as_text_however_it_tokenises() {
        assert!(reads_as_text("xQ7zhorseK9vW2"));
        assert!(!reads_as_text("q8Z3vW1xY7tR4uP0mK2n"));
    }

    /// Both pack 2.33 bytes into a token. Under 12 bytes, a four-letter word
    /// lowers the bar from 2.5 to 2.1.
    #[test]
    fn a_short_candidate_with_a_short_word_reads_as_text_sooner() {
        assert!(reads_as_text("abedxxx"));
        assert!(!reads_as_text("gtejaeb"));
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
