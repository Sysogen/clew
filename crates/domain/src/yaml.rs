// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Reading YAML, and keeping where each value was written.
//!
//! The high-level loader gives a tree with no positions in it, so a finding in
//! a YAML file had to be placed by searching the text for the value again.
//! That is wrong whenever the same text appears twice: two jobs opening on the
//! same command, a command whose first line is also a comment, a step name
//! quoting what it runs. Reading the parser's own events instead gives the
//! byte each value starts at, so a finding is placed rather than looked for.
//!
//! Anchors, aliases and merge keys are resolved here, which the loader does
//! only for the first two. A `<<: *base` at job level brought in nothing, so a
//! job written that way declared no steps at all and every rule was silent on
//! it.

use std::collections::HashMap;

use serde_json::{Map, Value};
use thiserror::Error;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// The key YAML merges one mapping into another with.
const MERGE: &str = "<<";

/// Why a document could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("not valid YAML")]
pub struct NotYaml;

/// Where a value sits in the text it was read from, as byte offsets.
///
/// `end` is where the next thing starts, so it may take in the whitespace or
/// the comment after the value. It bounds a search rather than quoting, which
/// is what it is for: a finding inside a block scalar is looked for between
/// these two and cannot land in another step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    /// The byte the value starts at.
    pub start: usize,
    /// The byte the next value starts at.
    pub end: usize,
}

/// A YAML value, and where it was written.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// A scalar, with the span of the text it was read from.
    Scalar(Value, Span),
    /// A sequence.
    Seq(Vec<Node>),
    /// A mapping, in the order the file wrote it.
    Map(Vec<(String, Node)>),
}

impl Node {
    /// The same value as every extractor reads it, positions dropped.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Scalar(value, _) => value.clone(),
            Self::Seq(items) => Value::Array(items.iter().map(Self::to_value).collect()),
            Self::Map(pairs) => Value::Object(
                pairs
                    .iter()
                    .map(|(key, node)| (key.clone(), node.to_value()))
                    .collect::<Map<String, Value>>(),
            ),
        }
    }

    /// The value under `key`, when this is a mapping holding one.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Map(pairs) => pairs.iter().find(|(held, _)| held == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The items, when this is a sequence.
    #[must_use]
    pub fn seq(&self) -> &[Self] {
        match self {
            Self::Seq(items) => items,
            _ => &[],
        }
    }

    /// The pairs, when this is a mapping.
    #[must_use]
    pub fn map(&self) -> &[(String, Self)] {
        match self {
            Self::Map(pairs) => pairs,
            _ => &[],
        }
    }

    /// This value as a string with something in it, and where it was written.
    #[must_use]
    pub fn text(&self) -> Option<(&str, Span)> {
        match self {
            Self::Scalar(Value::String(text), at) => {
                let trimmed = text.trim();
                (!trimmed.is_empty()).then_some((trimmed, *at))
            }
            _ => None,
        }
    }
}

/// Read `source`, keeping where each value was written.
///
/// # Errors
///
/// When the text is not YAML. An empty document is an empty mapping, as a file
/// being written one commit at a time will be.
pub fn parse(source: &str) -> Result<Node, NotYaml> {
    let mut build = Build::default();
    Parser::new_from_str(source)
        .load(&mut build, false)
        .map_err(|_| NotYaml)?;
    if build.failed {
        return Err(NotYaml);
    }
    Ok(build.done.pop().unwrap_or_else(|| Node::Map(Vec::new())))
}

/// A node being built, and the anchor it was given.
type Held = (Node, usize);

#[derive(Default)]
struct Build {
    /// Finished documents.
    done: Vec<Node>,
    /// Containers still open, outermost first.
    open: Vec<Held>,
    /// The key each open mapping is waiting on a value for.
    keys: Vec<Option<String>>,
    /// Every anchored node, by the id the parser gave it.
    anchors: HashMap<usize, Node>,
    /// The scalar whose `end` is not known yet.
    pending: Option<(usize, usize)>,
    /// Whether anything was given up on.
    failed: bool,
}

impl MarkedEventReceiver for Build {
    fn on_event(&mut self, event: Event, at: Marker) {
        self.close_pending(at.index());
        match event {
            Event::Scalar(text, style, anchor, _) => {
                let value = scalar(&text, style);
                let span = Span {
                    start: at.index(),
                    end: at.index() + text.len(),
                };
                self.pending = Some((self.open.len(), span.start));
                self.push((Node::Scalar(value, span), anchor));
            }
            Event::SequenceStart(anchor, _) => self.open.push((Node::Seq(Vec::new()), anchor)),
            Event::MappingStart(anchor, _) => {
                self.open.push((Node::Map(Vec::new()), anchor));
                self.keys.push(None);
            }
            Event::SequenceEnd => self.finish(),
            Event::MappingEnd => {
                self.keys.pop();
                self.finish();
            }
            Event::Alias(id) => {
                // An alias is the node it names, wherever that was written.
                match self.anchors.get(&id).cloned() {
                    Some(node) => self.push((node, 0)),
                    None => self.failed = true,
                }
            }
            Event::DocumentEnd => {
                if let Some((node, _)) = self.open.pop() {
                    self.done.push(node);
                }
            }
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentStart => {}
        }
    }
}

impl Build {
    /// Give the scalar still waiting for one its end, now that the next thing
    /// has been seen. A scalar ends where it ends, so this only widens it to
    /// take in what follows when the parser read more than the text itself,
    /// which a quoted or block scalar does.
    fn close_pending(&mut self, next: usize) {
        let Some((depth, start)) = self.pending.take() else {
            return;
        };
        let held = if depth == 0 {
            self.done.last_mut()
        } else {
            self.open.get_mut(depth - 1).map(|(node, _)| node)
        };
        let Some(node) = held else {
            return;
        };
        widen(node, start, next);
    }

    /// Record a finished node under its anchor and give it to its parent.
    fn push(&mut self, held: Held) {
        if held.1 > 0 {
            self.anchors.insert(held.1, held.0.clone());
        }
        let Some((parent, _)) = self.open.last_mut() else {
            // A document that is one scalar, with nothing around it.
            self.done.push(held.0);
            return;
        };
        match parent {
            Node::Seq(items) => items.push(held.0),
            Node::Map(pairs) => {
                let waiting = self.keys.last_mut();
                match waiting {
                    Some(key @ None) => {
                        // A key is read as text, and a key that is not text
                        // names nothing an extractor can ask for.
                        *key = match &held.0 {
                            Node::Scalar(Value::String(text), _) => Some(text.clone()),
                            Node::Scalar(other, _) => Some(other.to_string()),
                            _ => Some(String::new()),
                        };
                    }
                    Some(key) => {
                        let name = key.take().unwrap_or_default();
                        merge_or_insert(pairs, name, held.0);
                    }
                    None => self.failed = true,
                }
            }
            Node::Scalar(..) => self.failed = true,
        }
    }

    /// Close the innermost container and hand it to its parent.
    fn finish(&mut self) {
        if let Some(held) = self.open.pop() {
            self.push(held);
        }
    }
}

/// Put `value` under `key`, or merge it in where the key is YAML's merge key.
///
/// A merged mapping fills in what the mapping does not already say, which is
/// what the merge key means. A key written twice keeps the first, as the
/// mapping it is merging into wins.
fn merge_or_insert(pairs: &mut Vec<(String, Node)>, key: String, value: Node) {
    if key != MERGE {
        if !pairs.iter().any(|(held, _)| *held == key) {
            pairs.push((key, value));
        }
        return;
    }
    // `<<` takes one mapping or a sequence of them, nearest first.
    let merging: Vec<&Node> = match &value {
        Node::Map(_) => vec![&value],
        Node::Seq(items) => items.iter().collect(),
        Node::Scalar(..) => Vec::new(),
    };
    for from in merging {
        for (held, node) in from.map() {
            if !pairs.iter().any(|(there, _)| there == held) {
                pairs.push((held.clone(), node.clone()));
            }
        }
    }
}

/// Widen the scalar at `start` so it ends at `next`.
fn widen(node: &mut Node, start: usize, next: usize) {
    match node {
        Node::Scalar(_, at) if at.start == start => {
            at.end = at.end.max(next);
        }
        Node::Seq(items) => {
            if let Some(last) = items.last_mut() {
                widen(last, start, next);
            }
        }
        Node::Map(pairs) => {
            if let Some((_, last)) = pairs.last_mut() {
                widen(last, start, next);
            }
        }
        Node::Scalar(..) => {}
    }
}

/// A scalar's value, resolved the way YAML resolves one.
///
/// Only a plain scalar carries a type: `true` written plainly is a boolean and
/// `"true"` is the word. This is the same resolution the high-level loader
/// does, through the same function, so a value reads the same either way.
fn scalar(text: &str, style: TScalarStyle) -> Value {
    if style != TScalarStyle::Plain {
        return Value::String(text.to_owned());
    }
    match yaml_rust2::yaml::Yaml::from_str(text) {
        yaml_rust2::yaml::Yaml::Boolean(yes) => Value::Bool(yes),
        yaml_rust2::yaml::Yaml::Integer(number) => Value::Number(number.into()),
        yaml_rust2::yaml::Yaml::Real(number) => number
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map_or_else(|| Value::String(number.clone()), Value::Number),
        yaml_rust2::yaml::Yaml::Null => Value::Null,
        _ => Value::String(text.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Node {
        parse(text).expect("valid yaml")
    }

    /// The same value the high-level loader gives, so no extractor can tell
    /// which reader it came from.
    #[test]
    fn a_document_reads_as_the_value_it_is() {
        let found = read("a: 1\nb: true\nc: text\nd: \"true\"\ne: [1, two]\nf:\n  g: 2.5\n");

        assert_eq!(
            found.to_value(),
            serde_json::json!({
                "a": 1, "b": true, "c": "text", "d": "true",
                "e": [1, "two"], "f": {"g": 2.5}
            })
        );
    }

    /// The span is where the value was written, which is the whole point.
    #[test]
    fn a_scalar_knows_where_it_was_written() {
        let source = "one: first\ntwo: second\n";

        let found = read(source);
        let (text, at) = found.get("two").and_then(Node::text).expect("two");

        assert_eq!(text, "second");
        assert_eq!(&source[at.start..at.start + text.len()], "second");
        assert!(at.start > source.find("first").expect("first"));
    }

    /// Two values holding the same text sit in different places, which text
    /// search cannot tell apart and this does.
    #[test]
    fn the_same_text_written_twice_has_two_spans() {
        let source = "a:\n  run: echo same\nb:\n  run: echo same\n";

        let found = read(source);
        let first = found
            .get("a")
            .and_then(|n| n.get("run"))
            .and_then(Node::text);
        let second = found
            .get("b")
            .and_then(|n| n.get("run"))
            .and_then(Node::text);

        let (_, one) = first.expect("a");
        let (_, two) = second.expect("b");
        assert_ne!(one.start, two.start);
        assert!(one.start < two.start);
        assert_eq!(&source[one.start..one.start + 9], "echo same");
        assert_eq!(&source[two.start..two.start + 9], "echo same");
    }

    /// A folded block joins its lines, so a line of the command is not a line
    /// of the file. The span is what keeps a search for it inside this value
    /// rather than finding the same words in a later one.
    #[test]
    fn a_folded_block_still_spans_only_itself() {
        let source = "a:\n  run: >\n    one\n    two\nb:\n  run: one two\n";

        let found = read(source);
        let (text, at) = found
            .get("a")
            .and_then(|n| n.get("run"))
            .and_then(Node::text)
            .expect("a");

        assert_eq!(text, "one two", "folded into one line");
        let held = &source[at.start..at.end];
        assert!(!held.contains("run: one two"), "b is outside it: {held:?}");
    }

    /// A block scalar's span covers the block, so a line inside it is looked
    /// for there and nowhere else.
    #[test]
    fn a_block_scalar_spans_its_block() {
        let source = "a:\n  run: |\n    one\n    two\nb:\n  run: after\n";

        let found = read(source);
        let (text, at) = found
            .get("a")
            .and_then(|n| n.get("run"))
            .and_then(Node::text)
            .expect("a");

        assert_eq!(text, "one\ntwo");
        let held = &source[at.start..at.end];
        assert!(held.contains("one") && held.contains("two"), "{held:?}");
        assert!(
            !held.contains("after"),
            "it stops at the next value: {held:?}"
        );
    }

    /// A mapping keeps the order the file wrote it, so a reader placing
    /// findings by counting sees them in the order they appear.
    #[test]
    fn a_mapping_keeps_the_order_it_was_written_in() {
        let found = read("zeta: 1\nalpha: 2\n");

        let order: Vec<&str> = found.map().iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(order, ["zeta", "alpha"]);
    }

    /// An alias is the node it names, which the loader also does.
    #[test]
    fn an_alias_is_the_node_it_names() {
        let found = read("one: &x echo hi\ntwo: *x\n");

        assert_eq!(
            found.get("two").and_then(Node::text).map(|(t, _)| t),
            Some("echo hi")
        );
    }

    /// A merge key fills in what the mapping does not say, which the loader
    /// does not do at all: a job written `<<: *base` declared no steps.
    #[test]
    fn a_merge_key_fills_in_what_is_missing() {
        let found = read(
            "base: &b\n  runs-on: ubuntu-latest\n  steps:\n    - run: echo base\njobs:\n  merged:\n    <<: *b\n",
        );
        let job = found
            .get("jobs")
            .and_then(|n| n.get("merged"))
            .expect("merged");

        assert_eq!(
            job.get("runs-on").and_then(Node::text).map(|(t, _)| t),
            Some("ubuntu-latest")
        );
        assert_eq!(job.get("steps").map(|n| n.seq().len()), Some(1));
        assert!(job.get(MERGE).is_none(), "the merge key is not a key");
    }

    /// What the mapping says itself wins over what it merges, and a nearer
    /// mapping in a list of them wins over a later one.
    #[test]
    fn a_merge_does_not_overwrite_what_is_already_there() {
        let found = read(
            "a: &a\n  k: from-a\nb: &b\n  k: from-b\n  j: only-b\nmine:\n  k: my-own\n  <<: [*a, *b]\n",
        );
        let mine = found.get("mine").expect("mine");

        assert_eq!(
            mine.get("k").and_then(Node::text).map(|(t, _)| t),
            Some("my-own")
        );
        assert_eq!(
            mine.get("j").and_then(Node::text).map(|(t, _)| t),
            Some("only-b")
        );
    }

    /// An empty file is an empty mapping, and nonsense is an error.
    #[test]
    fn an_empty_document_is_empty_and_nonsense_is_an_error() {
        assert_eq!(read("").to_value(), serde_json::json!({}));
        assert!(parse("a:\n  - b\n c: broken\n").is_err());
        // An alias naming nothing is not a document clew will read.
        assert!(parse("a: *missing\n").is_err());
    }
}
