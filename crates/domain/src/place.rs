// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Where the things a file declares are written.
//!
//! A rule is asked about one declaration at a time, and placement finds a
//! declaration by searching the file's text, so searching inside the rule
//! read the whole file once for every declaration in it. A file is free to
//! hold thousands, and the file being read is the one being scanned, so that
//! is a cost the repository chooses.
//!
//! [`Places`] reads the file once instead, while the scan has the text, and
//! answers each lookup from what it found. The rules are handed the place
//! they are to report rather than the text to search.

use std::collections::BTreeMap;

use crate::extract::{Format, Syntax};
use crate::yaml::Span;

/// Where everything of one kind a file declares is written.
///
/// The key is what a rule has in hand: the entry a pre-approval grants, the
/// trigger a task runs on, the command a hook calls, the name a server is
/// declared under. A declaration written twice has two places, in the order
/// the file writes them, which is the order a rule counts them in.
#[derive(Debug, Default)]
pub struct Places {
    /// Keyed by the scope it was found in and the text itself, because a
    /// name may be declared in two blocks and those are two declarations.
    ///
    /// The extent, not just the start: a rule reading a command looks inside
    /// the one it was given, and where that ends is what keeps it from
    /// finding something in the next.
    at: BTreeMap<(String, String), Vec<Span>>,
    /// How long the file is, which is how far a command found by searching
    /// reaches: only the reader knows where one ends, and a rule looking
    /// inside a command it found itself must look to the end of the file or
    /// miss a line the command spans onto.
    len: usize,
}

impl Places {
    /// Where the `occurrence`th copy of `text` starts.
    #[must_use]
    pub fn nth(&self, text: &str, occurrence: usize) -> Option<usize> {
        self.nth_in("", text, occurrence).map(|held| held.start)
    }

    /// The same, for a kind whose declarations sit in named scopes, and
    /// giving the whole extent.
    #[must_use]
    pub fn nth_in(&self, scope: &str, text: &str, occurrence: usize) -> Option<Span> {
        self.at
            .get(&(scope.to_owned(), text.to_owned()))?
            .get(occurrence)
            .copied()
    }

    fn add(&mut self, scope: &str, text: &str, at: Span) {
        self.at
            .entry((scope.to_owned(), text.to_owned()))
            .or_default()
            .push(at);
    }

    /// Where a file writes the values it gives the keys `keys` name, and the
    /// values a `crushrc` gives the builtin `builtin` calls.
    ///
    /// A `crushrc` holds no key to anchor to, so a grant there is anchored to
    /// the call that makes it, and a file is one or the other.
    ///
    /// Values are counted across the file rather than per key, because that
    /// is how a grant is counted: a file granting the same tool under
    /// `allow` and under `allowed-tools` grants it twice, and the order is
    /// the file's. A caller that must know which key gave a value asks
    /// about that key alone.
    #[must_use]
    pub fn given(source: &str, format: Format, keys: &[&str], builtin: &[&str]) -> Self {
        let mut held = Self {
            len: source.len(),
            ..Self::default()
        };
        let wrote = values(source, format);
        for key in keys {
            // The whole key, as VS Code writes it, or its segments nested,
            // as one putting `defaultMode` under `permissions` does.
            let mut given = spans(source, format, key);
            if given.is_empty() {
                given = nested(source, format, key);
            }
            for (from, to) in given {
                for (text, at) in within(&wrote, from, to) {
                    held.add(
                        "",
                        text,
                        Span {
                            start: at,
                            end: at + text.len(),
                        },
                    );
                }
            }
        }
        for (text, at) in called(source, builtin) {
            held.add(
                "",
                &text,
                Span {
                    start: at,
                    end: at + text.len(),
                },
            );
        }
        held
    }

    /// Where a file declares each thing named by a key inside one of the
    /// blocks `blocks` name, scoped by the block it was declared in.
    #[must_use]
    pub fn declared(source: &str, format: Format, blocks: &[&str]) -> Self {
        let mut held = Self {
            len: source.len(),
            ..Self::default()
        };
        for block in blocks {
            for (from, to) in spans(source, format, block) {
                for (text, at) in keys_between(source, format, from, to) {
                    held.add(
                        block,
                        &text,
                        Span {
                            start: at,
                            end: at + text.len(),
                        },
                    );
                }
            }
        }
        held
    }

    /// Where a file writes each string it holds, and each line.
    ///
    /// A settings file writes a command as a string, and a reader looks for
    /// it in the escaping the file used. A YAML `run:` block writes it bare
    /// over several lines, and the first of those is where the block starts,
    /// which is what a reviewer needs to find it.
    #[must_use]
    pub fn written(source: &str, format: Format) -> Self {
        let mut held = Self {
            len: source.len(),
            ..Self::default()
        };
        for (text, at) in within(&values(source, format), 0, source.len()) {
            held.add(
                "",
                text,
                Span {
                    start: at,
                    end: at + text.len(),
                },
            );
        }
        let mut from = 0;
        for line in source.split_inclusive('\n') {
            let bare = line.trim_end();
            // The line itself, and the scalar after its key, because a YAML
            // step writes a command as `- run: <command>` and what a rule
            // holds is the command rather than the line around it.
            for text in [bare.trim_start(), scalar(bare)] {
                if !text.is_empty() {
                    let opens = from + bare.len() - text.len();
                    held.add(
                        "",
                        text,
                        Span {
                            start: opens,
                            end: opens + text.len(),
                        },
                    );
                }
            }
            from += line.len();
        }
        held
    }

    /// How far a command written in `source` reaches, by the escaping the
    /// file would have used, or by the first line of its bare form.
    ///
    /// `span` is what the reader already knew, which a format read with
    /// positions gives and nothing needs to search for.
    #[must_use]
    pub fn command(&self, command: &str, occurrence: usize, span: Option<Span>) -> Option<Span> {
        if span.is_some() {
            return span;
        }
        let written = serde_json::to_string(command).ok()?;
        let quoted = written.get(1..written.len() - 1)?;
        let found = self.nth_in("", quoted, occurrence).or_else(|| {
            self.nth_in(
                "",
                command.lines().next().unwrap_or(command).trim_end(),
                occurrence,
            )
        })?;
        // Where it ends is the reader's to say. A command written over
        // several lines is indented in the file and its text is not, so the
        // only honest bound on a command found by searching is the file.
        Some(Span {
            start: found.start,
            end: self.len,
        })
    }
}

/// The values a dotted key is given where the file writes only its segments,
/// each one nested in the last.
///
/// A file writes the whole key, as VS Code does, or nests it, as one putting
/// `defaultMode` under `permissions` does. The leaf is looked for under the
/// parent the key names rather than anywhere: another block writing the same
/// leaf is a different setting, and anchoring there puts the finding on it.
fn nested(source: &str, format: Format, key: &str) -> Vec<(usize, usize)> {
    let mut held: Option<Vec<(usize, usize)>> = None;
    for segment in key.split('.') {
        held = Some(match held {
            None => spans(source, format, segment),
            Some(outer) => under(source, format, &outer, segment),
        });
        if held.as_ref().is_some_and(Vec::is_empty) {
            return Vec::new();
        }
    }
    held.unwrap_or_default()
}

/// The values `key` is given where it is written inside one of `outer`.
fn under(source: &str, format: Format, outer: &[(usize, usize)], key: &str) -> Vec<(usize, usize)> {
    spans(source, format, key)
        .into_iter()
        .filter(|(from, _)| {
            outer
                .iter()
                .any(|(opens, shuts)| from > opens && from < shuts)
        })
        .collect()
}

/// The keys a tool lists its pre-approvals under. A grant is looked for only
/// after one of them, so a tool name in a description is not taken for a grant.
/// The longer spellings precede the ones they contain, so a Crush
/// `allowed_tools` is not half-matched as `allowed` and left unplaced.
pub const GRANT_LISTS: &[&str] = &["allow", "allowed-tools", "allowed_tools", "allowed"];

/// The builtin a `crushrc` lists its pre-approvals with. A `crushrc` holds no
/// key to anchor to, so a grant is anchored to the call that makes it.
pub const GRANT_BUILTIN: &[&str] = &["permissions", "allow"];

/// The builtin a `crushrc` declares a server with.
pub const SERVER_BUILTIN: &[&str] = &["mcp", "add"];

/// Whether a byte is one a key is written with.
///
/// Everything but whitespace, a separator, and the punctuation that holds one
/// declaration apart from the next.
fn is_key(c: u8) -> bool {
    !c.is_ascii_whitespace()
        && !matches!(
            c,
            b':' | b'=' | b'"' | b'\'' | b'{' | b'}' | b'[' | b']' | b','
        )
}

/// What a line gives a key, which is the text after its separator.
///
/// A YAML step writes a command as `- run: <command>`, and the command is
/// what a rule holds: the line around it is not what it would look for.
fn scalar(line: &str) -> &str {
    line.find(": ").map_or("", |at| line[at + 2..].trim())
}

/// Every string and bare word between bytes `from` and `to`, with where each
/// one's text starts.
///
/// A value sits inside a string, so a string is what is being read here, and
/// Every value the file writes, with where its text starts, in the order
/// the file writes them.
///
/// Walked once for the whole file rather than once per key, because a file
/// writing a key N times would otherwise cost N times its length, which is
/// the shape this index exists to remove.
fn values(source: &str, format: Format) -> Vec<(String, usize)> {
    let syntax = format.syntax();
    let text = source.as_bytes();
    let mut scan = Scan::default();
    let mut found = Vec::new();
    let mut word: Option<usize> = None;
    let mut i = 0;

    while i < text.len() {
        let was = scan.in_string();
        if let Some(on) = scan.inside(text, i) {
            // The close of a string, which is where its text ended.
            if was
                && !scan.in_string()
                && let Some(opens) = word.take()
                && let Some(held) = source.get(opens..i)
            {
                found.push((held.to_owned(), opens));
            }
            i = on;
            continue;
        }
        if let Some(on) = scan.opens(text, i, syntax) {
            // Past the quote, so a finding points at the text rather than at
            // the quote in front of it.
            if scan.in_string() {
                word = Some(on);
            }
            i = on;
            continue;
        }
        // A bare word, which is how frontmatter and TOML write a value
        // without quoting it.
        let ends = text[i].is_ascii_whitespace() || matches!(text[i], b',' | b']' | b'}');
        match (word, ends) {
            (None, false) => word = Some(i),
            (Some(opens), true) => {
                if let Some(held) = source.get(opens..i) {
                    found.push((held.to_owned(), opens));
                }
                word = None;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(opens) = word
        && let Some(held) = source.get(opens..)
    {
        found.push((held.to_owned(), opens));
    }

    found
}

/// The values whose text starts between bytes `from` and `to`.
///
/// Where a value starts is what says whose it is: one beginning before a
/// key's values belongs to the key before it, and one beginning inside them
/// is this key's however far it runs on.
fn within(
    values: &[(String, usize)],
    from: usize,
    to: usize,
) -> impl Iterator<Item = (&str, usize)> {
    values
        .iter()
        .filter(move |(_, at)| *at >= from && *at < to)
        .map(|(text, at)| (text.as_str(), *at))
}

/// Every key written between bytes `from` and `to`, with where a finding
/// about each one points, which is just past it.
fn keys_between(source: &str, format: Format, from: usize, to: usize) -> Vec<(String, usize)> {
    let syntax = format.syntax();
    let text = source.as_bytes();
    let mut scan = Scan::default();
    let mut found = Vec::new();
    let mut i = 0;

    while i < text.len() {
        if i >= from
            && i < to
            && !scan.in_comment()
            && let Some((name, at, past)) = key_here(source, syntax, i)
        {
            found.push((name, at));
            i = past;
            continue;
        }
        if let Some(on) = scan.inside(text, i) {
            i = on;
            continue;
        }
        if let Some(on) = scan.opens(text, i, syntax) {
            i = on;
            continue;
        }
        i += 1;
    }

    found
}

/// The key byte `i` of `source` opens, where a finding about it points, and
/// where to carry on from.
///
/// Quoted, as JSON does, or bare before its separator, as TOML and YAML do.
/// A finding points just past the key, which is where it has always pointed
/// and what the evidence a report quotes is centred on. Carrying on from
/// there is a third thing: resuming at the name would read the same key for
/// ever.
fn key_here(source: &str, syntax: Syntax, i: usize) -> Option<(String, usize, usize)> {
    let text = source.as_bytes();
    if syntax.quotes.contains(&text[i]) {
        let rest = source.get(i + 1..)?;
        let shuts = rest.find(text[i] as char)? + i + 1;
        if separated(source, shuts + 1) {
            return Some((source.get(i + 1..shuts)?.to_owned(), shuts + 1, shuts + 1));
        }
        return None;
    }
    // A bare key is made of key characters and nothing else. Reading up to
    // the next separator instead took in the punctuation between two of
    // them, so `{"local"` read as a key and the real one after it was
    // skipped.
    let ends = i + text[i..].iter().take_while(|c| is_key(**c)).count();
    let name = source.get(i..ends)?;
    let runs_on = i > 0 && is_key(text[i - 1]);
    (!name.is_empty() && !runs_on && separated(source, ends)).then(|| (name.to_owned(), ends, ends))
}

/// Every value a `crushrc` gives one of the builtin calls `words` names,
/// with where each one's text starts.
///
/// A shell builtin separates a name from its values with spaces, which no
/// key-and-separator reading accepts and must not: a bare word followed by a
/// space is most of English. Anchoring to the whole call instead keeps a
/// `crushrc` finding on the line that causes it.
fn called(source: &str, words: &[&str]) -> Vec<(String, usize)> {
    if words.is_empty() {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut start = 0;
    for line in source.split_inclusive('\n') {
        let at = start;
        start += line.len();

        let mut rest = line.trim_start();
        let called = words.iter().all(|word| match rest.strip_prefix(*word) {
            Some(after) if after.starts_with(char::is_whitespace) => {
                rest = after.trim_start();
                true
            }
            _ => false,
        });
        if !called {
            continue;
        }

        let from = line.len() - rest.len();
        for (text, offset) in within(&values(rest, Format::Crushrc), 0, rest.len()) {
            found.push((text.to_owned(), at + from + offset));
        }
    }
    found
}

/// Where a scan of a file's text is, reading left to right.
#[derive(Default, PartialEq)]
enum At {
    /// Writing a key or a value.
    #[default]
    Code,
    /// Inside a string the next matching quote closes.
    Str(u8),
    /// Inside a string the next three quotes close.
    Long(u8),
    /// Inside a comment that ends with the line.
    Line,
    /// Inside a comment that ends with `*/`.
    Block,
}

/// A scan of a file's text, reading what is a comment and what is a string.
#[derive(Default)]
struct Scan {
    at: At,
    escaped: bool,
}

impl Scan {
    /// Whether the scan is inside a comment.
    fn in_comment(&self) -> bool {
        matches!(self.at, At::Line | At::Block)
    }

    /// Whether the scan is inside a string, which is where a value sits.
    fn in_string(&self) -> bool {
        matches!(self.at, At::Str(_) | At::Long(_))
    }

    /// Where to carry on from, when byte `i` is inside a string or a comment.
    ///
    /// `None` where it is not, which is the caller's cue to read the byte.
    fn inside(&mut self, text: &[u8], i: usize) -> Option<usize> {
        let c = text[i];
        let next = text.get(i + 1).copied();
        match self.at {
            At::Code => return None,
            At::Str(quote) => {
                if self.escaped {
                    self.escaped = false;
                // A literal string holds no escapes, so a backslash in one
                // is a backslash.
                } else if c == b'\\' && quote == b'"' {
                    self.escaped = true;
                } else if c == quote {
                    self.at = At::Code;
                }
            }
            At::Long(quote) => {
                // A long basic string honours escapes, so an escaped quote
                // does not close it; a long literal one honours none.
                if self.escaped {
                    self.escaped = false;
                } else if c == b'\\' && quote == b'"' {
                    self.escaped = true;
                } else if c == quote {
                    // TOML lets up to two quotes sit against the delimiter,
                    // so a run of four or five closes and the extras belong
                    // to the value. Closing at the first three would leave
                    // one over to open a string of its own.
                    let run = text[i..].iter().take_while(|c| **c == quote).count();
                    if run >= 3 {
                        self.at = At::Code;
                        return Some(i + run.min(5));
                    }
                    return Some(i + run);
                }
            }
            At::Line => {
                if c == b'\n' {
                    self.at = At::Code;
                }
            }
            At::Block => {
                if c == b'*' && next == Some(b'/') {
                    self.at = At::Code;
                    return Some(i + 2);
                }
            }
        }
        Some(i + 1)
    }

    /// Where to carry on from, when a string or a comment opens at byte `i`.
    ///
    /// `None` where none does.
    fn opens(&mut self, text: &[u8], i: usize, syntax: Syntax) -> Option<usize> {
        let c = text[i];
        let spaced =
            i == 0 || text[i - 1].is_ascii_whitespace() || syntax.breaks.contains(&text[i - 1]);
        if let Some(marker) = syntax
            .line
            .iter()
            .chain(syntax.spaced.iter().filter(|_| spaced))
            .find(|marker| text[i..].starts_with(marker.as_bytes()))
        {
            self.at = At::Line;
            return Some(i + marker.len());
        }
        if syntax.block && c == b'/' && text.get(i + 1) == Some(&b'*') {
            self.at = At::Block;
            return Some(i + 2);
        }
        if syntax.quotes.contains(&c) {
            if syntax.long && text.get(i + 1) == Some(&c) && text.get(i + 2) == Some(&c) {
                self.at = At::Long(c);
                return Some(i + 3);
            }
            self.at = At::Str(c);
            return Some(i + 1);
        }
        None
    }
}

/// The byte ranges holding the values `key` is given, one for each place the
/// file writes it as a key, in order.
///
/// A key's values are the ones it was given, not every copy of the text after
/// it: between two `runOn` declarations a `label` holding the same word is
/// another key's value, and counting it put the second finding on the label.
///
/// A list or a block runs to its close, and anything else to the end of the
/// line, which is where frontmatter writes several values for one key.
fn spans(source: &str, format: Format, key: &str) -> Vec<(usize, usize)> {
    let syntax = format.syntax();
    let text = source.as_bytes();
    let mut scan = Scan::default();
    let mut found = Vec::new();
    let mut within = 0_usize;
    let mut i = 0;

    while i < text.len() {
        if let Some(on) = scan.inside(text, i) {
            i = on;
            continue;
        }
        if let Some(end) = key_at(source, syntax, i, key) {
            found.push((end, span(source, format, end, within)));
            i = end;
            continue;
        }
        if let Some(on) = scan.opens(text, i, syntax) {
            i = on;
            continue;
        }
        // How deep in a list or a block this key sits, which is what says
        // whether a comma separates anything where its values are written.
        match text[i] {
            b'[' | b'{' => within += 1,
            b']' | b'}' => within = within.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }

    found
}

/// Where the values written after byte `at` end, for a key `within` that
/// many lists or blocks.
fn span(source: &str, format: Format, at: usize, within: usize) -> usize {
    let syntax = format.syntax();
    let text = source.as_bytes();
    let opens = source[at..]
        .char_indices()
        .find(|(_, c)| !c.is_whitespace() && *c != ':' && *c != '=')
        .map(|(offset, c)| (at + offset, c));
    let Some((from, c @ ('[' | '{'))) = opens else {
        // One value, or several on one line, which is frontmatter's shape.
        // Inside a list or a block the next entry ends it instead: a compact
        // file writes a whole object on one line, and running to the newline
        // there would swallow every key after this one. Outside one a comma
        // separates nothing, which is how `allowed-tools: Bash(a), Read`
        // gives one key two values.
        if within > 0 {
            // The newline only decides this where it comes first, so it is
            // looked for no further than the entry: a file written on one
            // line would otherwise be read to its end for every key in it,
            // which is this index's own cost all over again.
            let ends = entry(source, format, at);
            return source
                .get(at..ends)
                .and_then(|held| held.find('\n'))
                .map_or(ends, |newline| at + newline);
        }
        let line = source[at..]
            .find('\n')
            .map_or(text.len(), |newline| at + newline);
        // Nothing but the separator on the key's own line, so the values are
        // the block indented beneath it, which is how YAML writes a list and
        // how frontmatter writes several tools.
        if source[at..line]
            .trim_start_matches([':', '=', ' ', '\t'])
            .is_empty()
        {
            return block(source, line);
        }
        return line;
    };

    // To the close that matches, counting the nesting between and reading
    // what is a string and what is a comment on the way.
    let shuts = if c == '[' { b']' } else { b'}' };
    let mut scan = Scan::default();
    let mut depth = 0_usize;
    let mut i = from;
    while i < text.len() {
        if let Some(on) = scan.inside(text, i) {
            i = on;
            continue;
        }
        if text[i] == c as u8 {
            depth += 1;
        } else if text[i] == shuts {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        }
        if let Some(on) = scan.opens(text, i, syntax) {
            i = on;
            continue;
        }
        i += 1;
    }
    text.len()
}

/// Where the entry starting at byte `at` ends: the next comma or closing
/// bracket the file writes in code, at the depth it started from.
fn entry(source: &str, format: Format, at: usize) -> usize {
    let syntax = format.syntax();
    let text = source.as_bytes();
    let mut scan = Scan::default();
    let mut depth = 0_usize;
    let mut i = at;

    while i < text.len() {
        if let Some(on) = scan.inside(text, i) {
            i = on;
            continue;
        }
        match text[i] {
            b'[' | b'{' => depth += 1,
            // A comma at the depth this entry started from separates it from
            // the next; a close at that depth ends what holds it.
            b',' | b']' | b'}' if depth == 0 => return i,
            b']' | b'}' => depth -= 1,
            _ => {}
        }
        if let Some(on) = scan.opens(text, i, syntax) {
            i = on;
            continue;
        }
        i += 1;
    }

    text.len()
}

/// Where the block indented beneath a key ends, starting from the newline
/// at `line`.
///
/// The first line indented no further than the key's own ends it, which is
/// the next key beside it, or the fence frontmatter closes with.
fn block(source: &str, line: usize) -> usize {
    let opens = source[..line].rfind('\n').map_or(0, |newline| newline + 1);
    let indent = source[opens..line].len() - source[opens..line].trim_start().len();
    let mut at = line;
    for next in source[line..].split_inclusive('\n').skip(1) {
        if !next.trim().is_empty() && next.len() - next.trim_start().len() <= indent {
            return at;
        }
        at += next.len();
    }
    source.len()
}

/// Just past `key` where byte `i` of `source` writes it as one: quoted, as
/// JSON does, or bare before its separator, as TOML and YAML do.
fn key_at(source: &str, syntax: Syntax, i: usize, key: &str) -> Option<usize> {
    let text = source.as_bytes();
    let wanted = key.as_bytes();
    // A quoted key, in whichever quote the format allows: TOML and YAML both
    // take one in either.
    let closes = i + 1 + wanted.len();
    if syntax.quotes.contains(&text[i])
        && text.get(i + 1..closes) == Some(wanted)
        && text.get(closes) == Some(&text[i])
        && separated(source, closes + 1)
    {
        return Some(closes + 1);
    }
    if !text[i..].starts_with(wanted) {
        return None;
    }
    let runs_on = i > 0
        && (text[i - 1].is_ascii_alphanumeric() || text[i - 1] == b'_' || text[i - 1] == b'-');
    (!runs_on && separated(source, i + wanted.len())).then_some(i + wanted.len())
}

/// Whether a separator follows byte `at`, which is what makes the text before
/// it a key rather than something that reads like one.
fn separated(source: &str, at: usize) -> bool {
    let after = source.get(at..).unwrap_or_default().trim_start();
    after.starts_with('=') || after.starts_with(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_of(source: &str, at: usize) -> usize {
        source[..at].matches('\n').count() + 1
    }

    /// One key given a list: the copies are counted in the order the file
    /// writes them, which is the order a rule counts them in.
    #[test]
    fn a_list_is_counted_in_the_order_the_file_writes_it() {
        let json =
            "{\n  \"allow\": [\n    \"Bash(ls)\",\n    \"Bash(*)\",\n    \"Bash(*)\"\n  ]\n}\n";

        let held = Places::given(json, Format::Json, &["allow"], &[]);

        assert_eq!(line_of(json, held.nth("Bash(ls)", 0).expect("first")), 3);
        assert_eq!(line_of(json, held.nth("Bash(*)", 0).expect("second")), 4);
        assert_eq!(line_of(json, held.nth("Bash(*)", 1).expect("third")), 5);
        assert_eq!(held.nth("Bash(*)", 2), None);
    }

    /// A value another key was given is not one this key was given, and a
    /// value named in a comment is a note.
    #[test]
    fn only_the_values_a_key_was_given_are_counted() {
        let jsonc = "{\n  \"runOn\": \"folderOpen\",\n  \"label\": \"folderOpen\",\n  // \"folderOpen\"\n  \"runOn\": \"folderOpen\"\n}\n";

        let held = Places::given(jsonc, Format::Jsonc, &["runOn"], &[]);

        assert_eq!(line_of(jsonc, held.nth("folderOpen", 0).expect("first")), 2);
        assert_eq!(
            line_of(jsonc, held.nth("folderOpen", 1).expect("second")),
            5
        );
        assert_eq!(held.nth("folderOpen", 2), None);
    }

    /// Frontmatter writes several values on one line and as a block beneath
    /// the key, and both are that key's values.
    #[test]
    fn frontmatter_is_counted_both_ways() {
        let one = "---\nallowed-tools: Bash(cargo test:*), Read\n---\n";
        let block = "---\nallowed-tools:\n  - Bash(ls)\n  - Read\n---\n";

        let held = Places::given(one, Format::Markdown, &["allowed-tools"], &[]);
        assert_eq!(line_of(one, held.nth("Read", 0).expect("on the line")), 2);

        let held = Places::given(block, Format::Markdown, &["allowed-tools"], &[]);
        assert_eq!(
            line_of(block, held.nth("Read", 0).expect("in the block")),
            4
        );
    }

    /// A `crushrc` holds no key, so a grant is anchored to the call.
    #[test]
    fn a_builtin_call_gives_its_values() {
        let crushrc = "# tools\npermissions allow view edit\npermissions allow bash\n";

        let held = Places::given(crushrc, Format::Crushrc, &[], &["permissions", "allow"]);

        assert_eq!(line_of(crushrc, held.nth("bash", 0).expect("the call")), 3);
        assert_eq!(line_of(crushrc, held.nth("edit", 0).expect("the first")), 2);
    }

    /// A name declared in two blocks is two declarations, and each is placed
    /// in the block it was declared in.
    #[test]
    fn a_declaration_is_scoped_to_its_block() {
        let json = "{\n  \"mcpServers\": {\n    \"pg\": {}\n  },\n  \"servers\": {\n    \"pg\": {}\n  }\n}\n";

        let held = Places::declared(json, Format::Json, &["mcpServers", "servers"]);

        assert_eq!(
            line_of(
                json,
                held.nth_in("mcpServers", "pg", 0).expect("first").start
            ),
            3
        );
        assert_eq!(
            line_of(json, held.nth_in("servers", "pg", 0).expect("second").start),
            6
        );
    }

    /// A declaration points just past its key, which is where a finding has
    /// always pointed and what the evidence a report quotes is centred on.
    /// A bare key is the case a quoted one does not cover: there is no
    /// closing quote to pass over, so the name's own end is what says where.
    #[test]
    fn a_bare_key_points_just_past_itself() {
        let yaml = "mcpServers:\n  pg:\n    command: psql\n";

        let held = Places::declared(yaml, Format::Yaml, &["mcpServers"]);

        let at = held.nth_in("mcpServers", "pg", 0).expect("the key").start;
        assert_eq!(yaml.get(..at), Some("mcpServers:\n  pg"));
    }

    /// A command written as a string is found by the escaping the file used,
    /// and a bare one by its first line.
    #[test]
    fn a_command_is_found_either_way_it_is_written() {
        let json = "{\n  \"command\": \"echo \\\"hi\\\"\\nmore\"\n}\n";
        let held = Places::written(json, Format::Json);

        let at = held
            .command("echo \"hi\"\nmore", 0, None)
            .expect("the string");
        assert_eq!(line_of(json, at.start), 2);

        let yaml = "steps:\n  - run: |\n      echo one\n      echo two\n";
        let held = Places::written(yaml, Format::Yaml);
        let at = held
            .command("echo one\necho two", 0, None)
            .expect("the line");
        assert_eq!(line_of(yaml, at.start), 3);
    }

    /// Where the file said it is, the reader is believed and nothing is
    /// searched for.
    #[test]
    fn a_span_the_reader_knew_is_taken_as_given() {
        let held = Places::written("", Format::Yaml);

        assert_eq!(
            held.command("anything", 0, Some(Span { start: 7, end: 9 })),
            Some(Span { start: 7, end: 9 })
        );
    }
}
