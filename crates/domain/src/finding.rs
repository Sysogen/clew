// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Something a scan found wrong, and where.

use crate::repo_path::RepoPath;

/// How much of the offending line is kept as evidence, in characters.
pub const DEFAULT_EVIDENCE_WIDTH: usize = 80;

/// A rule clew applies. The string is a promise: someone will suppress a
/// finding by it, so it never changes meaning once published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleId {
    /// Non-printing Unicode in a file the model reads as instructions.
    InvisibleUnicode,
}

impl RuleId {
    /// The identifier, as reported.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvisibleUnicode => "invisible-unicode",
        }
    }

    /// One line saying what the rule looks for.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::InvisibleUnicode => {
                "Non-printing Unicode in a file an agent reads as instructions"
            }
        }
    }
}

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Reported, not acted on.
    Low,
    /// Worth looking at.
    Medium,
    /// Acted on before the next agent run.
    High,
}

impl Severity {
    /// The word used in a report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Where in a file something was found. Both counted from one, and the column
/// counts characters, because a rule about non-ASCII cannot report bytes and
/// stay readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    /// The line.
    pub line: usize,
    /// The character within the line.
    pub column: usize,
}

/// Something wrong, and where.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The file it was found in.
    pub path: RepoPath,
    /// Where in the file, when the rule is about a place rather than the file.
    pub at: Option<Position>,
    /// The rule that made it.
    pub rule: RuleId,
    /// How much it matters.
    pub severity: Severity,
    /// The offending text, with every non-printing character escaped.
    pub evidence: String,
}

/// A window of `line` around `column`, with non-printing characters escaped.
///
/// The character never reaches the output. Printing it would carry the payload
/// into a terminal, a viewer, or whatever the report is pasted into, which is
/// the attack rather than a report of it. Escaping here rather than in a
/// renderer is what stops a second output format reintroducing it.
#[must_use]
pub fn evidence(line: &str, column: usize, width: usize) -> String {
    let chars: Vec<char> = line.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    let at = column.saturating_sub(1).min(chars.len() - 1);

    // Budgeted on what is written, not on what is read: one hidden character
    // becomes eight, so a window measured in source characters still lets a
    // minified line fill the report.
    let mut budget = width.saturating_sub(written(chars[at]).chars().count());
    let (mut first, mut last) = (at, at + 1);
    loop {
        let mut grew = false;
        if first > 0 {
            let cost = written(chars[first - 1]).chars().count();
            if cost <= budget {
                budget -= cost;
                first -= 1;
                grew = true;
            }
        }
        if last < chars.len() {
            let cost = written(chars[last]).chars().count();
            if cost <= budget {
                budget -= cost;
                last += 1;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    let mut out = String::new();
    if first > 0 {
        out.push('\u{2026}');
    }
    for c in &chars[first..last] {
        out.push_str(&written(*c));
    }
    if last < chars.len() {
        out.push('\u{2026}');
    }
    out
}

/// One character as it is reported.
fn written(c: char) -> String {
    if is_printing(c) {
        c.to_string()
    } else {
        format!("<U+{:04X}>", c as u32)
    }
}

/// Whether a character shows itself. A tab and a space do; a zero-width joiner
/// and a bidirectional override do not.
fn is_printing(c: char) -> bool {
    c == '\t' || (!c.is_control() && !crate::rules::is_hidden(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hidden_character_is_written_as_its_codepoint() {
        let said = evidence("use the\u{202E}project rules", 8, 80);

        assert!(!said.contains('\u{202E}'), "the character escaped: {said}");
        assert!(said.contains("<U+202E>"), "{said}");
        assert!(said.contains("use the"), "context survives: {said}");
    }

    #[test]
    fn a_tag_character_is_written_as_its_codepoint() {
        let said = evidence("hi\u{E0041}", 3, 80);

        assert_eq!(said, "hi<U+E0041>");
    }

    #[test]
    fn printable_text_is_left_alone() {
        assert_eq!(evidence("plain ascii", 1, 80), "plain ascii");
        assert_eq!(evidence("caf\u{e9} and \u{1F600}", 1, 80), "café and 😀");
    }

    /// A minified file is one long line, and a report is not the place to
    /// reproduce it.
    #[test]
    fn a_long_line_is_trimmed_around_the_offence() {
        let line = format!("{}\u{200B}{}", "a".repeat(200), "b".repeat(200));

        let said = evidence(&line, 201, 20);

        assert!(
            said.chars().count() <= 22,
            "{} chars: {said}",
            said.chars().count()
        );
        assert!(said.contains("<U+200B>"), "the offence is kept: {said}");
        assert!(said.starts_with('…') && said.ends_with('…'), "{said}");
    }

    /// A line that is nothing but hidden characters expands eightfold, and the
    /// bound has to hold against that or the report carries the file.
    #[test]
    fn a_line_of_hidden_characters_is_still_bounded() {
        let line = "\u{200B}".repeat(500);

        let said = evidence(&line, 250, 40);

        assert!(said.chars().count() <= 42, "{} chars", said.chars().count());
    }

    #[test]
    fn severity_and_rule_read_as_themselves() {
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(RuleId::InvisibleUnicode.as_str(), "invisible-unicode");
    }

    /// Sorting puts a report in file order, then position order.
    #[test]
    fn findings_sort_by_place() {
        let at = |line, column| Some(Position { line, column });
        let f = |path: &str, at| Finding {
            path: RepoPath::root().join(path),
            at,
            rule: RuleId::InvisibleUnicode,
            severity: Severity::High,
            evidence: String::new(),
        };
        let mut all = [
            f("b.md", at(1, 1)),
            f("a.md", at(9, 1)),
            f("a.md", at(2, 1)),
        ];
        all.sort();

        assert_eq!(
            all.iter().map(|x| x.path.as_str()).collect::<Vec<_>>(),
            ["a.md", "a.md", "b.md"]
        );
        assert_eq!(all[0].at.map(|p| p.line), Some(2));
    }
}
