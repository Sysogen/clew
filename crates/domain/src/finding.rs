// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Something a scan found wrong, and where.

use crate::credential;
use crate::repo_path::RepoPath;

/// How much of the offending line is kept as evidence, in characters.
pub const DEFAULT_EVIDENCE_WIDTH: usize = 80;

/// The widest evidence gets when the configured width is smaller: the longest
/// escape, `<U+10FFFF>`, with an ellipsis either side.
pub const MIN_EVIDENCE_WIDTH: usize = 12;

/// A rule clew applies. The string is a promise: someone will suppress a
/// finding by it, so it never changes meaning once published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleId {
    /// Non-printing Unicode in a file the model reads as instructions.
    InvisibleUnicode,
}

impl RuleId {
    /// The identifier, as reported and as a catalogue row names it.
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

    /// The rule a catalogue row names, if it names one that exists.
    #[must_use]
    pub fn from_catalogue(name: &str) -> Option<Self> {
        Some(match name {
            "invisible-unicode" => Self::InvisibleUnicode,
            _ => return None,
        })
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

/// Where in a file something was found, both counted from one. The column
/// counts characters: a rule about non-ASCII cannot report bytes readably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    /// The line.
    pub line: usize,
    /// The character within the line.
    pub column: usize,
}

/// A line as evidence quotes it: split once, with credential values masked.
///
/// [`Evidence::quote`] takes only this, so no rule can quote a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line(Vec<char>);

impl Line {
    /// Split `text` and mask the credentials in it.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(credential::mask(&text.chars().collect::<Vec<_>>()))
    }

    /// The masked characters.
    #[must_use]
    pub fn chars(&self) -> &[char] {
        &self.0
    }
}

/// Quoted text from an offending line, every non-printing character escaped.
///
/// [`Evidence::quote`] is the only way to make one, so a finding cannot hold
/// the raw character and no output format can print it.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Evidence(String);

impl Evidence {
    /// A window of `line` around the character at `at`, counted from zero, no
    /// wider than `width` once escaped, or [`MIN_EVIDENCE_WIDTH`] if that is
    /// wider.
    ///
    /// The line arrives split and masked, so a rule reporting many runs on one
    /// line does that once rather than once per finding.
    #[must_use]
    pub fn quote(line: &Line, at: usize, width: usize) -> Self {
        let line = line.chars();
        if line.is_empty() {
            return Self::default();
        }
        let at = at.min(line.len() - 1);

        // Budgeted on what is written, since one hidden character becomes
        // eight, with room kept for an ellipsis either side.
        let mut budget = width
            .saturating_sub(2)
            .saturating_sub(written(line[at]).chars().count());
        let (mut first, mut last) = (at, at + 1);
        loop {
            let mut grew = false;
            if first > 0 {
                let cost = written(line[first - 1]).chars().count();
                if cost <= budget {
                    budget -= cost;
                    first -= 1;
                    grew = true;
                }
            }
            if last < line.len() {
                let cost = written(line[last]).chars().count();
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
        for c in &line[first..last] {
            out.push_str(&written(*c));
        }
        if last < line.len() {
            out.push('\u{2026}');
        }
        Self(out)
    }

    /// The quoted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
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
    /// The offending text.
    pub evidence: Evidence,
}

/// One character as it is reported.
fn written(c: char) -> String {
    if is_printing(c) {
        c.to_string()
    } else {
        format!("<U+{:04X}>", c as u32)
    }
}

/// Whether a character shows itself. A tab does; a zero-width joiner does not.
fn is_printing(c: char) -> bool {
    c == '\t' || (!c.is_control() && !crate::rules::is_hidden(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted(line: &str, at: usize, width: usize) -> String {
        Evidence::quote(&Line::new(line), at, width)
            .as_str()
            .to_owned()
    }

    #[test]
    fn a_secret_cut_at_the_window_edge_is_still_masked() {
        let line = format!("export API_KEY=sk-live-{}\u{200B}", "S".repeat(60));

        let said = quoted(&line, line.chars().count() - 1, 20);

        assert!(!said.contains('S'), "{said}");
        assert!(said.contains("<U+200B>"), "{said}");
    }

    #[test]
    fn a_hidden_character_is_written_as_its_codepoint() {
        let said = quoted("use the\u{202E}project rules", 7, 80);

        assert!(!said.contains('\u{202E}'), "the character escaped: {said}");
        assert!(said.contains("<U+202E>"), "{said}");
        assert!(said.contains("use the"), "context survives: {said}");
    }

    #[test]
    fn a_tag_character_is_written_as_its_codepoint() {
        assert_eq!(quoted("hi\u{E0041}", 2, 80), "hi<U+E0041>");
    }

    #[test]
    fn printable_text_is_left_alone() {
        assert_eq!(quoted("plain ascii", 0, 80), "plain ascii");
        assert_eq!(quoted("caf\u{e9} and \u{1F600}", 0, 80), "café and 😀");
    }

    /// A minified file is one long line, and a report is not the place to
    /// reproduce it.
    #[test]
    fn a_long_line_is_trimmed_around_the_offence() {
        let line = format!("{}\u{200B}{}", "a".repeat(200), "b".repeat(200));

        let said = quoted(&line, 200, 20);

        assert!(
            said.chars().count() <= 20,
            "{} chars: {said}",
            said.chars().count()
        );
        assert!(said.contains("<U+200B>"), "the offence is kept: {said}");
        assert!(said.starts_with('…') && said.ends_with('…'), "{said}");
    }

    #[test]
    fn a_line_of_hidden_characters_is_still_bounded() {
        let said = quoted(&"\u{200B}".repeat(500), 249, 40);

        assert!(said.chars().count() <= 40, "{} chars", said.chars().count());
    }

    #[test]
    fn a_width_below_the_floor_still_shows_the_offence_within_it() {
        let said = quoted("aaaa\u{E0041}bbbb", 4, 0);

        assert!(said.contains("<U+E0041>"), "{said}");
        assert!(
            said.chars().count() <= MIN_EVIDENCE_WIDTH,
            "{} chars: {said}",
            said.chars().count()
        );
    }

    #[test]
    fn a_rule_reads_as_itself_in_both_directions() {
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(RuleId::InvisibleUnicode.as_str(), "invisible-unicode");
        assert_eq!(
            RuleId::from_catalogue("invisible-unicode"),
            Some(RuleId::InvisibleUnicode)
        );
        assert_eq!(RuleId::from_catalogue("Invisible-Unicode"), None);
    }

    #[test]
    fn findings_sort_by_place() {
        let at = |line, column| Some(Position { line, column });
        let f = |path: &str, at| Finding {
            path: RepoPath::root().join(path),
            at,
            rule: RuleId::InvisibleUnicode,
            severity: Severity::High,
            evidence: Evidence::default(),
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
