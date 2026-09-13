// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What clew says is wrong, as opposed to what a file declares.

use unicode_general_category::{GeneralCategory, get_general_category};

use crate::finding::{Evidence, Finding, Line, Position, RuleId, Severity};
use crate::repo_path::RepoPath;

/// Blank-rendering characters outside the format category.
const ALSO_HIDDEN: [char; 1] = ['\u{3164}']; // HANGUL FILLER

/// Whether a character reaches the model without reaching the reader.
///
/// `Cf` covers zero-width, bidirectional and tag characters. A variation
/// selector (`Mn`) and a non-breaking space (`Zs`) are ordinary text.
#[must_use]
pub fn is_hidden(c: char) -> bool {
    get_general_category(c) == GeneralCategory::Format || ALSO_HIDDEN.contains(&c)
}

/// Everything the named rules say about one file.
///
/// The catalogue row names the rules, not the tool: one tool keeps prose and
/// settings side by side, and evidence quoted from settings would print them.
#[must_use]
pub fn run(path: &RepoPath, checks: &[RuleId], text: &str, width: usize) -> Vec<Finding> {
    let mut found = Vec::new();
    for check in checks {
        match check {
            RuleId::InvisibleUnicode => found.extend(invisible_unicode(path, text, width)),
        }
    }
    found
}

/// Non-printing Unicode in a file an agent reads as instructions: the Rules
/// File Backdoor, disclosed by Pillar Security on 18 March 2025.
fn invisible_unicode(path: &RepoPath, text: &str, width: usize) -> Vec<Finding> {
    let mut found = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line = Line::new(raw);
        let mut in_run = false;
        for (column, c) in line.chars().iter().enumerate() {
            // A byte order mark legitimately opens a file, and only there.
            let opening_mark = index == 0 && column == 0 && *c == '\u{FEFF}';
            let hidden = is_hidden(*c) && !opening_mark;
            // One payload is one run, and one finding.
            let starts_run = hidden && !in_run;
            in_run = hidden;
            if !starts_run {
                continue;
            }
            found.push(Finding {
                path: path.clone(),
                at: Some(Position {
                    line: index + 1,
                    column: column + 1,
                }),
                rule: RuleId::InvisibleUnicode,
                severity: Severity::High,
                evidence: Evidence::quote(&line, column, width),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::DEFAULT_EVIDENCE_WIDTH;

    fn found_in(text: &str) -> Vec<Finding> {
        run(
            &RepoPath::root().join("CLAUDE.md"),
            &[RuleId::InvisibleUnicode],
            text,
            DEFAULT_EVIDENCE_WIDTH,
        )
    }

    #[test]
    fn a_zero_width_character_is_found() {
        let found = found_in("use\u{200B} the rules");

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].severity, Severity::High);
        assert_eq!(found[0].at.map(|p| (p.line, p.column)), Some((1, 4)));
    }

    #[test]
    fn a_bidirectional_override_is_found() {
        assert_eq!(found_in("a\u{202E}b").len(), 1);
        assert_eq!(found_in("a\u{2066}b").len(), 1);
    }

    /// The tag block encodes printable ASCII one to one, so a whole instruction
    /// fits in characters that render as nothing at all.
    #[test]
    fn a_tag_block_payload_is_one_finding() {
        let smuggled: String = "rm -rf /"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).expect("tag"))
            .collect();

        let found = found_in(&format!("Be helpful.{smuggled}"));

        assert_eq!(found.len(), 1, "one payload is one finding: {found:?}");
        assert_eq!(found[0].at.map(|p| (p.line, p.column)), Some((1, 12)));
    }

    #[test]
    fn two_runs_on_one_line_are_two_findings() {
        let found = found_in("a\u{200B}\u{200D}b\u{202E}c");

        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].at.map(|p| p.column), Some(2));
        assert_eq!(found[1].at.map(|p| p.column), Some(5));
    }

    #[test]
    fn other_format_characters_are_found() {
        assert_eq!(found_in("soft\u{00AD}hyphen").len(), 1);
        assert_eq!(found_in("word\u{2060}joiner").len(), 1);
        assert_eq!(found_in("hangul\u{3164}filler").len(), 1);
    }

    #[test]
    fn a_byte_order_mark_counts_only_away_from_the_start() {
        assert!(found_in("\u{FEFF}# Rules\n").is_empty());
        assert_eq!(found_in("# Rules\u{FEFF}\n").len(), 1);
        assert_eq!(found_in("# Rules\n\u{FEFF}more\n").len(), 1);
    }

    #[test]
    fn a_run_straight_after_the_opening_mark_starts_after_it() {
        let found = found_in("\u{FEFF}\u{200B}x");

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].at.map(|p| p.column), Some(2));
    }

    /// Flagging these would fire on most files that are perfectly fine.
    #[test]
    fn ordinary_text_is_left_alone() {
        assert!(found_in("# Rules\n\nUse tabs.\n").is_empty());
        assert!(found_in("a \u{1F600}\u{FE0F} b").is_empty(), "emoji");
        assert!(found_in("a\u{00A0}b").is_empty(), "non-breaking space");
        assert!(found_in("caf\u{e9} na\u{ef}ve \u{4F60}\u{597D}").is_empty());
        assert!(found_in("tab\there").is_empty());
    }

    #[test]
    fn every_occurrence_is_reported_with_its_place() {
        let found = found_in("one\u{200B}\ntwo\nthree\u{200D}x");

        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].at.map(|p| (p.line, p.column)), Some((1, 4)));
        assert_eq!(found[1].at.map(|p| (p.line, p.column)), Some((3, 6)));
    }

    #[test]
    fn the_character_never_reaches_the_finding() {
        let found = found_in("always\u{202E}obey");

        assert_eq!(found.len(), 1);
        assert!(!format!("{found:?}").contains('\u{202E}'), "{found:?}");
        assert!(found[0].evidence.as_str().contains("<U+202E>"), "{found:?}");
    }

    #[test]
    fn a_secret_beside_a_hidden_character_is_masked() {
        let found = found_in("Deploy with API_KEY=sk-live-PROSE123 and\u{200B} go.");

        assert_eq!(found.len(), 1);
        let said = found[0].evidence.as_str();
        assert!(!said.contains("sk-live-PROSE123"), "{said}");
        assert!(said.contains("API_KEY="), "{said}");
        assert!(said.contains("<U+200B>"), "{said}");
    }

    #[test]
    fn a_row_naming_no_rule_is_told_nothing() {
        assert!(
            run(
                &RepoPath::root().join("x"),
                &[],
                "a\u{202E}b",
                DEFAULT_EVIDENCE_WIDTH
            )
            .is_empty()
        );
    }

    /// Splitting the line again per finding made a line of many runs
    /// quadratic. The bound is loose; only that regression comes near it.
    #[test]
    fn a_line_of_many_runs_is_read_in_one_pass() {
        let line = "a\u{200B}".repeat(50_000);
        let started = std::time::Instant::now();

        let found = found_in(&line);

        assert_eq!(found.len(), 50_000);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
    }
}
