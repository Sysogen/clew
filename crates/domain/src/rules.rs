// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What clew says is wrong, as opposed to what a file declares.

use unicode_general_category::{GeneralCategory, get_general_category};

use crate::finding::{Finding, Position, RuleId, Severity, evidence};
use crate::repo_path::RepoPath;
use crate::surface::SurfaceKind;

/// Characters that render as nothing without carrying the format category.
/// `Cf` covers the rest, including the tag block that encodes ASCII invisibly.
const ALSO_HIDDEN: [char; 1] = ['\u{3164}']; // HANGUL FILLER

/// Whether a character reaches the model without reaching the reader.
///
/// A variation selector is `Mn` and sits in ordinary emoji, and a non-breaking
/// space is `Zs` and shows as a space. Neither is hidden, and flagging either
/// would fire on most files that are perfectly fine.
#[must_use]
pub fn is_hidden(c: char) -> bool {
    get_general_category(c) == GeneralCategory::Format || ALSO_HIDDEN.contains(&c)
}

/// Whether any rule reads this kind of file.
///
/// A hook script may be a compiled binary and an env file is credential values,
/// so neither is opened whatever a rule might want.
#[must_use]
pub fn applies_to(kind: SurfaceKind) -> bool {
    matches!(
        kind,
        SurfaceKind::InstructionFile
            | SurfaceKind::Skill
            | SurfaceKind::Cursor
            | SurfaceKind::Kiro
            | SurfaceKind::Windsurf
            | SurfaceKind::Copilot
            | SurfaceKind::Zed
    )
}

/// Everything the rules say about one file.
#[must_use]
pub fn run(path: &RepoPath, kind: SurfaceKind, text: &str, width: usize) -> Vec<Finding> {
    if !applies_to(kind) {
        return Vec::new();
    }
    invisible_unicode(path, text, width)
}

/// Non-printing Unicode in a file an agent reads as instructions.
///
/// Rules File Backdoor, disclosed by Pillar Security on 18 March 2025: text the
/// reviewer cannot see and the model acts on. There is no legitimate use in a
/// file of this kind, which is why the rule needs no heuristic.
fn invisible_unicode(path: &RepoPath, text: &str, width: usize) -> Vec<Finding> {
    let mut found = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let mut in_run = false;
        for (column, c) in line.chars().enumerate() {
            // A byte order mark opens a file legitimately. The same character
            // anywhere else was put there to be unseen.
            let opening_mark = index == 0 && column == 0 && c == '\u{FEFF}';
            let hidden = is_hidden(c) && !opening_mark;
            // A smuggled instruction is one run of characters. Reporting each
            // one would turn a single payload into a page of findings.
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
                evidence: evidence(line, column + 1, width),
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
            SurfaceKind::InstructionFile,
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
    fn a_tag_block_character_is_found() {
        let smuggled: String = "rm -rf /"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).expect("tag"))
            .collect();

        let found = found_in(&format!("Be helpful.{smuggled}"));

        assert_eq!(found.len(), 1, "one payload is one finding: {found:?}");
        assert_eq!(found[0].at.map(|p| (p.line, p.column)), Some((1, 12)));
    }

    /// Visible text between two runs makes them two places to look.
    #[test]
    fn two_runs_on_one_line_are_two_findings() {
        let found = found_in("a\u{200B}\u{200D}b\u{202E}c");

        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].at.map(|p| p.column), Some(2));
        assert_eq!(found[1].at.map(|p| p.column), Some(5));
    }

    /// The opening mark is not part of a run that follows it.
    #[test]
    fn a_run_straight_after_the_opening_mark_starts_after_it() {
        let found = found_in("\u{FEFF}\u{200B}x");

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].at.map(|p| p.column), Some(2));
    }

    #[test]
    fn other_format_characters_are_found() {
        assert_eq!(found_in("soft\u{00AD}hyphen").len(), 1);
        assert_eq!(found_in("word\u{2060}joiner").len(), 1);
        assert_eq!(found_in("hangul\u{3164}filler").len(), 1);
    }

    /// A byte order mark opens a file legitimately, and only there.
    #[test]
    fn a_byte_order_mark_counts_only_away_from_the_start() {
        assert!(found_in("\u{FEFF}# Rules\n").is_empty());
        assert_eq!(found_in("# Rules\u{FEFF}\n").len(), 1);
        assert_eq!(found_in("# Rules\n\u{FEFF}more\n").len(), 1);
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

    /// The evidence is what a reader sees, so it must not carry the payload.
    #[test]
    fn the_character_never_reaches_the_finding() {
        let found = found_in("always\u{202E}obey");

        assert_eq!(found.len(), 1);
        assert!(!found[0].evidence.contains('\u{202E}'), "{found:?}");
        assert!(format!("{found:?}").contains("<U+202E>"), "{found:?}");
    }

    /// A settings file is out of scope for this rule, and a hook script and an
    /// env file are never opened at all.
    #[test]
    fn a_kind_no_rule_applies_to_yields_nothing() {
        for kind in [
            SurfaceKind::ClaudeCode,
            SurfaceKind::HookScript,
            SurfaceKind::EnvFile,
            SurfaceKind::McpServers,
        ] {
            assert!(!applies_to(kind), "{kind:?}");
            assert!(
                run(
                    &RepoPath::root().join("x"),
                    kind,
                    "a\u{202E}b",
                    DEFAULT_EVIDENCE_WIDTH
                )
                .is_empty(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_kinds_a_rule_reads_are_the_files_a_model_reads_as_prose() {
        for kind in [
            SurfaceKind::InstructionFile,
            SurfaceKind::Skill,
            SurfaceKind::Cursor,
            SurfaceKind::Kiro,
            SurfaceKind::Windsurf,
            SurfaceKind::Copilot,
            SurfaceKind::Zed,
        ] {
            assert!(applies_to(kind), "{kind:?}");
        }
    }
}
