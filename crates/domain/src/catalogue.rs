// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The catalogue of recognised surfaces, loaded from `catalogue.toml`.
//!
//! Patterns are data rather than code because tools rename their configuration
//! files often, and a rename should be a reviewable one-line change rather than
//! a release.

use std::sync::OnceLock;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use thiserror::Error;

use crate::extract::{Extraction, Format};
use crate::repo_path::RepoPath;
use crate::surface::SurfaceKind;

/// The catalogue as shipped, embedded so the binary needs no data files.
const SOURCE: &str = include_str!("../catalogue.toml");

/// Why a catalogue could not be loaded.
#[derive(Debug, Error)]
pub enum CatalogueError {
    /// The file is not valid TOML, or does not match the expected shape.
    #[error("catalogue is not valid: {0}")]
    Invalid(String),
    /// A row carries a glob the matcher cannot compile.
    #[error("row {row} has an invalid glob {glob:?}: {reason}")]
    BadGlob {
        /// Which row, counting from zero.
        row: usize,
        /// The glob as written.
        glob: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A row carries a date that is not a real calendar day.
    #[error("row {row} has an invalid last_verified {date:?}")]
    BadDate {
        /// Which row, counting from zero.
        row: usize,
        /// The date as written.
        date: String,
    },
    /// A row names an extraction that does not exist.
    #[error("row {row} names an unknown extraction {extraction:?}")]
    UnknownExtraction {
        /// Which row, counting from zero.
        row: usize,
        /// The extraction as written.
        extraction: String,
    },
    /// A row names a format that does not exist.
    #[error("row {row} names an unknown format {format:?}")]
    UnknownFormat {
        /// Which row, counting from zero.
        row: usize,
        /// The format as written.
        format: String,
    },
    /// A row names a kind the domain does not have.
    #[error("row {row} has an unknown kind {kind:?}")]
    UnknownKind {
        /// Which row, counting from zero.
        row: usize,
        /// The kind as written.
        kind: String,
    },
}

/// What a path matched.
#[derive(Debug, Clone, Copy)]
pub struct Matched<'a> {
    /// The row itself.
    pub rule: &'a SurfaceRule,
    /// What the file is.
    pub kind: SurfaceKind,
    /// What to read out of it. Empty means inventory only.
    pub extract: &'a [Extraction],
    /// How the file is written.
    pub format: Format,
}

/// One row: a pattern, and what matching it means.
#[derive(Debug, Clone, Deserialize)]
pub struct SurfaceRule {
    /// Matched against the repository-relative path.
    pub glob: String,
    /// The tool that owns it, for reporting. What to read is `extract`.
    pub tool: String,
    /// What it is.
    pub kind: String,
    /// What to read out of it. Empty means inventory only.
    #[serde(default)]
    pub extract: Vec<String>,
    /// How the file is written. Omitted means JSON.
    #[serde(default = "default_format")]
    pub format: String,
    /// When this row was last checked against primary documentation.
    pub last_verified: String,
    /// The documentation it was checked against.
    pub source: String,
}

fn default_format() -> String {
    "json".to_owned()
}

#[derive(Debug, Deserialize)]
struct CatalogueFile {
    #[allow(dead_code)]
    version: u32,
    surface: Vec<SurfaceRule>,
}

/// Every recognised surface, and a compiled matcher over their globs.
#[derive(Debug)]
pub struct Catalogue {
    rules: Vec<SurfaceRule>,
    kinds: Vec<SurfaceKind>,
    extractions: Vec<Vec<Extraction>>,
    formats: Vec<Format>,
    globs: GlobSet,
}

impl Catalogue {
    /// Load and compile a catalogue from TOML.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is malformed, a glob will not compile, or
    /// a row names a kind that does not exist.
    pub fn load(source: &str) -> Result<Self, CatalogueError> {
        let file: CatalogueFile =
            toml::from_str(source).map_err(|e| CatalogueError::Invalid(e.to_string()))?;

        let mut builder = GlobSetBuilder::new();
        let mut kinds = Vec::with_capacity(file.surface.len());
        let mut extractions = Vec::with_capacity(file.surface.len());
        let mut formats = Vec::with_capacity(file.surface.len());

        for (row, rule) in file.surface.iter().enumerate() {
            let glob = Glob::new(&rule.glob).map_err(|e| CatalogueError::BadGlob {
                row,
                glob: rule.glob.clone(),
                reason: e.to_string(),
            })?;
            builder.add(glob);

            if !is_iso_date(&rule.last_verified) {
                return Err(CatalogueError::BadDate {
                    row,
                    date: rule.last_verified.clone(),
                });
            }

            extractions.push(
                rule.extract
                    .iter()
                    .map(|name| {
                        Extraction::from_catalogue(name).ok_or_else(|| {
                            CatalogueError::UnknownExtraction {
                                row,
                                extraction: name.clone(),
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            formats.push(Format::from_catalogue(&rule.format).ok_or_else(|| {
                CatalogueError::UnknownFormat {
                    row,
                    format: rule.format.clone(),
                }
            })?);

            kinds.push(SurfaceKind::from_catalogue(&rule.kind).ok_or_else(|| {
                CatalogueError::UnknownKind {
                    row,
                    kind: rule.kind.clone(),
                }
            })?);
        }

        Ok(Self {
            globs: builder
                .build()
                .map_err(|e| CatalogueError::Invalid(e.to_string()))?,
            rules: file.surface,
            kinds,
            extractions,
            formats,
        })
    }

    /// The row matching `path`, if any.
    ///
    /// Declaration order decides: the first matching row wins, so a specific
    /// pattern must precede a general one.
    #[must_use]
    pub fn lookup(&self, path: &RepoPath) -> Option<Matched<'_>> {
        let first = self.globs.matches(path.as_str()).into_iter().min()?;
        Some(Matched {
            rule: &self.rules[first],
            kind: self.kinds[first],
            extract: &self.extractions[first],
            format: self.formats[first],
        })
    }

    /// Every row, in declaration order.
    #[must_use]
    pub fn rules(&self) -> &[SurfaceRule] {
        &self.rules
    }
}

/// Whether `value` is a calendar day written `YYYY-MM-DD`.
fn is_iso_date(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    let [y, m, d] = parts[..] else { return false };
    if (y.len(), m.len(), d.len()) != (4, 2, 2) {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (y.parse::<u16>(), m.parse::<u8>(), d.parse::<u8>())
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=last).contains(&day)
}

/// The catalogue shipped with this build.
///
/// # Panics
///
/// Panics when the embedded catalogue is malformed, which a test prevents from
/// ever reaching a release.
// A malformed embedded catalogue is a build defect, not a runtime condition:
// the file is a compile-time constant of our own, and a test rejects it before
// release. Failing loudly at first use is the correct response to a broken
// invariant.
#[allow(clippy::panic)]
#[must_use]
pub fn shipped() -> &'static Catalogue {
    static SHIPPED: OnceLock<Catalogue> = OnceLock::new();
    SHIPPED.get_or_init(|| match Catalogue::load(SOURCE) {
        Ok(catalogue) => catalogue,
        Err(error) => panic!("the embedded catalogue is malformed: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RepoPath {
        s.split('/')
            .fold(RepoPath::root(), |acc, seg| acc.join(seg))
    }

    #[test]
    fn the_shipped_catalogue_loads() {
        let catalogue = Catalogue::load(SOURCE).expect("the shipped catalogue must be valid");
        assert!(!catalogue.rules().is_empty());
    }

    #[test]
    fn every_row_carries_a_dated_citation() {
        for rule in shipped().rules() {
            assert!(
                rule.source.starts_with("https://"),
                "{} has no source",
                rule.glob
            );
            assert!(
                is_iso_date(&rule.last_verified),
                "{} has no valid verification date",
                rule.glob
            );
        }
    }

    /// Each tool keeps its own label. A refactor that collapsed several tools
    /// onto one kind reported `.aider.conf.yml` as "Claude Code", and no test
    /// noticed, so this pins every row.
    #[test]
    fn each_surface_keeps_its_own_kind_and_extractions() {
        let expected = [
            (".claude/settings.json", SurfaceKind::ClaudeCode),
            (".claude/settings.local.json", SurfaceKind::ClaudeCode),
            (".mcp.json", SurfaceKind::McpServers),
            (".claude/hooks/x.sh", SurfaceKind::HookScript),
            (".claude/skills/a/SKILL.md", SurfaceKind::Skill),
            ("CLAUDE.md", SurfaceKind::InstructionFile),
            ("AGENTS.md", SurfaceKind::InstructionFile),
            (".kiro/settings/mcp.json", SurfaceKind::Kiro),
            (".kiro/steering/product.md", SurfaceKind::Kiro),
            (".kiro/hooks/lint-on-save.json", SurfaceKind::Kiro),
            (".codex/config.toml", SurfaceKind::Codex),
            (".gemini/settings.json", SurfaceKind::Gemini),
            (".cursor/mcp.json", SurfaceKind::Cursor),
            (".cursor/rules/react.mdc", SurfaceKind::Cursor),
            (".cursorrules", SurfaceKind::Cursor),
            (".vscode/mcp.json", SurfaceKind::VsCode),
            (".vscode/tasks.json", SurfaceKind::VsCode),
            (".github/copilot-instructions.md", SurfaceKind::Copilot),
            (".continue/config.json", SurfaceKind::Continue),
            ("cline_mcp_settings.json", SurfaceKind::Cline),
            (".aider.conf.yml", SurfaceKind::Aider),
            (".devcontainer/devcontainer.json", SurfaceKind::DevContainer),
        ];

        assert_eq!(
            expected.len(),
            shipped().rules().len(),
            "every catalogue row needs a case here"
        );

        let all = &[
            Extraction::Hooks,
            Extraction::Permissions,
            Extraction::McpServers,
        ][..];
        let servers = &[Extraction::McpServers][..];
        let parsed = [
            (".claude/settings.json", all),
            (".claude/settings.local.json", all),
            (".claude/skills/a/SKILL.md", &[Extraction::Permissions][..]),
            (".mcp.json", servers),
            (".gemini/settings.json", servers),
            (".kiro/settings/mcp.json", servers),
            (".kiro/hooks/lint-on-save.json", &[Extraction::Hooks][..]),
            (".cursor/mcp.json", servers),
            ("cline_mcp_settings.json", servers),
            (".codex/config.toml", servers),
        ];
        let formats = [
            (".codex/config.toml", Format::Toml),
            (".claude/skills/a/SKILL.md", Format::Markdown),
        ];

        for (path, kind) in expected {
            let matched = shipped()
                .lookup(&p(path))
                .unwrap_or_else(|| panic!("{path} matched no row"));
            assert_eq!(matched.kind, kind, "{path}");

            let want = parsed
                .iter()
                .find(|(q, _)| *q == path)
                .map_or(&[][..], |(_, e)| *e);
            assert_eq!(
                matched.extract, want,
                "{path} declares the wrong extractions"
            );

            let expected_format = formats
                .iter()
                .find(|(q, _)| *q == path)
                .map_or(Format::Json, |(_, f)| *f);
            assert_eq!(matched.format, expected_format, "{path}");
        }
    }

    #[test]
    fn declaration_order_resolves_an_overlap() {
        // A SKILL.md inside a hooks directory matches two rows. The hooks row
        // is declared first, so it wins.
        let kind = shipped()
            .lookup(&p(".claude/skills/git/hooks/SKILL.md"))
            .expect("match")
            .kind;
        assert_eq!(
            kind,
            SurfaceKind::HookScript,
            "the earlier row must win an overlap"
        );

        let settings = shipped()
            .lookup(&p(".claude/settings.json"))
            .expect("match")
            .kind;
        assert_eq!(settings, SurfaceKind::ClaudeCode);
        let skill = shipped()
            .lookup(&p(".claude/skills/prose/SKILL.md"))
            .expect("match")
            .kind;
        assert_eq!(skill, SurfaceKind::Skill);
    }

    #[test]
    fn a_hooks_directory_must_sit_below_claude() {
        assert!(shipped().lookup(&p(".claude/hooks/x.sh")).is_some());
        assert!(
            shipped()
                .lookup(&p(".claude/skills/git/hooks/pre-push"))
                .is_some()
        );
        assert!(
            shipped().lookup(&p("hooks/.claude/readme")).is_none(),
            "hooks is an ancestor here"
        );
        assert!(shipped().lookup(&p(".git/hooks/pre-commit")).is_none());
    }

    #[test]
    fn an_invalid_glob_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 1
               [[surface]]
               glob = "["
               tool = "x"
               kind = "settings"
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("an unclosed class must not load");
        assert!(matches!(error, CatalogueError::BadGlob { .. }), "{error:?}");
    }

    #[test]
    fn an_unknown_kind_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "not-a-kind"
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("an unknown kind must not load");
        assert!(
            matches!(error, CatalogueError::UnknownKind { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn an_unknown_format_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               format = "yaml"
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("a format clew cannot parse must not load");
        assert!(
            matches!(error, CatalogueError::UnknownFormat { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn an_unknown_extraction_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               extract = ["not-a-thing"]
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("an unknown extraction must not load");
        assert!(
            matches!(error, CatalogueError::UnknownExtraction { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn kiro_surfaces_match_below_the_repository_root() {
        for path in [
            "packages/api/.kiro/settings/mcp.json",
            "packages/api/.kiro/steering/nested/rules.md",
            "packages/api/.kiro/hooks/lint.json",
        ] {
            assert_eq!(
                shipped().lookup(&p(path)).map(|m| m.kind),
                Some(SurfaceKind::Kiro),
                "{path}"
            );
        }
    }

    /// AGENTS.md lives inside Kiro's steering directory as well as at a
    /// repository root, so the two rows overlap and only the order separates
    /// them. The specific one must win, or the file is filed under the wrong
    /// tool.
    #[test]
    fn a_steering_agents_file_is_kiro_not_the_generic_row() {
        assert_eq!(
            shipped()
                .lookup(&p(".kiro/steering/AGENTS.md"))
                .map(|m| m.kind),
            Some(SurfaceKind::Kiro)
        );
        assert_eq!(
            shipped().lookup(&p("AGENTS.md")).map(|m| m.kind),
            Some(SurfaceKind::InstructionFile),
            "a root AGENTS.md is still the generic row"
        );
    }

    /// Cursor organises rules in folders, and ignores a plain `.md` placed
    /// among them. Matching one would report a file the tool never reads.
    #[test]
    fn cursor_rules_match_at_any_depth_and_only_as_mdc() {
        for path in [
            ".cursor/rules/react.mdc",
            ".cursor/rules/frontend/components.mdc",
            "packages/web/.cursor/rules/a/b/deep.mdc",
        ] {
            assert_eq!(
                shipped().lookup(&p(path)).map(|m| m.kind),
                Some(SurfaceKind::Cursor),
                "{path}"
            );
        }

        assert!(
            shipped()
                .lookup(&p(".cursor/rules/api-guidelines.md"))
                .is_none(),
            "Cursor ignores a plain .md here, so clew must not claim it"
        );
    }

    #[test]
    fn a_row_without_extract_is_inventory_only() {
        let hook = shipped().lookup(&p(".claude/hooks/x.sh")).expect("match");
        assert!(
            hook.extract.is_empty(),
            "a hook script may be a binary and must never be opened"
        );

        let instruction = shipped().lookup(&p("CLAUDE.md")).expect("match");
        assert!(
            instruction.extract.is_empty(),
            "an instruction file declares prose, not access"
        );

        let settings = shipped()
            .lookup(&p(".claude/settings.json"))
            .expect("match");
        assert_eq!(settings.extract.len(), 3, "{:?}", settings.extract);
    }

    #[test]
    fn a_malformed_date_is_rejected_at_load() {
        for bad in [
            "2026-99-99",
            "2026-09-XX",
            "2026-02-30",
            "2026-9-1",
            "",
            "2026-13-01",
        ] {
            let toml = format!(
                r#"version = 1
                   [[surface]]
                   glob = "x"
                   tool = "x"
                   kind = "skill"
                   last_verified = "{bad}"
                   source = "https://example.invalid"
                "#
            );
            let error = Catalogue::load(&toml).expect_err("not a calendar day");
            assert!(
                matches!(error, CatalogueError::BadDate { .. }),
                "{bad}: {error:?}"
            );
        }

        let leap = r#"version = 1
                      [[surface]]
                      glob = "x"
                      tool = "x"
                      kind = "skill"
                      last_verified = "2024-02-29"
                      source = "https://example.invalid"
                   "#;
        assert!(Catalogue::load(leap).is_ok(), "a real leap day must load");
    }

    #[test]
    fn a_row_missing_its_citation_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "settings"
            "#,
        )
        .expect_err("a row without a date or source must not load");
        assert!(matches!(error, CatalogueError::Invalid(_)), "{error:?}");
    }
}
