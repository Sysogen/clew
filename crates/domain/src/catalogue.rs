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
    /// A row names a kind the domain does not have.
    #[error("row {row} has an unknown kind {kind:?}")]
    UnknownKind {
        /// Which row, counting from zero.
        row: usize,
        /// The kind as written.
        kind: String,
    },
}

/// One row: a pattern, and what matching it means.
#[derive(Debug, Clone, Deserialize)]
pub struct SurfaceRule {
    /// Matched against the repository-relative path.
    pub glob: String,
    /// The tool that owns it. Extraction is dispatched on this.
    pub tool: String,
    /// What it is.
    pub kind: String,
    /// When this row was last checked against primary documentation.
    pub last_verified: String,
    /// The documentation it was checked against.
    pub source: String,
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

        for (row, rule) in file.surface.iter().enumerate() {
            let glob = Glob::new(&rule.glob).map_err(|e| CatalogueError::BadGlob {
                row,
                glob: rule.glob.clone(),
                reason: e.to_string(),
            })?;
            builder.add(glob);

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
        })
    }

    /// The row matching `path`, if any.
    ///
    /// Declaration order decides: the first matching row wins, so a specific
    /// pattern must precede a general one.
    #[must_use]
    pub fn lookup(&self, path: &RepoPath) -> Option<(&SurfaceRule, SurfaceKind)> {
        let first = self.globs.matches(path.as_str()).into_iter().min()?;
        Some((&self.rules[first], self.kinds[first]))
    }

    /// Every row, in declaration order.
    #[must_use]
    pub fn rules(&self) -> &[SurfaceRule] {
        &self.rules
    }
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
                rule.last_verified.len() == 10 && rule.last_verified.starts_with("202"),
                "{} has no verification date",
                rule.glob
            );
        }
    }

    #[test]
    fn declaration_order_resolves_an_overlap() {
        // A SKILL.md inside a hooks directory matches two rows. The hooks row
        // is declared first, so it wins.
        let (_, kind) = shipped()
            .lookup(&p(".claude/skills/git/hooks/SKILL.md"))
            .expect("match");
        assert_eq!(
            kind,
            SurfaceKind::HookScript,
            "the earlier row must win an overlap"
        );

        let (_, settings) = shipped()
            .lookup(&p(".claude/settings.json"))
            .expect("match");
        assert_eq!(settings, SurfaceKind::ClaudeCode);
        let (_, skill) = shipped()
            .lookup(&p(".claude/skills/prose/SKILL.md"))
            .expect("match");
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
