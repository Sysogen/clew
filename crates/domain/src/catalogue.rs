// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The catalogue of recognised surfaces, loaded from `catalogue.toml`.
//!
//! Patterns are data rather than code because tools rename their configuration
//! files often, and a rename should be a reviewable one-line change rather than
//! a release.

use std::sync::OnceLock;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use thiserror::Error;

use crate::extract::{Extraction, Format};
use crate::repo_path::RepoPath;
use crate::scope::Scope;
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
    /// A row names a scope that does not exist.
    #[error("row {row} names an unknown scope {scope:?}")]
    UnknownScope {
        /// Which row, counting from zero.
        row: usize,
        /// The scope as written.
        scope: String,
    },
    /// A row outside a repository whose glob does not begin with a directory.
    #[error("row {row} is scanned from a directory it must name: {glob:?}")]
    UnanchoredRow {
        /// Which row, counting from zero.
        row: usize,
        /// The glob as written.
        glob: String,
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
    /// Which tree it belongs to.
    pub scope: Scope,
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
    /// Which tree it is matched against. Omitted means the repository.
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "repository".to_owned()
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
    scopes: Vec<Scope>,
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
        let mut scopes = Vec::with_capacity(file.surface.len());

        for (row, rule) in file.surface.iter().enumerate() {
            // A `*` stays inside one segment. Crossing them made `.env.*`
            // take a directory named `.env.local`.
            let glob = GlobBuilder::new(&rule.glob)
                .literal_separator(true)
                .build()
                .map_err(|e| CatalogueError::BadGlob {
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

            let scope =
                Scope::from_catalogue(&rule.scope).ok_or_else(|| CatalogueError::UnknownScope {
                    row,
                    scope: rule.scope.clone(),
                })?;
            // A home scan enters only the directories its rows name, so the
            // first segment has to be one.
            let mut segments = rule.glob.split('/');
            let anchored = segments
                .next()
                .is_some_and(|first| !first.is_empty() && !first.contains(['*', '?', '[', '{']));
            // A traversal segment anywhere resolves outside the root the scan
            // was given, so none is allowed at any position.
            let walks_out = rule.glob.split('/').any(|s| s == "." || s == "..");
            if scope != Scope::Repository && (!anchored || walks_out) {
                return Err(CatalogueError::UnanchoredRow {
                    row,
                    glob: rule.glob.clone(),
                });
            }
            scopes.push(scope);
        }

        Ok(Self {
            globs: builder
                .build()
                .map_err(|e| CatalogueError::Invalid(e.to_string()))?,
            rules: file.surface,
            kinds,
            extractions,
            scopes,
            formats,
        })
    }

    /// The row matching `path`, if any.
    ///
    /// Declaration order decides: the first matching row wins, so a specific
    /// pattern must precede a general one.
    #[must_use]
    pub fn lookup(&self, path: &RepoPath) -> Option<Matched<'_>> {
        self.lookup_in(path, Scope::Repository)
    }

    /// The first row of `scope` matching `path`.
    ///
    /// Rows of another scope are not candidates: a home path and a repository
    /// path can read alike, and reporting one as the other would name the
    /// wrong tree.
    #[must_use]
    pub fn lookup_in(&self, path: &RepoPath, scope: Scope) -> Option<Matched<'_>> {
        let first = self
            .globs
            .matches(path.as_str())
            .into_iter()
            .find(|i| self.scopes[*i] == scope)?;
        Some(Matched {
            rule: &self.rules[first],
            kind: self.kinds[first],
            extract: &self.extractions[first],
            format: self.formats[first],
            scope: self.scopes[first],
        })
    }

    /// The rows belonging to one scope.
    #[must_use]
    pub fn rules_in(&self, scope: Scope) -> Vec<&SurfaceRule> {
        self.rules
            .iter()
            .zip(&self.scopes)
            .filter(|(_, s)| **s == scope)
            .map(|(rule, _)| rule)
            .collect()
    }

    /// The directories a scan of `scope` starts from, in order, without
    /// repeats.
    ///
    /// Walking a whole home directory or a whole machine would cost far more
    /// than it finds, so only the directories the rows name are entered.
    #[must_use]
    pub fn roots_in(&self, scope: Scope) -> Vec<&str> {
        let mut roots: Vec<&str> = Vec::new();
        for (rule, wanted) in self.rules.iter().zip(&self.scopes) {
            if *wanted != scope {
                continue;
            }
            let root = literal_prefix(&rule.glob);
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        roots
    }

    /// Every row, in declaration order.
    #[must_use]
    pub fn rules(&self) -> &[SurfaceRule] {
        &self.rules
    }
}

/// Whether `value` is a calendar day written `YYYY-MM-DD`.
/// The directory a glob is rooted at: its leading literal segments, without a
/// trailing filename.
///
/// `etc/devin/rules/**/*.md` is entered at `etc/devin/rules`, not at `etc`, so
/// a scan reads what the row names rather than the rest of the machine.
fn literal_prefix(glob: &str) -> &str {
    let wild = |s: &&str| s.contains(['*', '?', '[', '{']);
    let segments: Vec<&str> = glob.split('/').collect();
    let mut keep = segments.iter().take_while(|s| !wild(s)).count();
    // Every segment is literal, so the last one names the file itself.
    if keep == segments.len() {
        keep = keep.saturating_sub(1);
    }
    if keep == 0 {
        return glob;
    }
    let end = segments[..keep].iter().map(|s| s.len() + 1).sum::<usize>() - 1;
    &glob[..end]
}

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
    use crate::scope::Scope;

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
            (".zed/settings.json", SurfaceKind::Zed),
            (".agents/skills/a/SKILL.md", SurfaceKind::Zed),
            (".rules", SurfaceKind::Zed),
            (".devin/rules/a.md", SurfaceKind::Windsurf),
            (".windsurf/rules/a.md", SurfaceKind::Windsurf),
            (".windsurfrules", SurfaceKind::Windsurf),
            (".continue/config.json", SurfaceKind::Continue),
            ("cline_mcp_settings.json", SurfaceKind::Cline),
            (".clinerules/coding.md", SurfaceKind::Cline),
            ("GEMINI.md", SurfaceKind::InstructionFile),
            ("AGENT.md", SurfaceKind::InstructionFile),
            (".env", SurfaceKind::EnvFile),
            (".env.local", SurfaceKind::EnvFile),
            (".aider.conf.yml", SurfaceKind::Aider),
            (".devcontainer/devcontainer.json", SurfaceKind::DevContainer),
        ];

        assert_eq!(
            expected.len(),
            shipped().rules_in(Scope::Repository).len(),
            "every repository row needs a case here"
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
            (".zed/settings.json", servers),
            (".kiro/hooks/lint-on-save.json", &[Extraction::Hooks][..]),
            (".cursor/mcp.json", servers),
            ("cline_mcp_settings.json", servers),
            (".codex/config.toml", servers),
        ];
        let formats = [
            (".codex/config.toml", Format::Toml),
            (".zed/settings.json", Format::Jsonc),
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

    /// A Zed skill is a named folder holding a SKILL.md. Neither a bare file
    /// nor a deeper tree is one, and reporting either would inventory a file
    /// Zed never loads.
    #[test]
    fn a_zed_skill_is_exactly_one_folder_deep() {
        assert_eq!(
            shipped()
                .lookup(&p(".agents/skills/review/SKILL.md"))
                .map(|m| m.kind),
            Some(SurfaceKind::Zed)
        );
        assert!(shipped().lookup(&p(".agents/skills/SKILL.md")).is_none());
        assert!(
            shipped()
                .lookup(&p(".agents/skills/team/review/SKILL.md"))
                .is_none()
        );
    }

    /// An env file is nothing but values, and clew never reads one. The row
    /// exists so a scan says the credentials are there.
    /// Home rows are the half a scan of a checkout cannot see, so each is
    /// pinned to the tree it belongs to and what it declares.
    #[test]
    fn each_home_surface_keeps_its_own_kind_and_extractions() {
        let all = &[
            Extraction::Hooks,
            Extraction::Permissions,
            Extraction::McpServers,
        ][..];
        let servers = &[Extraction::McpServers][..];
        let expected: &[(&str, SurfaceKind, &[Extraction])] = &[
            (".claude/settings.json", SurfaceKind::ClaudeCode, all),
            (".gemini/settings.json", SurfaceKind::Gemini, servers),
            (".kiro/settings/mcp.json", SurfaceKind::Kiro, servers),
            (".kiro/steering/product.md", SurfaceKind::Kiro, &[]),
            (
                ".codeium/windsurf/mcp_config.json",
                SurfaceKind::Windsurf,
                servers,
            ),
            (
                ".codeium/windsurf/memories/global_rules.md",
                SurfaceKind::Windsurf,
                &[],
            ),
            (".agents/skills/a/SKILL.md", SurfaceKind::Zed, &[]),
            (".agents/AGENTS.md", SurfaceKind::InstructionFile, &[]),
        ];

        assert_eq!(
            expected.len(),
            shipped().rules_in(Scope::Home).len(),
            "every home row needs a case here"
        );

        for (path, kind, extract) in expected {
            let m = shipped()
                .lookup_in(&p(path), Scope::Home)
                .unwrap_or_else(|| panic!("{path} matched no home row"));
            assert_eq!(m.kind, *kind, "{path}");
            assert_eq!(m.extract, *extract, "{path}");
            assert_eq!(m.scope, Scope::Home, "{path}");
        }
    }

    /// The two trees are matched separately. A repository holding a .claude
    /// directory must not be read against a home row, or the report names the
    /// wrong tree.
    #[test]
    fn a_scope_never_matches_a_row_from_the_other() {
        assert!(
            shipped()
                .lookup_in(&p(".codeium/windsurf/mcp_config.json"), Scope::Repository)
                .is_none(),
            "a home-only path has no repository row"
        );
        assert!(
            shipped().lookup_in(&p("CLAUDE.md"), Scope::Home).is_none(),
            "a repository-only path has no home row"
        );
        assert_eq!(
            shipped()
                .lookup_in(&p(".claude/settings.json"), Scope::Home)
                .map(|m| m.scope),
            Some(Scope::Home),
            "a path both trees use resolves to the tree asked for"
        );
    }

    /// A home row names the directory the scan enters. A traversal segment
    /// would send it above the home directory, or into all of it.
    #[test]
    fn a_row_outside_a_repository_cannot_walk_out_of_its_root() {
        for glob in ["../outside/**", "./**", ".", ".."] {
            let error = Catalogue::load(&format!(
                r#"version = 1
                   [[surface]]
                   scope = "home"
                   glob = "{glob}"
                   tool = "x"
                   kind = "skill"
                   last_verified = "2026-09-12"
                   source = "https://example.invalid"
                "#
            ))
            .expect_err("{glob} must not load");
            assert!(
                matches!(error, CatalogueError::UnanchoredRow { .. }),
                "{glob}: {error:?}"
            );
        }
    }

    #[test]
    fn a_scan_enters_only_the_directories_its_rows_name() {
        assert_eq!(
            shipped().roots_in(Scope::Home),
            vec![
                ".claude",
                ".gemini",
                ".kiro/settings",
                ".kiro/steering",
                ".codeium/windsurf",
                ".codeium/windsurf/memories",
                ".agents/skills",
                ".agents"
            ]
        );
        assert_eq!(
            shipped().roots_in(Scope::System),
            vec!["etc/devin/rules", "etc/windsurf/rules"],
            "a system scan reads what the rows name, not the rest of /etc"
        );
    }

    /// A row must name a directory the scan can enter, and a traversal segment
    /// anywhere resolves outside the root the scan was given.
    #[test]
    fn a_row_outside_a_repository_cannot_reach_past_its_root() {
        for glob in ["foo/../../outside/**/*.md", "a/./b/**/*.md", "a/../b"] {
            let error = Catalogue::load(&format!(
                r#"version = 1
                   [[surface]]
                   scope = "home"
                   glob = "{glob}"
                   tool = "x"
                   kind = "skill"
                   last_verified = "2026-09-12"
                   source = "https://example.invalid"
                "#
            ))
            .expect_err("must not load");
            assert!(
                matches!(error, CatalogueError::UnanchoredRow { .. }),
                "{glob}: {error:?}"
            );
        }
    }

    /// Policy an administrator deploys is not in any repository and not in any
    /// home directory, and nobody being scanned chose it.
    #[test]
    fn each_system_surface_keeps_its_own_kind() {
        let expected = [
            ("etc/devin/rules/policy.md", SurfaceKind::Windsurf),
            ("etc/windsurf/rules/policy.md", SurfaceKind::Windsurf),
        ];

        assert_eq!(
            expected.len(),
            shipped().rules_in(Scope::System).len(),
            "every system row needs a case here"
        );

        for (path, kind) in expected {
            let m = shipped()
                .lookup_in(&p(path), Scope::System)
                .unwrap_or_else(|| panic!("{path} matched no system row"));
            assert_eq!(m.kind, kind, "{path}");
            assert!(m.extract.is_empty(), "{path} is inventory");
        }

        assert!(
            shipped()
                .lookup_in(&p("etc/devin/rules/policy.md"), Scope::Home)
                .is_none(),
            "a system path is not a home row"
        );
    }

    #[test]
    fn env_files_are_matched_and_never_read() {
        for path in [".env", ".env.local", ".env.production", "api/.env"] {
            let m = shipped()
                .lookup(&p(path))
                .unwrap_or_else(|| panic!("{path}"));
            assert_eq!(m.kind, SurfaceKind::EnvFile, "{path}");
            assert!(m.extract.is_empty(), "{path} must never be opened");
        }
    }

    /// `.envrc` is a direnv script, not an env file, and a directory named
    /// `.env` holds paths rather than values.
    #[test]
    fn the_env_rows_stop_at_env_files() {
        assert!(shipped().lookup(&p(".envrc")).is_none());
        assert!(shipped().lookup(&p(".env/sub/file")).is_none());
        assert!(
            shipped()
                .lookup(&p("services/.env.local/README.md"))
                .is_none(),
            "a directory named .env.local holds paths, not values"
        );
        assert!(shipped().lookup(&p("environment.txt")).is_none());
    }

    #[test]
    fn cline_reads_markdown_and_text_in_its_rules_directory() {
        for path in [
            ".clinerules/a.md",
            ".clinerules/b.txt",
            "api/.clinerules/c/d.md",
        ] {
            assert_eq!(
                shipped().lookup(&p(path)).map(|m| m.kind),
                Some(SurfaceKind::Cline),
                "{path}"
            );
        }
        assert!(
            shipped().lookup(&p(".clinerules/notes.json")).is_none(),
            "Cline processes .md and .txt there, nothing else"
        );
    }

    /// A rules directory may hold a file named for another tool. The specific
    /// row must win, which is why the shared names are listed last.
    #[test]
    fn a_shared_name_inside_a_rules_directory_keeps_its_own_row() {
        assert_eq!(
            shipped()
                .lookup(&p(".devin/rules/AGENT.md"))
                .map(|m| m.kind),
            Some(SurfaceKind::Windsurf)
        );
        assert_eq!(
            shipped().lookup(&p("AGENT.md")).map(|m| m.kind),
            Some(SurfaceKind::InstructionFile)
        );
    }

    #[test]
    fn windsurf_rules_match_in_both_directories_and_at_the_root() {
        for path in [
            ".devin/rules/style.md",
            ".windsurf/rules/style.md",
            "packages/api/.devin/rules/nested/a.md",
            ".windsurfrules",
        ] {
            assert_eq!(
                shipped().lookup(&p(path)).map(|m| m.kind),
                Some(SurfaceKind::Windsurf),
                "{path}"
            );
        }
    }

    #[test]
    fn zed_skills_are_inventory_while_claude_skills_are_read() {
        let zed = shipped()
            .lookup(&p(".agents/skills/a/SKILL.md"))
            .expect("match");
        assert!(
            zed.extract.is_empty(),
            "Zed documents no grant in its frontmatter"
        );

        let claude = shipped()
            .lookup(&p(".claude/skills/a/SKILL.md"))
            .expect("match");
        assert_eq!(claude.extract, &[Extraction::Permissions]);
    }

    /// The two rows overlap, and only their order separates them.
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
