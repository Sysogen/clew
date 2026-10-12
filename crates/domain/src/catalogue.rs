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
use crate::finding::RuleId;
use crate::repo_path::RepoPath;
use crate::rule::Subject;
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
    /// The file declares a schema this crate does not read.
    #[error("catalogue schema {found} is not {expected}")]
    UnknownSchema {
        /// What the file declared.
        found: u32,
        /// What this crate reads.
        expected: u32,
    },
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
    /// A row names a rule that does not exist.
    #[error("row {row} names an unknown check {check:?}")]
    UnknownCheck {
        /// Which row, counting from zero.
        row: usize,
        /// The rule as written.
        check: String,
    },
    /// `report_checks` names a rule that does not exist.
    #[error("report_checks names an unknown check {check:?}")]
    UnknownReportCheck {
        /// The rule as written.
        check: String,
    },
    /// A row names a rule that reads a whole scan rather than one file.
    ///
    /// A row offers a rule the file it matched, so a rule reading the scan is
    /// offered nothing there and runs nothing. It belongs in `report_checks`.
    #[error("row {row} names {check:?}, which reads a whole scan: put it in report_checks")]
    ReportCheckInRow {
        /// Which row, counting from zero.
        row: usize,
        /// The rule as written.
        check: String,
    },
    /// `report_checks` names a rule that reads a file rather than a scan.
    ///
    /// The other way round, and just as silent: the report offers nothing a
    /// file rule reads, so it runs nothing. It belongs on the rows whose
    /// files it should read.
    #[error("report_checks names {check:?}, which reads a file: put it on a row")]
    RowCheckInReport {
        /// The rule as written.
        check: String,
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
    /// A row names a seed that is not a plain path inside the scan root. The
    /// seed is joined to that root and read, so a traversal segment or an
    /// absolute path would reach outside it.
    #[error("row {row} seeds a directory outside the scan: {seed:?}")]
    UnrootedSeed {
        /// Which row, counting from zero.
        row: usize,
        /// The seed as written.
        seed: String,
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
    /// What to read out of it.
    pub extract: &'a [Extraction],
    /// Which rules read it.
    pub check: &'a [RuleId],
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
    /// What to read out of it.
    #[serde(default)]
    pub extract: Vec<String>,
    /// Which rules read it. Empty means none does.
    #[serde(default)]
    pub check: Vec<String>,
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
    /// A directory the scan must be told to enter for this row to be
    /// reachable, because the walk prunes its way there. Omitted means the
    /// walk reaches it on its own, which is true of every other row.
    #[serde(default)]
    pub seed: Option<String>,
}

fn default_scope() -> String {
    "repository".to_owned()
}

fn default_format() -> String {
    "json".to_owned()
}

/// The schema this crate reads. Raised when the shape of the file changes, as
/// it did when `revision` was added, again when `seed` was, and again when
/// `report_checks` was, so a file written for an older shape is refused rather
/// than half read.
///
/// `seed` raised it although a reader that did not know the field would still
/// parse the file: it would parse it and enter none of the directories the
/// field names, which is the half reading this number exists to refuse. A
/// field that changes what a scan reaches is a shape change whether or not
/// serde minds. `report_checks` raised it for the same reason, one rule
/// further on: a reader that did not know it would run none of the rules it
/// names and report a clean scan.
const SCHEMA: u32 = 4;

/// Just the schema, read before the rest: a file written for an older shape is
/// missing fields the current one requires, and "missing field `revision`" says
/// far less than the schema it was written for.
#[derive(Debug, Deserialize)]
struct Schema {
    version: u32,
}

#[derive(Debug, Deserialize)]
struct CatalogueFile {
    #[allow(dead_code)]
    version: u32,
    /// Raised when a row changes what a scan finds. `version` above says how
    /// the file is shaped; this says what it holds.
    revision: u32,
    /// The rules that read a whole scan rather than one file.
    ///
    /// A row names the rules that read the file it matches, which is what
    /// makes this file the place behaviour is decided. A rule reading the
    /// whole scan belongs to no row, so it is named here instead, and the
    /// answer to what decides whether a rule runs stays the same one.
    #[serde(default)]
    report_checks: Vec<String>,
    surface: Vec<SurfaceRule>,
}

/// Every recognised surface, and a compiled matcher over their globs.
#[derive(Debug)]
pub struct Catalogue {
    revision: u32,
    report_checks: Vec<RuleId>,
    rules: Vec<SurfaceRule>,
    kinds: Vec<SurfaceKind>,
    extractions: Vec<Vec<Extraction>>,
    checks: Vec<Vec<RuleId>>,
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
        let declared: Schema =
            toml::from_str(source).map_err(|e| CatalogueError::Invalid(e.to_string()))?;
        if declared.version != SCHEMA {
            return Err(CatalogueError::UnknownSchema {
                found: declared.version,
                expected: SCHEMA,
            });
        }

        let file: CatalogueFile =
            toml::from_str(source).map_err(|e| CatalogueError::Invalid(e.to_string()))?;

        let mut builder = GlobSetBuilder::new();
        let mut kinds = Vec::with_capacity(file.surface.len());
        let mut extractions = Vec::with_capacity(file.surface.len());
        let mut checks = Vec::with_capacity(file.surface.len());
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

            checks.push(
                rule.check
                    .iter()
                    .map(|name| {
                        let id = RuleId::from_catalogue(name).ok_or_else(|| {
                            CatalogueError::UnknownCheck {
                                row,
                                check: name.clone(),
                            }
                        })?;
                        if reads_a_report(id) {
                            return Err(CatalogueError::ReportCheckInRow {
                                row,
                                check: name.clone(),
                            });
                        }
                        Ok(id)
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
            if scope != Scope::Repository && !anchored(&rule.glob) {
                return Err(CatalogueError::UnanchoredRow {
                    row,
                    glob: rule.glob.clone(),
                });
            }
            if let Some(seed) = rule.seed.as_deref().filter(|seed| !rooted(seed)) {
                return Err(CatalogueError::UnrootedSeed {
                    row,
                    seed: seed.to_owned(),
                });
            }
            scopes.push(scope);
        }

        Ok(Self {
            revision: file.revision,
            report_checks: report_checks(&file.report_checks)?,
            globs: builder
                .build()
                .map_err(|e| CatalogueError::Invalid(e.to_string()))?,
            rules: file.surface,
            kinds,
            extractions,
            checks,
            scopes,
            formats,
        })
    }

    /// What this catalogue holds, raised when a row changes what a scan finds.
    #[must_use]
    pub fn revision(&self) -> u32 {
        self.revision
    }

    /// The rules that read a whole scan.
    #[must_use]
    pub fn report_checks(&self) -> &[RuleId] {
        &self.report_checks
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
            check: &self.checks[first],
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

    /// The row an entry of a seeded directory matches, among the rows that
    /// asked for that directory to be entered.
    ///
    /// A seed steps around the prune list for the row that names it, and for
    /// no other. Matching the whole catalogue inside a seeded directory would
    /// hand every row a subtree the walk was told to skip: a `CLAUDE.md` left
    /// in `.git/hooks` is not an instruction file an agent reads, and
    /// reporting it would claim more of that directory than any row asked for.
    #[must_use]
    pub fn lookup_seeded(&self, path: &RepoPath, scope: Scope, seed: &str) -> Option<Matched<'_>> {
        let first =
            self.globs.matches(path.as_str()).into_iter().find(|i| {
                self.scopes[*i] == scope && self.rules[*i].seed.as_deref() == Some(seed)
            })?;
        Some(Matched {
            rule: &self.rules[first],
            kind: self.kinds[first],
            extract: &self.extractions[first],
            check: &self.checks[first],
            format: self.formats[first],
            scope: self.scopes[first],
        })
    }

    /// The directories a repository scan must be told to enter.
    ///
    /// A row inside a pruned directory is unreachable by walking, and relaxing
    /// the prune would turn the one type whose job is "what not to enter" into
    /// a set of exceptions. Naming the directory on the row instead keeps the
    /// exception where a reviewer reads it.
    #[must_use]
    pub fn seeds_in(&self, scope: Scope) -> Vec<&str> {
        let mut held: Vec<&str> = Vec::new();
        for (rule, wanted) in self.rules.iter().zip(&self.scopes) {
            if *wanted != scope {
                continue;
            }
            if let Some(seed) = rule.seed.as_deref().filter(|s| !held.contains(s)) {
                held.push(seed);
            }
        }
        held
    }

    /// Every row, in declaration order.
    #[must_use]
    pub fn rules(&self) -> &[SurfaceRule] {
        &self.rules
    }

    /// The rules the first row of `kind` names, for a file no glob matched.
    #[must_use]
    pub fn checks_for(&self, kind: SurfaceKind) -> &[RuleId] {
        self.kinds
            .iter()
            .position(|k| *k == kind)
            .map_or(&[][..], |row| self.checks[row].as_slice())
    }
}

/// The rules `report_checks` names, or the first name that cannot go there.
///
/// A rule that reads no whole scan would run nothing from here, so it is
/// refused rather than listed and ignored.
fn report_checks(names: &[String]) -> Result<Vec<RuleId>, CatalogueError> {
    names
        .iter()
        .map(|name| {
            let id =
                RuleId::from_catalogue(name).ok_or_else(|| CatalogueError::UnknownReportCheck {
                    check: name.clone(),
                })?;
            if !reads_a_report(id) {
                return Err(CatalogueError::RowCheckInReport {
                    check: name.clone(),
                });
            }
            Ok(id)
        })
        .collect()
}

/// Whether a rule reads a whole scan.
fn reads_a_report(id: RuleId) -> bool {
    crate::rule::of(id).reads().contains(&Subject::Report)
}

/// Whether a glob names the directory a scan outside a repository starts at.
///
/// A home scan enters only the directories its rows name, so the first segment
/// has to be one. A traversal segment anywhere resolves outside the root the
/// scan was given, so none is allowed at any position.
fn anchored(glob: &str) -> bool {
    let named = glob
        .split('/')
        .next()
        .is_some_and(|first| !first.is_empty() && !first.contains(['*', '?', '[', '{']));
    named && !glob.split('/').any(|s| s == "." || s == "..")
}

/// Whether a seed is a plain path inside the scan root.
///
/// A seed is joined to that root and read, rather than matched against a path
/// the walk already found, so it is the one field that can reach outside it. An
/// empty segment is what a leading slash leaves, so an absolute path needs no
/// check of its own; a drive letter and a UNC prefix do, since neither leaves
/// one.
fn rooted(seed: &str) -> bool {
    !seed.contains(':')
        && !seed.is_empty()
        // Split on both separators: a seed is joined to a path, and on the
        // platform where `\` separates, `a\..\out` traverses as surely as
        // `a/../out` does.
        && seed
            .split(['/', '\\'])
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

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

    /// The kind every repository row reports itself as.
    fn repository_kinds() -> &'static [(&'static str, SurfaceKind)] {
        &[
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
            (".codex/hooks.json", SurfaceKind::Codex),
            (".codex/hooks/session_start.py", SurfaceKind::HookScript),
            (".gemini/settings.json", SurfaceKind::Gemini),
            (".cursor/mcp.json", SurfaceKind::Cursor),
            (".cursor/rules/react.mdc", SurfaceKind::Cursor),
            (".cursorrules", SurfaceKind::Cursor),
            (".vscode/settings.json", SurfaceKind::VsCode),
            (".vscode/mcp.json", SurfaceKind::VsCode),
            (".vscode/tasks.json", SurfaceKind::VsCode),
            (".github/copilot-instructions.md", SurfaceKind::Copilot),
            (".zed/settings.json", SurfaceKind::Zed),
            (".agents/skills/a/SKILL.md", SurfaceKind::Zed),
            (".rules", SurfaceKind::Zed),
            (".devin/rules/a.md", SurfaceKind::Windsurf),
            (".windsurf/rules/a.md", SurfaceKind::Windsurf),
            (".windsurfrules", SurfaceKind::Windsurf),
            (".crushrc", SurfaceKind::Crush),
            (".github/workflows/ci.yml", SurfaceKind::Workflow),
            (".git/hooks/pre-commit", SurfaceKind::HookScript),
            ("crush.json", SurfaceKind::Crush),
            ("CRUSH.md", SurfaceKind::InstructionFile),
            (".continue/config.json", SurfaceKind::Continue),
            ("cline_mcp_settings.json", SurfaceKind::Cline),
            (".clinerules/coding.md", SurfaceKind::Cline),
            ("GEMINI.md", SurfaceKind::InstructionFile),
            ("AGENT.md", SurfaceKind::InstructionFile),
            (".env", SurfaceKind::EnvFile),
            (".env.local", SurfaceKind::EnvFile),
            (".aider.conf.yml", SurfaceKind::Aider),
            (".devcontainer/devcontainer.json", SurfaceKind::DevContainer),
        ]
    }

    /// Each tool keeps its own label. A refactor that collapsed several tools
    /// onto one kind reported `.aider.conf.yml` as "Claude Code", and no test
    /// noticed, so this pins every row.
    #[test]
    fn each_surface_keeps_its_own_kind_and_extractions() {
        let expected = repository_kinds();

        assert_eq!(
            expected.len(),
            shipped().rules_in(Scope::Repository).len(),
            "every repository row needs a case here"
        );

        let all = &[
            Extraction::Hooks,
            Extraction::Permissions,
            Extraction::McpServers,
            Extraction::Autonomy,
        ][..];
        let servers = &[Extraction::McpServers][..];
        let parsed = [
            (".claude/settings.json", all),
            (".claude/settings.local.json", all),
            (".claude/skills/a/SKILL.md", &[Extraction::Permissions][..]),
            (".mcp.json", servers),
            (
                ".gemini/settings.json",
                &[Extraction::McpServers, Extraction::Permissions][..],
            ),
            (".kiro/settings/mcp.json", servers),
            (
                ".zed/settings.json",
                &[Extraction::McpServers, Extraction::Autonomy][..],
            ),
            (".vscode/settings.json", &[Extraction::Autonomy][..]),
            (".kiro/hooks/lint-on-save.json", &[Extraction::Hooks][..]),
            (".cursor/mcp.json", servers),
            (".vscode/mcp.json", servers),
            (".vscode/tasks.json", &[Extraction::Tasks][..]),
            ("cline_mcp_settings.json", servers),
            (
                ".codex/config.toml",
                &[
                    Extraction::McpServers,
                    Extraction::Autonomy,
                    Extraction::Hooks,
                ][..],
            ),
            (".codex/hooks.json", &[Extraction::Hooks][..]),
            (
                "crush.json",
                &[
                    Extraction::Hooks,
                    Extraction::Permissions,
                    Extraction::McpServers,
                ][..],
            ),
            (
                ".crushrc",
                &[
                    Extraction::Hooks,
                    Extraction::Permissions,
                    Extraction::McpServers,
                ][..],
            ),
            (".github/workflows/ci.yml", &[Extraction::Workflow][..]),
        ];
        for &(path, kind) in expected {
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
        }
    }

    /// Every row that is not plain JSON, and nothing else. A row whose format
    /// is wrong parses as a format the file is not written in, which reads as
    /// a file that declares nothing.
    #[test]
    fn a_row_reads_the_format_its_file_is_written_in() {
        let formats = [
            (Scope::Repository, ".codex/config.toml", Format::Toml),
            (Scope::Home, ".codex/config.toml", Format::Toml),
            (Scope::Repository, ".zed/settings.json", Format::Jsonc),
            (Scope::Repository, ".vscode/settings.json", Format::Jsonc),
            (Scope::Repository, ".vscode/mcp.json", Format::Jsonc),
            (Scope::Repository, ".vscode/tasks.json", Format::Jsonc),
            (Scope::Repository, "crush.json", Format::Jsonc),
            (Scope::Repository, ".crushrc", Format::Crushrc),
            (Scope::Repository, ".github/workflows/ci.yml", Format::Yaml),
            (Scope::Home, ".config/crush/crushrc", Format::Crushrc),
            (Scope::Home, ".config/crush/crush.json", Format::Jsonc),
            (
                Scope::Repository,
                ".claude/skills/a/SKILL.md",
                Format::Markdown,
            ),
        ];

        for (scope, path, wanted) in formats {
            let matched = shipped()
                .lookup_in(&p(path), scope)
                .unwrap_or_else(|| panic!("{path} matched no {scope:?} row"));
            assert_eq!(matched.format, wanted, "{path} in {scope:?}");
        }

        // Counted, so a row that stops being JSON without a case here fails
        // rather than being read as JSON quietly.
        assert_eq!(
            shipped()
                .rules()
                .iter()
                .filter(|rule| rule.format != "json")
                .count(),
            formats.len(),
            "every row that is not JSON needs a case here"
        );
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
        // `.git/hooks/pre-commit` is a surface, by its own row rather than
        // this one: the Claude glob wants a `hooks` directory below `.claude`.
        assert_eq!(
            shipped()
                .lookup(&p(".git/hooks/pre-commit"))
                .map(|m| m.kind),
            Some(SurfaceKind::HookScript)
        );
    }

    /// git runs a hook by the name it looks for, so a file under any other
    /// name is not one. That is also what keeps the samples `git init` writes
    /// out of the report: every repository ever initialised holds a dozen,
    /// and a wildcard would call each one a surface.
    #[test]
    fn a_git_hook_is_matched_by_name_and_a_sample_is_not() {
        for at in [
            ".git/hooks/pre-commit",
            ".git/hooks/commit-msg",
            ".git/hooks/post-index-change",
            ".githooks/pre-push",
            ".husky/pre-commit",
            "hooks/prepare-commit-msg",
        ] {
            assert_eq!(
                shipped()
                    .lookup_in(&p(at), Scope::Repository)
                    .map(|m| m.kind),
                Some(SurfaceKind::HookScript),
                "{at}"
            );
        }
        for at in [
            // What `git init` writes, and nothing git runs.
            ".git/hooks/pre-commit.sample",
            ".git/hooks/README",
            ".git/hooks/pre-commit.bak",
            // A name git does not look for is not a hook git runs.
            ".githooks/install.sh",
            ".husky/_/husky.sh",
            // The directory a React project keeps its own hooks in, which is
            // why `hooks` is matched by name rather than by wildcard.
            "hooks/useAuth.ts",
            "hooks/index.js",
            // And only at the root, not wherever the name appears.
            "vendor/x/.git/hooks/pre-commit",
            "packages/a/hooks/pre-commit",
        ] {
            assert!(
                shipped().lookup_in(&p(at), Scope::Repository).is_none(),
                "{at} is not a hook git runs"
            );
        }
    }

    /// A seed is joined to the scan root and read, rather than matched against
    /// a path the walk already found. So it is the one field that can reach
    /// outside the root, and it is checked whatever the scope.
    #[test]
    fn a_seed_that_reaches_outside_the_scan_is_refused() {
        for seed in [
            "../outside",
            "a/../../outside",
            "/etc",
            "/",
            "",
            ".",
            "..",
            "a//b",
            "a/./b",
            "C:/windows",
            "\\\\server\\share",
        ] {
            let error = Catalogue::load(&format!(
                r#"version = 4
                   revision = 1
                   [[surface]]
                   glob = "x"
                   tool = "x"
                   kind = "hook-script"
                   seed = '{seed}'
                   last_verified = "2026-09-11"
                   source = "https://example.invalid"
                "#
            ))
            .expect_err("a seed outside the scan must not load");
            assert!(
                matches!(error, CatalogueError::UnrootedSeed { .. }),
                "{seed:?}: {error:?}"
            );
        }
        // A backslash separates on the platform that uses one, so a
        // traversal written with backslashes traverses just as surely.
        for seed in ["a\\..\\outside", "..\\outside", "a\\.\\b", "a\\\\b"] {
            let error = Catalogue::load(&format!(
                r#"version = 4
                   revision = 1
                   [[surface]]
                   glob = "x"
                   tool = "x"
                   kind = "hook-script"
                   seed = '{seed}'
                   last_verified = "2026-09-11"
                   source = "https://example.invalid"
                "#
            ))
            .expect_err("a backslash traversal must not load");
            assert!(
                matches!(error, CatalogueError::UnrootedSeed { .. }),
                "{seed:?}: {error:?}"
            );
        }
        // A plain path inside the scan loads, whatever the scope.
        for scope in ["repository", "home", "system"] {
            let held = Catalogue::load(&format!(
                r#"version = 4
                   revision = 1
                   [[surface]]
                   scope = "{scope}"
                   glob = "a/b"
                   tool = "x"
                   kind = "hook-script"
                   seed = "a/b"
                   last_verified = "2026-09-11"
                   source = "https://example.invalid"
                "#
            ));
            assert!(held.is_ok(), "{scope}: {held:?}");
        }
    }

    /// A seeded directory is matched against the rows that named it, so a
    /// file there that some other row would claim is not claimed.
    #[test]
    fn a_seeded_lookup_sees_only_the_rows_that_asked_for_it() {
        let held = shipped();
        assert_eq!(
            held.lookup_seeded(&p(".git/hooks/pre-commit"), Scope::Repository, ".git/hooks")
                .map(|m| m.kind),
            Some(SurfaceKind::HookScript)
        );
        for at in [".git/hooks/CLAUDE.md", ".git/hooks/.env"] {
            assert!(
                held.lookup_seeded(&p(at), Scope::Repository, ".git/hooks")
                    .is_none(),
                "{at} is claimed by a row that did not ask for this directory"
            );
            // And the plain lookup does claim them, which is why the seeded
            // one has to exist at all.
            assert!(held.lookup_in(&p(at), Scope::Repository).is_some(), "{at}");
        }
        // A seed nothing declares matches nothing.
        assert!(
            held.lookup_seeded(&p(".git/hooks/pre-commit"), Scope::Repository, "elsewhere")
                .is_none()
        );
    }

    /// The directory a scan is told to enter, because the walk prunes its way
    /// there. Naming it on the row keeps the exception where it is read.
    ///
    /// Only `.git/hooks`. The other three the row matches are reachable by
    /// walking, and are not where git looks in any case: git reads
    /// `$GIT_DIR/hooks` unless `core.hooksPath` says otherwise, which clew
    /// does not read. Seeding them would spend a gap on directories git does
    /// not run hooks from.
    #[test]
    fn the_git_hooks_directory_is_seeded_and_nothing_else_is() {
        assert_eq!(shipped().seeds_in(Scope::Repository), vec![".git/hooks"]);
        assert!(shipped().seeds_in(Scope::Home).is_empty());
        assert!(shipped().seeds_in(Scope::System).is_empty());
    }

    #[test]
    fn an_invalid_glob_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 4
               revision = 1
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
            r#"version = 4
               revision = 1
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
            r#"version = 4
               revision = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               format = "ini"
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
    fn an_unknown_check_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 4
               revision = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               check = ["not-a-rule"]
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("an unknown check must not load");
        assert!(
            matches!(error, CatalogueError::UnknownCheck { .. }),
            "{error:?}"
        );
    }

    /// `report_checks` is resolved the way a row's `check` is, so a typo in
    /// it is refused rather than quietly naming no rule.
    #[test]
    fn an_unknown_report_check_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 4
               revision = 1
               report_checks = ["not-a-rule"]
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("an unknown report check must not load");
        assert!(
            matches!(error, CatalogueError::UnknownReportCheck { .. }),
            "{error:?}"
        );
    }

    /// A catalogue naming none is the ordinary case, and runs no report rule.
    #[test]
    fn a_catalogue_naming_no_report_check_loads() {
        let held = Catalogue::load(
            r#"version = 4
               revision = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect("a catalogue with no report checks");

        assert!(held.report_checks().is_empty());
    }

    /// The shipped catalogue names the one rule that reads a whole scan, and
    /// a scan that ran none of them would report a clean result rather than
    /// an error, so nothing else would say so.
    #[test]
    fn the_shipped_catalogue_names_its_report_check() {
        assert_eq!(
            shipped().report_checks(),
            &[RuleId::UnpromptedWriteAccess],
            "{:?}",
            shipped().report_checks()
        );
    }

    /// A row offers a rule one file. A rule reading the whole scan is never
    /// offered anything there, so naming it in a row runs nothing, and
    /// running nothing is what this file exists to make impossible to do by
    /// accident.
    #[test]
    fn a_row_naming_a_report_rule_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 4
               revision = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               check = ["unprompted-write-access"]
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("a row naming a report rule must not load");
        assert!(
            matches!(error, CatalogueError::ReportCheckInRow { row: 0, .. }),
            "{error:?}"
        );
    }

    /// And the other way round: a rule reading a file is handed nothing by
    /// the report, so naming it there runs nothing either.
    #[test]
    fn report_checks_naming_a_file_rule_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 4
               revision = 1
               report_checks = ["invisible-unicode"]
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("report_checks naming a file rule must not load");
        assert!(
            matches!(error, CatalogueError::RowCheckInReport { .. }),
            "{error:?}"
        );
    }

    /// Every path matches a row, and that row names exactly `rules`.
    fn checked(paths: &[(Scope, &str)], rules: &[RuleId]) {
        for (scope, path) in paths {
            let m = shipped()
                .lookup_in(&p(path), *scope)
                .unwrap_or_else(|| panic!("{path} matched no row"));
            assert_eq!(m.check, rules, "{path}");
        }
    }

    /// A group of rows and the rules that read all of them.
    type Checked = (Vec<(Scope, &'static str)>, Vec<RuleId>);

    /// Which rules read each checked row.
    ///
    /// A table rather than a run of assertions, so the count in
    /// `a_rule_reads_prose_hook_scripts_and_what_configuration_decides` has
    /// one place to compare against: a row that gains a check and no line here
    /// fails, and so does a line for a row that has none.
    fn checked_rows() -> Vec<Checked> {
        let mut rows = checked_prose_and_script_rows();
        rows.extend(checked_deciding_rows());
        rows
    }

    /// Which rules read each row that is read as prose or as shell.
    fn checked_prose_and_script_rows() -> Vec<Checked> {
        let prose = vec![RuleId::InvisibleUnicode];
        vec![
            (
                vec![
                    (Scope::Repository, "CLAUDE.md"),
                    (Scope::Repository, ".kiro/steering/product.md"),
                    (Scope::Repository, "AGENTS.md"),
                    (Scope::Repository, ".cursor/rules/react.mdc"),
                    (Scope::Repository, ".cursorrules"),
                    (Scope::Repository, ".github/copilot-instructions.md"),
                    (Scope::Repository, ".agents/skills/review/SKILL.md"),
                    (Scope::Repository, ".rules"),
                    (Scope::Repository, ".devin/rules/a.md"),
                    (Scope::Repository, ".windsurf/rules/a.md"),
                    (Scope::Repository, ".windsurfrules"),
                    (Scope::Repository, ".clinerules/coding.md"),
                    (Scope::Repository, "GEMINI.md"),
                    (Scope::Repository, "AGENT.md"),
                    (Scope::Repository, "CRUSH.md"),
                    (Scope::Home, ".kiro/steering/product.md"),
                    (Scope::Home, ".codeium/windsurf/memories/global_rules.md"),
                    (Scope::Home, ".agents/skills/review/SKILL.md"),
                    (Scope::Home, ".agents/AGENTS.md"),
                    (Scope::Home, ".config/crush/CRUSH.md"),
                    (Scope::Home, ".config/AGENTS.md"),
                    (Scope::System, "etc/devin/rules/policy.md"),
                    (Scope::System, "etc/windsurf/rules/policy.md"),
                ],
                prose,
            ),
            // A hook script is the one surface every shell rule reads,
            // wherever the tool keeps its scripts.
            (
                vec![
                    (Scope::Repository, ".claude/hooks/sync.sh"),
                    (Scope::Repository, ".codex/hooks/session_start.py"),
                    (Scope::Home, ".codex/hooks/session_start.py"),
                    // A git hook is shell that runs without being asked, and
                    // an agent that commits is what asks for it.
                    (Scope::Repository, ".git/hooks/pre-commit"),
                ],
                vec![
                    RuleId::InvisibleUnicode,
                    RuleId::OpaqueHook,
                    RuleId::DownloadAndExecute,
                    RuleId::DecodeAndExecute,
                    RuleId::CredentialExfiltration,
                    RuleId::UnverifiedDownload,
                    RuleId::UnpinnedRemotePackage,
                ],
            ),
        ]
    }

    /// Which rules read each checked row that decides something: the mode an
    /// agent starts in, what it pre-approves, how a server it declares is
    /// reached, and when a task it declares runs.
    fn checked_deciding_rows() -> Vec<Checked> {
        vec![
            // Prose that also grants tools, so both rules read it.
            (
                vec![(Scope::Repository, ".claude/skills/a/SKILL.md")],
                vec![RuleId::InvisibleUnicode, RuleId::UnrestrictedShell],
            ),
            // A settings file decides the mode, the pre-approvals and the
            // servers all three.
            (
                vec![
                    (Scope::Repository, ".claude/settings.json"),
                    (Scope::Repository, ".claude/settings.local.json"),
                    (Scope::Home, ".claude/settings.json"),
                ],
                vec![
                    RuleId::BypassPermissions,
                    RuleId::UnrestrictedShell,
                    RuleId::PlaintextTransport,
                ],
            ),
            // Gemini pre-approves tools and decides whether a server it
            // declares is confirmed, and says nothing about a mode.
            (
                vec![
                    (Scope::Repository, ".gemini/settings.json"),
                    (Scope::Home, ".gemini/settings.json"),
                ],
                vec![
                    RuleId::UnrestrictedShell,
                    RuleId::TrustedServer,
                    RuleId::PlaintextTransport,
                ],
            ),
            // The only row that sets a mode and declares no server.
            (
                vec![(Scope::Repository, ".vscode/settings.json")],
                vec![RuleId::BypassPermissions],
            ),
            (
                vec![
                    (Scope::Repository, ".codex/config.toml"),
                    (Scope::Repository, ".zed/settings.json"),
                    (Scope::Home, ".codex/config.toml"),
                ],
                vec![RuleId::BypassPermissions, RuleId::PlaintextTransport],
            ),
            // Nothing but servers, so a transport is all there is to judge.
            (
                vec![
                    (Scope::Repository, ".mcp.json"),
                    (Scope::Repository, ".kiro/settings/mcp.json"),
                    (Scope::Repository, ".cursor/mcp.json"),
                    (Scope::Repository, ".vscode/mcp.json"),
                    (Scope::Repository, "cline_mcp_settings.json"),
                    (Scope::Home, ".kiro/settings/mcp.json"),
                    (Scope::Home, ".codeium/windsurf/mcp_config.json"),
                ],
                vec![RuleId::PlaintextTransport],
            ),
            // Crush pre-approves tools and declares servers. No row reads a
            // mode from it: its `permissions` block admits a grant list alone.
            (
                vec![
                    (Scope::Repository, "crush.json"),
                    (Scope::Home, ".config/crush/crush.json"),
                ],
                vec![RuleId::UnrestrictedShell, RuleId::PlaintextTransport],
            ),
            // A `crushrc` is the only row read twice: every shell rule, for
            // the Bash it is, and the two that judge what its builtins
            // declare. Its JSON form is parsed and so reads only the latter.
            (
                vec![
                    (Scope::Repository, ".crushrc"),
                    (Scope::Home, ".config/crush/crushrc"),
                ],
                vec![
                    RuleId::UnrestrictedShell,
                    RuleId::PlaintextTransport,
                    RuleId::InvisibleUnicode,
                    RuleId::OpaqueHook,
                    RuleId::DownloadAndExecute,
                    RuleId::DecodeAndExecute,
                    RuleId::CredentialExfiltration,
                    RuleId::UnverifiedDownload,
                    RuleId::UnpinnedRemotePackage,
                ],
            ),
            // A CI workflow runs shell on every push, so every rule that
            // reads a hook's command reads its steps, plus the one that asks
            // whether an agent was told not to ask.
            (
                vec![(Scope::Repository, ".github/workflows/ci.yml")],
                vec![
                    RuleId::AgentRunsUnattended,
                    RuleId::InvisibleUnicode,
                    RuleId::DownloadAndExecute,
                    RuleId::DecodeAndExecute,
                    RuleId::CredentialExfiltration,
                    RuleId::UnverifiedDownload,
                    RuleId::UnpinnedRemotePackage,
                ],
            ),
            // The one row that declares a task, and a trigger is all it says.
            (
                vec![(Scope::Repository, ".vscode/tasks.json")],
                vec![RuleId::AutoRunTask],
            ),
        ]
    }

    /// A rule reads prose, hook scripts, and the things a configuration file
    /// decides: the mode it starts an agent in, what it pre-approves, how a
    /// server it declares is reached, and when a task it declares runs.
    #[test]
    fn a_rule_reads_prose_hook_scripts_and_what_configuration_decides() {
        let table = checked_rows();
        let counted: usize = table.iter().map(|(paths, _)| paths.len()).sum();

        assert_eq!(
            counted,
            shipped()
                .rules()
                .iter()
                .filter(|r| !r.check.is_empty())
                .count(),
            "every checked row needs a line in checked_rows"
        );
        for (paths, rules) in &table {
            checked(paths, rules);
        }
    }

    /// Inventory: read for what it declares, with nothing to judge in it. A
    /// hook file names a command, and the script it names is what gets ruled
    /// on; an environment file is reported and never opened.
    #[test]
    fn a_row_with_nothing_to_judge_names_no_rule() {
        for (scope, path) in [
            (Scope::Repository, ".kiro/hooks/lint-on-save.json"),
            (Scope::Repository, ".env"),
        ] {
            let m = shipped()
                .lookup_in(&p(path), scope)
                .unwrap_or_else(|| panic!("{path} matched no row"));
            assert!(m.check.is_empty(), "{path} has nothing to judge");
        }
    }

    /// Provenance is left out on purpose: re-dating a row after re-reading its
    /// documentation would churn the file and stop it being read.
    #[test]
    fn the_catalogue_matches_its_snapshot() {
        let snapshot = include_str!("../catalogue.snapshot");
        let pinned: Vec<&str> = snapshot
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect();

        let mut held = vec![format!("revision {}", shipped().revision())];
        held.push(format!(
            "report_checks {}",
            if shipped().report_checks().is_empty() {
                "-".to_owned()
            } else {
                shipped()
                    .report_checks()
                    .iter()
                    .map(|rule| rule.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            }
        ));
        for (row, rule) in shipped().rules().iter().enumerate() {
            let list = |names: &[String]| {
                if names.is_empty() {
                    "-".to_owned()
                } else {
                    names.join(",")
                }
            };
            held.push(format!(
                "{} {} {} {} {} {} {}",
                rule.scope,
                rule.glob,
                rule.kind,
                rule.format,
                list(&rule.extract),
                list(&rule.check),
                rule.seed.as_deref().unwrap_or("-"),
            ));
            assert!(row < pinned.len(), "{} has no pinned line", rule.glob);
        }

        assert_eq!(
            pinned,
            held.iter().map(String::as_str).collect::<Vec<_>>(),
            "the catalogue changed; update catalogue.snapshot and raise its \
             revision if what a scan finds changed"
        );
    }

    /// A file written for an older shape is refused rather than half read.
    ///
    /// The schema says 3. `revision` raised it to 2 by becoming required,
    /// which serde would refuse on its own. `seed` raised it to 3 and serde
    /// would not: an optional field reads as absent, and a reader that did
    /// not know it would parse the file and enter none of the directories it
    /// names. Half reading is what this number refuses, whether or not the
    /// parser minds.
    #[test]
    fn a_file_written_for_another_schema_is_refused() {
        let error = Catalogue::load(
            r#"version = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "skill"
               last_verified = "2026-09-11"
               source = "https://example.invalid"
            "#,
        )
        .expect_err("an older schema must not load");

        assert!(
            matches!(
                error,
                CatalogueError::UnknownSchema {
                    found: 1,
                    expected: 4
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn an_unknown_extraction_is_rejected_at_load() {
        let error = Catalogue::load(
            r#"version = 4
               revision = 1
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
            Extraction::Autonomy,
        ][..];
        let servers = &[Extraction::McpServers][..];
        let hooks = &[Extraction::Hooks][..];
        let expected: &[(&str, SurfaceKind, &[Extraction])] = &[
            (".claude/settings.json", SurfaceKind::ClaudeCode, all),
            (
                ".codex/config.toml",
                SurfaceKind::Codex,
                &[
                    Extraction::McpServers,
                    Extraction::Autonomy,
                    Extraction::Hooks,
                ][..],
            ),
            (".codex/hooks.json", SurfaceKind::Codex, hooks),
            (
                ".codex/hooks/session_start.py",
                SurfaceKind::HookScript,
                &[],
            ),
            (
                ".gemini/settings.json",
                SurfaceKind::Gemini,
                &[Extraction::McpServers, Extraction::Permissions][..],
            ),
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
            (".config/crush/CRUSH.md", SurfaceKind::InstructionFile, &[]),
            (".config/AGENTS.md", SurfaceKind::InstructionFile, &[]),
            (
                ".config/crush/crushrc",
                SurfaceKind::Crush,
                &[
                    Extraction::Hooks,
                    Extraction::Permissions,
                    Extraction::McpServers,
                ][..],
            ),
            (
                ".config/crush/crush.json",
                SurfaceKind::Crush,
                &[
                    Extraction::Hooks,
                    Extraction::Permissions,
                    Extraction::McpServers,
                ][..],
            ),
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
                r#"version = 4
               revision = 1
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

    /// Crush loads each of its files under two names, and one row carries
    /// both. A row that matched only the name a case here happens to use would
    /// leave the other invisible, which no count can see.
    #[test]
    fn crush_matches_both_names_of_each_file_it_loads() {
        let both = [
            (Scope::Repository, ".crushrc", "crushrc"),
            (Scope::Repository, ".crush.json", "crush.json"),
            (
                Scope::Home,
                ".config/crush/.crushrc",
                ".config/crush/crushrc",
            ),
            (
                Scope::Home,
                ".config/crush/.crush.json",
                ".config/crush/crush.json",
            ),
        ];
        for (scope, dotted, plain) in both {
            let hidden = shipped()
                .lookup_in(&p(dotted), scope)
                .unwrap_or_else(|| panic!("{dotted} matched no {scope:?} row"));
            let visible = shipped()
                .lookup_in(&p(plain), scope)
                .unwrap_or_else(|| panic!("{plain} matched no {scope:?} row"));
            assert_eq!(hidden.kind, visible.kind, "{dotted} and {plain}");
            assert_eq!(hidden.check, visible.check, "{dotted} and {plain}");
        }
    }

    /// Crush lists six spellings of its own context file, and a glob matches
    /// the case the file carries on disk, so a row naming one name leaves the
    /// other five invisible on any filesystem that keeps case.
    #[test]
    fn every_crush_context_file_name_is_matched() {
        for name in [
            "crush.md",
            "crush.local.md",
            "Crush.md",
            "Crush.local.md",
            "CRUSH.md",
            "CRUSH.local.md",
        ] {
            let matched = shipped()
                .lookup_in(&p(name), Scope::Repository)
                .unwrap_or_else(|| panic!("{name} matched no row"));
            assert_eq!(matched.kind, SurfaceKind::InstructionFile, "{name}");
        }
    }

    /// GitHub loads a workflow from the repository root alone. A nested
    /// `.github/workflows` is a fixture, a vendored copy or another project's
    /// tree, and a high-severity finding there would be about a file nothing
    /// executes.
    #[test]
    fn a_workflow_is_only_matched_at_the_repository_root() {
        for at in [".github/workflows/ci.yml", ".github/workflows/release.yaml"] {
            let matched = shipped()
                .lookup_in(&p(at), Scope::Repository)
                .unwrap_or_else(|| panic!("{at} matched no row"));
            assert_eq!(matched.kind, SurfaceKind::Workflow, "{at}");
        }
        for at in [
            "fixtures/project/.github/workflows/ci.yml",
            "vendor/other/.github/workflows/ci.yml",
            "sub/.github/workflows/ci.yml",
        ] {
            assert!(
                shipped().lookup_in(&p(at), Scope::Repository).is_none(),
                "{at} is not a workflow GitHub runs"
            );
        }
        // And a workflow directory holding something else is not a workflow.
        assert!(
            shipped()
                .lookup_in(&p(".github/workflows/notes.txt"), Scope::Repository)
                .is_none()
        );
    }

    #[test]
    fn a_scan_enters_only_the_directories_its_rows_name() {
        assert_eq!(
            shipped().roots_in(Scope::Home),
            vec![
                ".claude",
                ".codex",
                ".codex/hooks",
                ".gemini",
                ".kiro/settings",
                ".kiro/steering",
                ".codeium/windsurf",
                ".codeium/windsurf/memories",
                ".agents/skills",
                ".agents",
                ".config/crush",
                ".config"
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
                r#"version = 4
               revision = 1
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
    fn a_row_extracts_only_what_it_declares() {
        let hook = shipped().lookup(&p(".claude/hooks/x.sh")).expect("match");
        assert!(
            hook.extract.is_empty(),
            "a hook script declares nothing to extract"
        );

        let instruction = shipped().lookup(&p("CLAUDE.md")).expect("match");
        assert!(
            instruction.extract.is_empty(),
            "an instruction file declares prose, not access"
        );

        let settings = shipped()
            .lookup(&p(".claude/settings.json"))
            .expect("match");
        assert_eq!(settings.extract.len(), 4, "{:?}", settings.extract);
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
                r#"version = 4
               revision = 1
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

        let leap = r#"version = 4
               revision = 1
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
            r#"version = 4
               revision = 1
               [[surface]]
               glob = "x"
               tool = "x"
               kind = "settings"
            "#,
        )
        .expect_err("a row without a date or source must not load");
        assert!(matches!(error, CatalogueError::Invalid(_)), "{error:?}");
    }

    #[test]
    fn a_kind_is_read_for_what_its_row_names() {
        assert_eq!(
            shipped().checks_for(SurfaceKind::HookScript),
            [
                RuleId::InvisibleUnicode,
                RuleId::OpaqueHook,
                RuleId::DownloadAndExecute,
                RuleId::DecodeAndExecute,
                RuleId::CredentialExfiltration,
                RuleId::UnverifiedDownload,
                RuleId::UnpinnedRemotePackage
            ]
        );
        assert!(shipped().checks_for(SurfaceKind::EnvFile).is_empty());
    }
}
