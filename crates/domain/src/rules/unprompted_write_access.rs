// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `unprompted-write-access` rule.

use super::said_at;
use std::collections::BTreeMap;

use crate::autonomy::Autonomy;
use crate::finding::{Finding, RuleId, Severity};
use crate::repo_path::RepoPath;
use crate::rule::{Examined, FoundMode, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct UnpromptedWriteAccess;

/// The value of `approval_policy` that stops Codex asking.
///
/// `on-request` asks, and a `{ granular = ... }` table keeps some prompts, so
/// neither is this half. The reference gives `untrusted` as unsupported and
/// `on-failure` as deprecated, so neither is named.
const NEVER: (&str, &str) = ("approval_policy", "never");

/// Whether a mode lets the agent write the working tree.
///
/// Both spellings of the same decision. `danger-full-access` is deliberately
/// absent in either spelling: it is already `bypass-permissions` on its own,
/// and a second finding over the same key would say the same thing twice.
fn writes(mode: &Autonomy) -> bool {
    matches!(
        (mode.key.as_str(), mode.value.as_str()),
        ("sandbox_mode", "workspace-write") | ("default_permissions", ":workspace")
    )
}

impl Rule for UnpromptedWriteAccess {
    fn id(&self) -> RuleId {
        RuleId::UnpromptedWriteAccess
    }

    fn name(&self) -> &'static str {
        "unprompted-write-access"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "A configuration that both stops the asking and lets the agent write"
    }

    fn detail(&self) -> &'static str {
        "Codex's configuration reference gives two separate controls: \
                approval_policy, which decides when Codex pauses for approval, and the \
                sandbox, written either as sandbox_mode or as a default_permissions \
                profile. Neither is a finding on its own, and clew says so elsewhere: \
                approval_policy = \"never\" leaves the sandbox, which bounds what an \
                unasked agent reaches, and a sandbox permitting writes leaves the prompt, \
                which is someone deciding. This file sets both, so neither control is \
                left. What the agent may then write without being asked includes the \
                files deciding what the next run may do: a git hook, an instruction file, \
                this configuration. The reference recommends \"never\" for non-interactive \
                runs, which is also where nobody is watching. Running unattended is a \
                legitimate thing to do, and what this reports is that both controls were \
                turned off together, not that the run is wrong. One hole, stated: both \
                halves have to be in the same file. The reference puts project-scoped \
                overrides in .codex/config.toml files, plural, and does not say in what \
                order they merge, so a pair split across two of them is not reported. \
                Joining them in the wrong order would report a configuration that never \
                applied, which is the worse of the two errors here. A second: the \
                sandbox half is read in its two built-in spellings, and a \
                default_permissions naming a [permissions.<name>] table of its own is \
                not, although such a table grants writes with filesystem.<path> set to \
                write or by extending :workspace. Reading those tables is an extraction \
                this rule does not have."
    }

    fn remediation(&self) -> &'static str {
        "Keep one of the two. approval_policy = \"on-request\" is what the reference \
                recommends for an interactive run, and a sandbox left at read-only is what \
                makes \"never\" safe where nobody is asked. Where an unattended run really \
                does need to write, approval_policy = { granular = ... } keeps some \
                prompts rather than none, and sandbox_workspace_write.writable_roots \
                narrows where the writes land. \
                sandbox_workspace_write.network_access decides whether that sandbox can \
                reach the network, which is what turns a write into an exfiltration, so \
                leave it off."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Report]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Report { modes } = at else {
            return Vec::new();
        };
        // Gathered by file in one pass, so a repository with many nested
        // configurations costs one walk of the modes rather than one for each
        // of them. Keyed by path, so a file is answered once however many of
        // these keys it writes, and the answers come out in path order, which
        // is the order a report lists everything else in.
        let mut per_file: BTreeMap<&RepoPath, (bool, Option<&FoundMode>)> = BTreeMap::new();
        for held in *modes {
            let (unprompted, writable) = per_file.entry(&held.path).or_default();
            if (held.mode.key.as_str(), held.mode.value.as_str()) == NEVER {
                *unprompted = true;
            }
            if writable.is_none() && writes(&held.mode) {
                *writable = Some(held);
            }
        }

        per_file
            .into_values()
            .filter_map(|(unprompted, writable)| {
                let writable = writable.filter(|_| unprompted)?;
                // Placed at the sandbox, which is the half granting the
                // writes, and quoting both: the sandbox line on its own is a
                // value this rule's own prose calls harmless.
                let said = format!(
                    "{} = {:?} with {} = {:?}",
                    NEVER.0, NEVER.1, writable.mode.key, writable.mode.value
                );
                Some(said_at(
                    &writable.path,
                    self.id(),
                    writable.at,
                    &said,
                    width,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Format;
    use crate::finding::DEFAULT_EVIDENCE_WIDTH;
    use crate::rule::judge;

    fn mode(key: &str, value: &str) -> Autonomy {
        Autonomy {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    /// A file as a test writes it: where it is, what it says, and the modes
    /// a scan would have read out of it.
    struct File<'a> {
        path: &'a str,
        source: &'a str,
        modes: &'a [(&'a str, &'a str)],
    }

    /// Judged the way the scan judges it, one report over every file, with
    /// each mode placed in the file that wrote it as the scan places it.
    fn found_in(files: &[File<'_>]) -> Vec<FoundMode> {
        files
            .iter()
            .flat_map(|file| {
                let path = RepoPath::root().join(file.path);
                file.modes.iter().map(move |(k, v)| {
                    FoundMode::new(&path, &mode(k, v), file.source, Format::Toml)
                })
            })
            .collect()
    }

    /// What the rule says about one scan.
    fn said_about(files: &[File<'_>]) -> Vec<Finding> {
        let modes = found_in(files);
        judge(
            &Examined::Report { modes: &modes },
            &[RuleId::UnpromptedWriteAccess],
            DEFAULT_EVIDENCE_WIDTH,
        )
    }

    fn codex(source: &str, modes: &[(&str, &str)]) -> Vec<Finding> {
        said_about(&[File {
            path: ".codex/config.toml",
            source,
            modes,
        }])
    }

    /// Both halves, in the spelling the reference leads with.
    #[test]
    fn nothing_asking_and_a_sandbox_that_writes_is_a_finding() {
        let found = codex(
            "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n",
            &[
                ("approval_policy", "never"),
                ("sandbox_mode", "workspace-write"),
            ],
        );

        assert_eq!(found.len(), 1, "{found:?}");
        // Placed at the sandbox, which is the half granting the writes.
        assert_eq!(found[0].at.expect("a position").line, 2, "{found:?}");
        assert_eq!(found[0].severity, Severity::Medium);
    }

    /// The same decision in the profile spelling.
    #[test]
    fn a_workspace_permission_profile_is_the_same_half() {
        let found = codex(
            "approval_policy = \"never\"\ndefault_permissions = \":workspace\"\n",
            &[
                ("approval_policy", "never"),
                ("default_permissions", ":workspace"),
            ],
        );

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].at.expect("a position").line, 2, "{found:?}");
    }

    /// Each half alone leaves one control standing, which is why neither is a
    /// finding anywhere in clew. A conjunction that fired on one of them
    /// would be the two rules that already exist, reported a third time.
    #[test]
    fn either_half_alone_is_silent() {
        assert!(
            codex(
                "approval_policy = \"never\"\n",
                &[("approval_policy", "never")]
            )
            .is_empty()
        );
        assert!(
            codex(
                "sandbox_mode = \"workspace-write\"\n",
                &[("sandbox_mode", "workspace-write")]
            )
            .is_empty()
        );
        assert!(
            codex(
                "default_permissions = \":workspace\"\n",
                &[("default_permissions", ":workspace")]
            )
            .is_empty()
        );
    }

    /// The reference gives `on-request` for an interactive run, and a
    /// `granular` table keeps some prompts. Either way something asks, so the
    /// sandbox is not the only control left.
    #[test]
    fn an_approval_policy_that_still_asks_is_silent() {
        for policy in ["on-request", "granular"] {
            assert!(
                codex(
                    &format!(
                        "approval_policy = \"{policy}\"\nsandbox_mode = \"workspace-write\"\n"
                    ),
                    &[
                        ("approval_policy", policy),
                        ("sandbox_mode", "workspace-write"),
                    ],
                )
                .is_empty(),
                "{policy} asks"
            );
        }
    }

    /// `danger-full-access` is `bypass-permissions` on its own, in either
    /// spelling. Reporting it here too would say the same thing twice about
    /// one key.
    #[test]
    fn a_sandbox_that_bounds_nothing_is_left_to_the_rule_that_owns_it() {
        for sandbox in [
            ("sandbox_mode", "danger-full-access"),
            ("default_permissions", ":danger-full-access"),
        ] {
            assert!(
                codex(
                    &format!(
                        "approval_policy = \"never\"\n{} = \"{}\"\n",
                        sandbox.0, sandbox.1
                    ),
                    &[("approval_policy", "never"), sandbox],
                )
                .is_empty(),
                "{sandbox:?} is already a finding of its own"
            );
        }
    }

    /// A read-only sandbox is what makes `never` safe, which is the sentence
    /// this rule exists to hold clew to.
    #[test]
    fn a_read_only_sandbox_with_nothing_asking_is_silent() {
        assert!(
            codex(
                "approval_policy = \"never\"\nsandbox_mode = \"read-only\"\n",
                &[("approval_policy", "never"), ("sandbox_mode", "read-only")],
            )
            .is_empty()
        );
    }

    /// A profile of its own is a hole, stated rather than guessed at. Such a
    /// table grants writes with `filesystem.<path>` set to write or by
    /// extending `:workspace`, and reading it is an extraction this rule does
    /// not have, so a configuration using one is silent. Pinned, so closing
    /// the hole is a visible change rather than a number moving.
    #[test]
    fn a_permission_profile_of_its_own_is_not_read() {
        assert!(
            codex(
                "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n\n[permissions.ours]\nextends = \":workspace\"\n",
                &[("approval_policy", "never"), ("default_permissions", "ours")],
            )
            .is_empty()
        );
    }

    /// One file at a time, which is a stated limit rather than a claim about
    /// Codex. The reference puts project-scoped overrides in
    /// `.codex/config.toml` files, plural, and does not say in what order they
    /// merge, so a pair split across two of them is left unreported: joining
    /// them in an order the documentation does not give would be a finding
    /// against a configuration that never applied.
    #[test]
    fn two_halves_in_two_files_are_not_a_pair() {
        let found = said_about(&[
            File {
                path: ".codex/config.toml",
                source: "approval_policy = \"never\"\n",
                modes: &[("approval_policy", "never")],
            },
            File {
                path: "nested/.codex/config.toml",
                source: "sandbox_mode = \"workspace-write\"\n",
                modes: &[("sandbox_mode", "workspace-write")],
            },
        ]);

        assert!(found.is_empty(), "{found:?}");
    }

    /// The reference says not to combine the two sandbox spellings, and a
    /// file that does is still one configuration and one answer.
    #[test]
    fn a_file_writing_both_sandbox_spellings_is_one_finding() {
        let found = codex(
            "approval_policy = \"never\"\ndefault_permissions = \":workspace\"\nsandbox_mode = \"workspace-write\"\n",
            &[
                ("approval_policy", "never"),
                ("default_permissions", ":workspace"),
                ("sandbox_mode", "workspace-write"),
            ],
        );

        assert_eq!(found.len(), 1, "{found:?}");
        // Which of the two it names is a coin toss the reference does not
        // settle, so it is settled here: the first the scan read, which for a
        // sorted set of modes is the same one every run.
        assert!(
            found[0].evidence.as_str().contains("default_permissions"),
            "{found:?}"
        );
    }

    /// Two configurations each setting both halves are two findings: a
    /// repository with a nested Codex directory has two of them to fix.
    #[test]
    fn two_files_each_setting_both_are_two_findings() {
        let source = "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n";
        let modes: &[(&str, &str)] = &[
            ("approval_policy", "never"),
            ("sandbox_mode", "workspace-write"),
        ];
        let found = said_about(&[
            File {
                path: ".codex/config.toml",
                source,
                modes,
            },
            File {
                path: "nested/.codex/config.toml",
                source,
                modes,
            },
        ]);

        assert_eq!(found.len(), 2, "{found:?}");
    }

    /// The evidence names both halves. The line it is placed at says
    /// `sandbox_mode = "workspace-write"`, which this rule's own prose calls
    /// harmless, so quoting that line would read as a finding against a value
    /// clew says is fine.
    #[test]
    fn the_evidence_names_both_halves() {
        let found = codex(
            "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n",
            &[
                ("approval_policy", "never"),
                ("sandbox_mode", "workspace-write"),
            ],
        );

        let said = found[0].evidence.as_str();
        assert!(said.contains("approval_policy"), "{said:?}");
        assert!(said.contains("sandbox_mode"), "{said:?}");
        assert!(said.contains("never"), "{said:?}");
        assert!(said.contains("workspace-write"), "{said:?}");
    }

    /// A scan that found no mode at all, which is most of them.
    #[test]
    fn a_report_with_nothing_in_it_is_silent() {
        assert!(said_about(&[]).is_empty());
    }

    /// A rule the catalogue does not name never runs, which is the invariant
    /// `report_checks` exists to keep.
    #[test]
    fn a_rule_the_catalogue_does_not_name_does_not_run() {
        let path = RepoPath::root().join(".codex/config.toml");
        let source = "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n";
        let held: Vec<FoundMode> = [
            mode("approval_policy", "never"),
            mode("sandbox_mode", "workspace-write"),
        ]
        .iter()
        .map(|mode| FoundMode::new(&path, mode, source, Format::Toml))
        .collect();

        assert!(
            judge(
                &Examined::Report { modes: &held },
                &[],
                DEFAULT_EVIDENCE_WIDTH
            )
            .is_empty()
        );
    }
}
