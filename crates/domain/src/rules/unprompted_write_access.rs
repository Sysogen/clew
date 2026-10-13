// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `unprompted-write-access` rule.

use super::said_at;
use crate::autonomy::Autonomy;
use crate::finding::{Finding, RuleId, Severity};
use crate::hook::project_of;
use crate::profile::Profile;
use crate::repo_path::RepoPath;
use crate::rule::{Examined, FoundMode, FoundProfile, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct UnpromptedWriteAccess;

/// The value of `approval_policy` that stops Codex asking.
///
/// `on-request` asks, and a `{ granular = ... }` table keeps some prompts, so
/// neither is this half. The reference gives `untrusted` as unsupported and
/// `on-failure` as deprecated, so neither is named.
const NEVER: (&str, &str) = ("approval_policy", "never");

/// The key naming the sandbox as a mode, and the one naming it as a profile.
const SANDBOX: &str = "sandbox_mode";
const PROFILE: &str = "default_permissions";

/// The project directories a run could start under, one for each directory
/// holding a file the scan read something from, in path order.
///
/// A run deeper than the deepest such directory sees the layers that
/// directory sees, so there is nothing further to ask about, and two files in
/// one directory are one configuration rather than two.
///
/// The profiles count as well as the modes. A file defining the profile a
/// file above it selects declares no mode of its own, and leaving it out
/// would mean never asking about the one place that selection resolves to a
/// write.
fn layers(modes: &[FoundMode], profiles: &[FoundProfile]) -> Vec<RepoPath> {
    let mut held: Vec<RepoPath> = modes
        .iter()
        .map(|m| project_of(&m.path))
        .chain(profiles.iter().map(|p| project_of(&p.path)))
        .collect();
    held.sort();
    held.dedup();
    held
}

/// Whether the file at `path` is in force for a run under the project
/// directory `at`.
///
/// Codex walks from the project root to the working directory and loads every
/// `.codex/config.toml` it finds, so a file applies where its own project
/// directory holds the one being asked about. The project directory rather
/// than the file's own: `.codex` sits between them, and `a/.codex` is no
/// prefix of `a/b/.codex` although `a` is of `a/b`.
fn applies(path: &RepoPath, at: &RepoPath) -> bool {
    let above = project_of(path);
    above == *at
        || above.as_str().is_empty()
        || at.as_str().starts_with(above.as_str())
            && at.as_str().as_bytes().get(above.as_str().len()) == Some(&b'/')
}

/// Whether a mode lets the agent write the working tree.
///
/// Both spellings of the same decision, and a profile of its own is resolved
/// rather than guessed at: the table defining it grants writes with
/// `filesystem.<path> = "write"`, or extends one that does, so what it
/// permits is read out of the file rather than assumed from its name.
///
/// `danger-full-access` is deliberately absent in either spelling: it is
/// already `bypass-permissions` on its own, and a second finding over the
/// same key would say the same thing twice.
fn writes(mode: &Autonomy, defined: &[&Profile]) -> bool {
    match (mode.key.as_str(), mode.value.as_str()) {
        (SANDBOX, "workspace-write") => true,
        // Written out, `danger-full-access` is `bypass-permissions`, which
        // grades it higher than this rule does. Behind a profile name it is
        // this rule's, because that one reads the key doing the selecting and
        // a profile is where it stops being able to see: reporting it here
        // understates it by a grade, and not reporting it says nothing at all.
        (PROFILE, ":danger-full-access") => false,
        (PROFILE, selected) => Profile::selected(defined, selected),
        _ => false,
    }
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
                turned off together, not that the run is wrong. The two halves need not \
                be in one file: Codex walks from the project root to the working \
                directory and loads every .codex/config.toml it finds, with the closest \
                file winning a key, so a root that stops the asking and a nested file \
                that permits writes leave neither control for a run below. The finding \
                is placed at the sandbox, and names the file the other half came from. A \
                default_permissions naming a [permissions.<name>] table of its own is \
                resolved against that table, which grants writes with filesystem rules \
                or by extending :workspace, rather than guessed at from the name. A \
                profile extending :danger-full-access is reported here too, although \
                bypass-permissions grades that value higher: that rule reads the key \
                doing the selecting, which names the profile rather than its parent, so \
                a profile is where it stops being able to see."
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
        let Examined::Report { modes, profiles } = at else {
            return Vec::new();
        };

        // One answer per configuration a run could start under, which is one
        // per directory holding a file. A run deeper than the deepest file
        // sees the same layers as that file does, so there is nothing further
        // to ask about.
        let mut answers: Vec<Finding> = Vec::new();
        for under in layers(modes, profiles) {
            let under = &under;
            // What the layers from the root down to `under` settle on. The
            // closest file to the run wins, so the deepest layer naming a key
            // is the one in force.
            let effective = |key: &str| -> Option<&FoundMode> {
                modes
                    .iter()
                    .filter(|m| m.mode.key == key && applies(&m.path, under))
                    .max_by_key(|m| project_of(&m.path).depth())
            };
            let Some(unprompted) = effective(NEVER.0).filter(|m| m.mode.value == NEVER.1) else {
                continue;
            };
            // Both spellings of the sandbox, the deeper of the two winning
            // where a file writes both, which the reference tells it not to.
            let Some(sandbox) = [SANDBOX, PROFILE]
                .iter()
                .filter_map(|key| effective(key))
                .max_by_key(|m| project_of(&m.path).depth())
            else {
                continue;
            };
            // Closest first, because the closest file wins a key and a
            // profile table is a key: a root defining `ours` as read-only and
            // a nested file redefining it as a write are two answers, and
            // resolution takes the first it finds.
            let mut defined: Vec<&FoundProfile> = profiles
                .iter()
                .filter(|p| applies(&p.path, under))
                .collect();
            defined.sort_by_key(|p| std::cmp::Reverse(project_of(&p.path).depth()));
            let defined: Vec<&Profile> = defined.into_iter().map(|p| &p.profile).collect();
            if !writes(&sandbox.mode, &defined) {
                continue;
            }

            // Placed at the sandbox, which is the half granting the writes,
            // and quoting both: the sandbox line on its own is a value this
            // rule's own prose calls harmless. A finding carries one path, so
            // where the other half is in another file the evidence names it,
            // last: evidence is clipped to a width, and the two halves matter
            // more than which file the far one sits in.
            let from = if unprompted.path == sandbox.path {
                String::new()
            } else {
                format!(" in {}", unprompted.path.as_str())
            };
            let said = format!(
                "{} = {:?} with {} = {:?}{from}",
                sandbox.mode.key, sandbox.mode.value, NEVER.0, NEVER.1
            );
            let found = said_at(&sandbox.path, self.id(), sandbox.at, &said, width);
            // The same pair settles several runs where a deeper file says
            // nothing about either key, and that is one thing to fix.
            if !answers.contains(&found) {
                answers.push(found);
            }
        }
        answers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Format;
    use crate::finding::DEFAULT_EVIDENCE_WIDTH;
    use crate::rule::FoundProfile;
    use crate::rule::judge;

    fn mode(key: &str, value: &str) -> Autonomy {
        Autonomy {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    /// A file as a test writes it: where it is, what it says, the modes a
    /// scan would have read out of it, and any profile it defines.
    struct File<'a> {
        path: &'a str,
        source: &'a str,
        modes: &'a [(&'a str, &'a str)],
        profiles: &'a [(&'a str, Option<&'a str>, bool)],
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

    /// The profiles those files define, as the scan gathers them.
    fn defined_in(files: &[File<'_>]) -> Vec<FoundProfile> {
        files
            .iter()
            .flat_map(|file| {
                let path = RepoPath::root().join(file.path);
                file.profiles
                    .iter()
                    .map(move |(name, extends, writes)| FoundProfile {
                        path: path.clone(),
                        profile: Profile {
                            name: (*name).to_owned(),
                            extends: extends.map(str::to_owned),
                            writes: *writes,
                        },
                    })
            })
            .collect()
    }

    /// What the rule says about one scan, quoted as a report quotes it.
    fn said_about(files: &[File<'_>]) -> Vec<Finding> {
        said_at_width(files, DEFAULT_EVIDENCE_WIDTH)
    }

    /// The same, with room for every word, for a test about what the evidence
    /// says rather than about how wide a report is.
    fn said_widely(files: &[File<'_>]) -> Vec<Finding> {
        said_at_width(files, 200)
    }

    fn said_at_width(files: &[File<'_>], width: usize) -> Vec<Finding> {
        let modes = found_in(files);
        let profiles = defined_in(files);
        judge(
            &Examined::Report {
                modes: &modes,
                profiles: &profiles,
            },
            &[RuleId::UnpromptedWriteAccess],
            width,
        )
    }

    fn codex(source: &str, modes: &[(&str, &str)]) -> Vec<Finding> {
        said_about(&[File {
            path: ".codex/config.toml",
            source,
            modes,
            profiles: &[],
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

    /// Codex walks from the project root to the working directory and loads
    /// every `.codex/config.toml` it finds, so two files in that chain are
    /// one configuration. A root that stops the asking and a nested file that
    /// permits writes leave neither control for a run below.
    ///
    /// A finding carries one path, so it is placed at the sandbox and the
    /// evidence names the file the other half came from.
    #[test]
    fn two_halves_in_two_layers_are_a_pair() {
        let found = said_widely(&[
            File {
                path: ".codex/config.toml",
                source: "approval_policy = \"never\"\n",
                modes: &[("approval_policy", "never")],
                profiles: &[],
            },
            File {
                path: "nested/.codex/config.toml",
                source: "sandbox_mode = \"workspace-write\"\n",
                modes: &[("sandbox_mode", "workspace-write")],
                profiles: &[],
            },
        ]);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path.as_str(), "nested/.codex/config.toml");
        let said = found[0].evidence.as_str();
        assert!(said.contains(".codex/config.toml"), "{said:?}");
        assert!(said.contains("workspace-write"), "{said:?}");
    }

    /// The closest file to the run wins, which is the whole reason the order
    /// matters: a nested file putting the sandbox back is the fix, and
    /// reporting it anyway would report a configuration that never applied.
    #[test]
    fn a_nested_layer_putting_the_sandbox_back_is_not_a_pair_there() {
        let found = said_about(&[
            File {
                path: ".codex/config.toml",
                source: "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n",
                modes: &[
                    ("approval_policy", "never"),
                    ("sandbox_mode", "workspace-write"),
                ],
                profiles: &[],
            },
            File {
                path: "nested/.codex/config.toml",
                source: "sandbox_mode = \"read-only\"\n",
                modes: &[("sandbox_mode", "read-only")],
                profiles: &[],
            },
        ]);

        // The root still answers for a run started there, and only that.
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path.as_str(), ".codex/config.toml");
    }

    /// Only the chain from the root down. Two directories beside each other
    /// are two configurations, and neither loads the other, so joining them
    /// would report a pair nothing ever applies together.
    #[test]
    fn two_halves_in_two_directories_beside_each_other_are_not_a_pair() {
        let found = said_about(&[
            File {
                path: "a/.codex/config.toml",
                source: "approval_policy = \"never\"\n",
                modes: &[("approval_policy", "never")],
                profiles: &[],
            },
            File {
                path: "b/.codex/config.toml",
                source: "sandbox_mode = \"workspace-write\"\n",
                modes: &[("sandbox_mode", "workspace-write")],
                profiles: &[],
            },
        ]);

        assert!(found.is_empty(), "{found:?}");
    }

    /// A directory holding another tool's settings is a layer too, since a
    /// mode was read there, and the pair it inherits is the same pair. One
    /// thing to fix is one finding.
    #[test]
    fn a_pair_inherited_by_two_layers_is_reported_once() {
        let found = said_about(&[
            File {
                path: ".codex/config.toml",
                source: "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n",
                modes: &[
                    ("approval_policy", "never"),
                    ("sandbox_mode", "workspace-write"),
                ],
                profiles: &[],
            },
            File {
                path: "nested/.claude/settings.json",
                source: "{\"permissions\":{\"defaultMode\":\"plan\"}}",
                modes: &[("permissions.defaultMode", "plan")],
                profiles: &[],
            },
        ]);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path.as_str(), ".codex/config.toml");
    }

    /// A profile of its own is resolved rather than guessed at: the table
    /// defining it grants writes, so the pair is there.
    #[test]
    fn a_permission_profile_that_writes_is_the_sandbox_half() {
        let found = said_about(&[File {
            path: ".codex/config.toml",
            source: "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n\n[permissions.ours.filesystem]\n\"/srv\" = \"write\"\n",
            modes: &[
                ("approval_policy", "never"),
                ("default_permissions", "ours"),
            ],
            profiles: &[("ours", None, true)],
        }]);

        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].evidence.as_str().contains("ours"), "{found:?}");
    }

    /// And one that grants nothing is not, which is what keeps this from
    /// firing on every profile a file happens to name.
    #[test]
    fn a_permission_profile_that_writes_nothing_is_not() {
        let found = said_about(&[File {
            path: ".codex/config.toml",
            source: "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n",
            modes: &[
                ("approval_policy", "never"),
                ("default_permissions", "ours"),
            ],
            profiles: &[("ours", Some(":read-only"), false)],
        }]);

        assert!(found.is_empty(), "{found:?}");
    }

    /// A profile defined in a root layer is in force below it, because Codex
    /// loads that layer for a run there.
    #[test]
    fn a_profile_defined_in_a_root_layer_is_in_force_below_it() {
        let found = said_about(&[
            File {
                path: ".codex/config.toml",
                source: "[permissions.ours]\nextends = \":workspace\"\n",
                modes: &[],
                profiles: &[("ours", Some(":workspace"), false)],
            },
            File {
                path: "nested/.codex/config.toml",
                source: "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n",
                modes: &[
                    ("approval_policy", "never"),
                    ("default_permissions", "ours"),
                ],
                profiles: &[],
            },
        ]);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path.as_str(), "nested/.codex/config.toml");
    }

    /// A file defining the profile a file above it selects declares no mode
    /// of its own, so the directory it sits in is a run location nothing else
    /// would ask about. A run there loads both layers and resolves the
    /// selection to a write.
    #[test]
    fn a_profile_defined_below_a_selection_applies_to_a_run_there() {
        let found = said_about(&[
            File {
                path: ".codex/config.toml",
                source: "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n",
                modes: &[
                    ("approval_policy", "never"),
                    ("default_permissions", "ours"),
                ],
                profiles: &[],
            },
            File {
                path: "service/.codex/config.toml",
                source: "[permissions.ours.filesystem]\n\"/srv\" = \"write\"\n",
                modes: &[],
                profiles: &[("ours", None, true)],
            },
        ]);

        assert_eq!(found.len(), 1, "{found:?}");
        // Placed where the selection is, which is the line to change.
        assert_eq!(found[0].path.as_str(), ".codex/config.toml");
    }

    /// A profile extending the built-in that bounds nothing is a write, and
    /// the rule that owns that value cannot see it: it reads the key that
    /// selected the profile, which names `ours` rather than its parent.
    #[test]
    fn a_profile_extending_the_unbounded_built_in_is_the_sandbox_half() {
        let found = said_about(&[File {
            path: ".codex/config.toml",
            source: "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n\n[permissions.ours]\nextends = \":danger-full-access\"\n",
            modes: &[
                ("approval_policy", "never"),
                ("default_permissions", "ours"),
            ],
            profiles: &[("ours", Some(":danger-full-access"), false)],
        }]);

        assert_eq!(found.len(), 1, "{found:?}");
    }

    /// The closest file wins a key, and a profile table is a key. A root
    /// defining `ours` as read-only and a nested file redefining it as a
    /// write are two answers, and the nested one is in force below.
    #[test]
    fn the_closest_definition_of_a_profile_wins() {
        let found = said_about(&[
            File {
                path: ".codex/config.toml",
                source: "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n\n[permissions.ours]\nextends = \":read-only\"\n",
                modes: &[
                    ("approval_policy", "never"),
                    ("default_permissions", "ours"),
                ],
                profiles: &[("ours", Some(":read-only"), false)],
            },
            File {
                path: "service/.codex/config.toml",
                source: "[permissions.ours]\nextends = \":workspace\"\n",
                modes: &[],
                profiles: &[("ours", Some(":workspace"), false)],
            },
        ]);

        assert_eq!(found.len(), 1, "{found:?}");
        // The selection is at the root, which is the line to change.
        assert_eq!(found[0].path.as_str(), ".codex/config.toml");
    }

    /// Only the chain from the root down. A profile defined beside the file
    /// selecting it is in no layer that selection reaches, so no run resolves
    /// the one to the other and there is nothing to report.
    #[test]
    fn a_profile_defined_beside_a_selection_is_not_in_force() {
        let found = said_about(&[
            File {
                path: "a/.codex/config.toml",
                source: "approval_policy = \"never\"\ndefault_permissions = \"ours\"\n",
                modes: &[
                    ("approval_policy", "never"),
                    ("default_permissions", "ours"),
                ],
                profiles: &[],
            },
            File {
                path: "b/.codex/config.toml",
                source: "[permissions.ours.filesystem]\n\"/srv\" = \"write\"\n",
                modes: &[],
                profiles: &[("ours", None, true)],
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
                profiles: &[],
            },
            File {
                path: "nested/.codex/config.toml",
                source,
                modes,
                profiles: &[],
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
                &Examined::Report {
                    modes: &held,
                    profiles: &[],
                },
                &[],
                DEFAULT_EVIDENCE_WIDTH
            )
            .is_empty()
        );
    }
}
