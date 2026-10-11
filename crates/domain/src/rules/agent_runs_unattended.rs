// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `agent-runs-unattended` rule.

use super::{about_file, found_at, where_written};
use crate::finding::{Finding, RuleId, Severity};
use crate::rule::{Examined, Rule, Subject};
use crate::shell;

/// A flag that removes the prompt: on its own, or only with one value.
struct Removes {
    /// The flag, spelt as the tool's own reference spells it.
    flag: &'static str,
    /// The value that removes the prompt, where the flag takes one. `None`
    /// when the flag alone does it.
    value: Option<&'static str>,
}

/// An agent CLI and the flags its own documentation says remove the prompt.
///
/// Each was read from that tool's reference or its argument definitions, and
/// each removes every control rather than narrowing one. The near misses are
/// deliberately absent:
///
/// - Claude Code's `--allow-dangerously-skip-permissions` adds the bypass mode
///   to the mode cycle without starting in it, so an unattended run never
///   reaches it.
/// - Its `--permission-mode` values `acceptEdits`, `plan`, `auto` and `manual`
///   all still ask about something. `dontAsk` is not here because the
///   reference names it without saying what it does.
/// - Codex's `--ask-for-approval never` on its own leaves the sandbox, which
///   defaults to read-only. Only the flag that waives the sandbox too is
///   listed, which is the same line `bypass-permissions` draws.
/// - Gemini CLI's `--approval-mode auto_edit` auto-approves edit tools alone.
const AGENTS: &[(&str, &[Removes])] = &[
    (
        "claude",
        &[
            Removes {
                flag: "--dangerously-skip-permissions",
                value: None,
            },
            Removes {
                flag: "--permission-mode",
                value: Some("bypassPermissions"),
            },
        ],
    ),
    (
        "codex",
        &[Removes {
            flag: "--dangerously-bypass-approvals-and-sandbox",
            value: None,
        }],
    ),
    (
        "gemini",
        &[
            Removes {
                flag: "--yolo",
                value: None,
            },
            Removes {
                flag: "-y",
                value: None,
            },
            Removes {
                flag: "--approval-mode",
                value: Some("yolo"),
            },
        ],
    ),
];

/// Commands that run a package rather than being one, so the agent is named
/// after them rather than first.
const RUNNERS: &[&str] = &["npx", "bunx", "uvx", "pnpm", "yarn", "npm", "bun", "deno"];

/// The package names each agent is published under, which is how a runner
/// names it.
const PACKAGES: &[(&str, &str)] = &[
    ("@anthropic-ai/claude-code", "claude"),
    ("@openai/codex", "codex"),
    ("@google/gemini-cli", "gemini"),
];

/// See [`Rule::detail`] for what this flags and why.
pub struct AgentRunsUnattended;

impl Rule for AgentRunsUnattended {
    fn id(&self) -> RuleId {
        RuleId::AgentRunsUnattended
    }

    fn name(&self) -> &'static str {
        "agent-runs-unattended"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "An agent invoked with the flag that removes its permission prompt"
    }

    fn detail(&self) -> &'static str {
        "A command runs an agent CLI with the flag that waives every permission \
                prompt: Claude Code's --dangerously-skip-permissions or --permission-mode \
                bypassPermissions, Codex's --dangerously-bypass-approvals-and-sandbox, \
                or Gemini CLI's --yolo, -y or --approval-mode yolo. Nothing asks and \
                nothing bounds what the agent then does. In a CI workflow this runs on \
                every push, with the repository's secrets in the environment and nobody \
                at the keyboard, so a prompt injection reaching the model reaches the \
                job's credentials. A flag that narrows a prompt rather than removing it \
                is not flagged, nor is a value the flag's own reference does not define. \
                Running an agent unattended is a deliberate pattern and some jobs do it \
                in a sandbox: what this reports is that the prompt was removed, not that \
                the job is wrong."
    }

    fn remediation(&self) -> &'static str {
        "Narrow the grant instead of removing the prompt: a settings file listing \
                the commands the job actually needs bounds the agent where the flag does \
                not. Where an unattended run is genuinely wanted, give the job its own \
                least-privilege token rather than the workflow's default one, and keep \
                the agent out of jobs that can be triggered by a fork."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::HookCommand]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::HookCommand {
            path,
            command,
            source,
            occurrence,
        } = at
        else {
            return Vec::new();
        };
        shell::commands(command)
            .iter()
            .filter_map(|words| waived(words))
            .map(|flag| {
                // A `run:` block spans lines, and the one holding the flag is
                // the line to read. Falling back to the whole command keeps a
                // command the file writes some other way placed at all.
                where_flagged(source, command, flag, *occurrence)
                    .or_else(|| where_written(source, command, *occurrence))
                    .and_then(|at| found_at(path, self.id(), source, at, width))
                    .unwrap_or_else(|| about_file(path, self.id(), flag, width))
            })
            .collect()
    }
}

/// Where `source` writes the line of `command` that passes `flag`.
///
/// `None` when the command holds no such line, or when the line is not in the
/// text as written, which a quoted or folded block makes possible.
fn where_flagged(source: &str, command: &str, flag: &str, occurrence: usize) -> Option<usize> {
    let line = command
        .lines()
        .find(|line| line.split_whitespace().any(|word| word.starts_with(flag)))?
        .trim();
    (!line.is_empty())
        .then(|| source.match_indices(line).nth(occurrence))
        .flatten()
        .map(|(at, _)| at)
}

/// The flag that waived the prompt in one command, if one did.
fn waived(words: &[Option<String>]) -> Option<&'static str> {
    let named = agent(words)?;
    let (_, flags) = AGENTS.iter().find(|(name, _)| *name == named.0)?;
    // Only what follows the agent's own name: a runner's `-y` is its own.
    let given: Vec<&str> = words[named.1..]
        .iter()
        .filter_map(|word| word.as_deref())
        .collect();
    flags
        .iter()
        .find(|removes| passed(&given, removes))
        .map(|removes| removes.flag)
}

/// Whether `given` passes this flag in a form that removes the prompt.
fn passed(given: &[&str], removes: &Removes) -> bool {
    let Some(wanted) = removes.value else {
        return given.contains(&removes.flag);
    };
    given
        .windows(2)
        .any(|pair| pair[0] == removes.flag && pair[1] == wanted)
        || given.iter().any(|word| {
            word.strip_prefix(removes.flag)
                .and_then(|rest| rest.strip_prefix('='))
                == Some(wanted)
        })
}

/// The agent a command runs, and which word named it.
///
/// A command is the agent, or a runner given the agent to run. Anything else
/// only mentions it: `echo claude --dangerously-skip-permissions` runs no
/// agent, and reading one out of it would report a prompt nobody removed.
fn agent(words: &[Option<String>]) -> Option<(&'static str, usize)> {
    let program = named_agent(words.first()?.as_deref()?);
    if let Some(name) = program {
        return Some((name, 1));
    }
    if !RUNNERS.contains(&basename(words.first()?.as_deref()?)) {
        return None;
    }
    // The first word after the runner that names an agent, so `npx -y claude`
    // and `pnpm dlx @anthropic-ai/claude-code` both resolve.
    words
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(at, word)| named_agent(word.as_deref()?).map(|name| (name, at + 1)))
}

/// The agent a word names, by its own name or by the package it ships as.
fn named_agent(word: &str) -> Option<&'static str> {
    if let Some((_, name)) = PACKAGES.iter().find(|(package, _)| {
        // A runner takes a version, as `@openai/codex@0.5.0` does.
        word == *package || word.starts_with(&format!("{package}@"))
    }) {
        return Some(name);
    }
    let name = basename(word);
    AGENTS
        .iter()
        .find(|(agent, _)| *agent == name)
        .map(|(agent, _)| *agent)
}

/// A program's name without the path it was called through.
fn basename(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::DEFAULT_EVIDENCE_WIDTH;
    use crate::repo_path::RepoPath;
    use crate::rule::judge;

    fn found_in(run: &str, source: &str) -> Vec<Finding> {
        judge(
            &Examined::HookCommand {
                path: &RepoPath::root().join(".github/workflows/ci.yml"),
                command: run,
                source,
                occurrence: 0,
            },
            &[RuleId::AgentRunsUnattended],
            DEFAULT_EVIDENCE_WIDTH,
        )
    }

    fn fires(run: &str) -> bool {
        !found_in(
            run,
            &format!("jobs:\n  a:\n    steps:\n      - run: {run}\n"),
        )
        .is_empty()
    }

    /// Each flag its own tool's reference names as waiving every prompt.
    #[test]
    fn every_documented_waiver_fires() {
        for run in [
            "claude -p review --dangerously-skip-permissions",
            "claude --permission-mode bypassPermissions -p review",
            "claude --permission-mode=bypassPermissions -p review",
            "codex --dangerously-bypass-approvals-and-sandbox exec go",
            "gemini --yolo -p fix",
            "gemini -y -p fix",
            "gemini --approval-mode yolo -p fix",
            "gemini --approval-mode=yolo -p fix",
        ] {
            assert!(fires(run), "{run}");
        }
    }

    /// The near misses, each absent for its own documented reason. A rule that
    /// fired on these would report a prompt nobody removed.
    #[test]
    fn a_flag_that_narrows_rather_than_waives_is_no_finding() {
        for run in [
            // Adds the bypass mode to the cycle without starting in it.
            "claude --allow-dangerously-skip-permissions -p review",
            "claude --permission-mode acceptEdits -p review",
            "claude --permission-mode plan -p review",
            "claude --permission-mode auto -p review",
            // Auto-approves edit tools alone.
            "gemini --approval-mode auto_edit -p fix",
            // Stops the asking but leaves the sandbox, which is read-only.
            "codex --ask-for-approval never exec go",
            // A mode the reference names without saying what it does.
            "claude --permission-mode dontAsk -p review",
            // The agent, run with nothing waived.
            "claude -p review",
        ] {
            assert!(!fires(run), "{run}");
        }
    }

    /// A flag belongs to the tool that defines it. Reading them as one set
    /// would have `-y`, which is `yes` to most of the world, waive a prompt
    /// Claude Code never offered.
    #[test]
    fn a_flag_is_only_its_own_tools() {
        for run in [
            "claude --yolo -p review",
            "claude -y -p review",
            "codex --yolo exec go",
            "codex --dangerously-skip-permissions exec go",
            "gemini --dangerously-skip-permissions -p fix",
        ] {
            assert!(!fires(run), "{run}");
        }
    }

    /// The command has to run the agent. A line that names it in an argument
    /// runs nothing, and a rule that searched the text would fire on prose
    /// about the flag, a lint forbidding it included.
    #[test]
    fn a_command_that_only_mentions_an_agent_is_no_finding() {
        for run in [
            "echo claude --dangerously-skip-permissions",
            "grep -r -- --dangerously-skip-permissions .",
            "echo 'do not run gemini --yolo'",
            "git commit -m 'drop claude --dangerously-skip-permissions'",
        ] {
            assert!(!fires(run), "{run}");
        }
    }

    /// A runner is given the agent to run, so the agent is named after it.
    /// Its own flags are not the agent's: `npx -y` answers npx.
    #[test]
    fn an_agent_run_through_a_runner_is_found() {
        for run in [
            "npx @anthropic-ai/claude-code --dangerously-skip-permissions",
            "npx -y @anthropic-ai/claude-code --dangerously-skip-permissions",
            "npx -y @openai/codex@0.5.0 --dangerously-bypass-approvals-and-sandbox",
            "bunx @google/gemini-cli --yolo",
            "./node_modules/.bin/claude --dangerously-skip-permissions",
        ] {
            assert!(fires(run), "{run}");
        }
        // The runner's own yes flag, with no agent after it.
        assert!(!fires("npx -y prettier --write ."));
        // And with one after it: `-y` is npx's answer, not the agent's, so
        // only what follows the agent's own name counts.
        assert!(!fires("npx -y @google/gemini-cli -p fix"));
        assert!(!fires("npx -y @anthropic-ai/claude-code -p review"));
    }

    /// A step runs several commands, and only the one running the agent is
    /// judged. Splitting them is what keeps a flag in one command from being
    /// read as belonging to another.
    #[test]
    fn each_command_in_a_step_is_judged_on_its_own() {
        assert!(fires(
            "npm ci && claude -p review --dangerously-skip-permissions"
        ));
        // The flag belongs to the `echo`, not to the agent beside it.
        assert!(!fires(
            "claude -p review; echo --dangerously-skip-permissions"
        ));
    }

    /// The finding lands on the line that passes the flag, not at the start of
    /// the block, so a long `run:` still points a reviewer at the command.
    #[test]
    fn a_block_is_placed_at_the_line_that_waives_the_prompt() {
        let source = "jobs:\n  a:\n    steps:\n      - run: |\n          echo start\n          claude -p x --dangerously-skip-permissions\n          echo done\n";
        let run = "echo start\nclaude -p x --dangerously-skip-permissions\necho done\n";

        let found = found_in(run, source);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].at.map(|p| p.line), Some(6), "{found:?}");
        assert_eq!(found[0].severity, Severity::High);
    }

    /// A word whose value the file does not hold is not a flag. Guessing what
    /// `$FLAGS` expands to would report a prompt that may never be waived.
    #[test]
    fn a_flag_the_file_does_not_write_is_not_read() {
        assert!(!fires("claude -p review $FLAGS"));
        assert!(!fires("claude --permission-mode $MODE -p review"));
    }
}
