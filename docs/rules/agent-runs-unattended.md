# agent-runs-unattended

Severity **high**, pack core 5.

An agent invoked with the flag that removes its permission prompt

## What it means

A command runs an agent CLI with the flag that waives every permission prompt:
Claude Code's --dangerously-skip-permissions or --permission-mode
bypassPermissions, Codex's --dangerously-bypass-approvals-and-sandbox, or
Gemini CLI's --yolo, -y or --approval-mode yolo. Nothing asks and nothing
bounds what the agent then does. In a CI workflow it runs whenever that
workflow is triggered, with nobody at the keyboard and with the job's token and
whatever secrets the job was given, so a prompt injection reaching the model
reaches those. Which events trigger it and which secrets it holds are not read
here, so neither is claimed. A flag that narrows a prompt rather than removing
it is not flagged, nor is a value the flag's own reference does not define.
Running an agent unattended is a deliberate pattern and some jobs do it in a
sandbox: what this reports is that the prompt was removed, not that the job is
wrong.

## What to do

Narrow the grant instead of removing the prompt: a settings file listing the
commands the job actually needs bounds the agent where the flag does not. Where
an unattended run is genuinely wanted, give the job its own least-privilege
token rather than the workflow's default one, and keep the agent out of jobs
that can be triggered by a fork.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/rules/agent_runs_unattended.rs`, not this page.
