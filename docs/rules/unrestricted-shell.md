# unrestricted-shell

Severity **medium**, pack core 2.

A pre-approved shell grant with nothing restricting the commands it runs

## What it means

A configuration file pre-approves the shell with nothing restricting what it
runs: Claude Code's Bash, Bash() or Bash(*), or Gemini CLI's run_shell_command,
in permissions.allow, tools.allowed, or a skill's allowed-tools. Every command
the agent chooses then runs without being shown to anyone, which is the grant
the other entries in those lists exist to avoid needing. A tool that takes no
argument restriction, such as WebSearch or an MCP tool, is not flagged: a bare
entry is the only way to write that grant.

## What to do

Replace the entry with the commands the project actually runs, scoped, as
Bash(cargo test:*) and run_shell_command(git) are. Where a broad grant is
genuinely wanted, keeping it in a personal settings.local.json rather than the
file the repository ships limits it to the person who chose it.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.
