# bypass-permissions

Severity **high**, pack core 3.

A mode that starts an agent with neither a permission prompt nor a sandbox

## What it means

A configuration file starts an agent with nothing asking before it acts and
nothing bounding what it does: Claude Code's permissions.defaultMode set to
bypassPermissions, Codex's sandbox_mode set to danger-full-access, VS Code's
chat.tools.global.autoApprove set to true, or Zed's
agent.tool_permissions.default set to allow. Any instruction the agent reads,
including one smuggled into a file it is given, then runs unattended. Two
limits belong on the finding: Claude Code stopped honouring bypassPermissions
from project and local settings in v2.1.257, so a repository setting it reaches
only an older client, and Zed's built-in security rules still prompt for a few
actions.

## What to do

Remove the mode and let the agent ask, or narrow what may happen without
asking: permissions.allow in Claude Code, chat.tools.terminal.autoApprove in VS
Code and a per-tool always_allow in Zed each pre-approve named operations
rather than every one. Where a machine genuinely runs unattended, setting the
mode in that machine's own user settings rather than in a file the repository
ships keeps it to the machine that meant it.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/rules/bypass_permissions.rs`, not this page.
