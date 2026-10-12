# unprompted-write-access

Severity **medium**, pack core 5.

A configuration that both stops the asking and lets the agent write

## What it means

Codex's configuration reference gives two separate controls: approval_policy,
which decides when Codex pauses for approval, and the sandbox, written either
as sandbox_mode or as a default_permissions profile. Neither is a finding on
its own, and clew says so elsewhere: approval_policy = "never" leaves the
sandbox, which bounds what an unasked agent reaches, and a sandbox permitting
writes leaves the prompt, which is someone deciding. This file sets both, so
neither control is left. What the agent may then write without being asked
includes the files deciding what the next run may do: a git hook, an
instruction file, this configuration. The reference recommends "never" for
non-interactive runs, which is also where nobody is watching. Running
unattended is a legitimate thing to do, and what this reports is that both
controls were turned off together, not that the run is wrong.

## What to do

Keep one of the two. approval_policy = "on-request" is what the reference
recommends for an interactive run, and a sandbox left at read-only is what
makes "never" safe where nobody is asked. Where an unattended run really does
need to write, approval_policy = { granular = ... } keeps some prompts rather
than none, and sandbox_workspace_write.writable_roots narrows where the writes
land. sandbox_workspace_write.network_access decides whether that sandbox can
reach the network, which is what turns a write into an exfiltration, so leave
it off.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/rules/unprompted_write_access.rs`, not this page.
