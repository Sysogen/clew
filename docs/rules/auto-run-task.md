# auto-run-task

Severity **high**, pack core 3.

A task a workspace runs when the folder is opened

## What it means

A task sets runOptions.runOn to folderOpen, which VS Code documents as running
it when the containing folder is opened. Opening a repository is what a
reviewer does before reading any of it, so the command runs before anyone has
looked at what it is. A task naming no command of its own still runs the ones
it depends on. Two limits apply and neither is a reason to ignore this: an
automatic task never runs in a workspace that is not trusted, and
task.allowAutomaticTasks defaults to off, which prompts once rather than
running. What the file asks for is still arbitrary execution on open, in a
repository anyone may clone, and one Allow is all that stands in the way.
CVE-2026-10591 is where this led: AWS fixed Kiro IDE 0.11 because its file
write tool let crafted instructions write this very trigger, rated 8.8 high
under CVSS 3.1 by AWS as the assigning authority.

## What to do

Take the trigger out and leave the task to be chosen, which is what runOn
default means and what omitting runOptions already does. Where a workspace
genuinely needs setup on open, read the command first and keep it to something
whose source you control, since every later change to it runs on the same
trigger. Leaving task.allowAutomaticTasks at off keeps the prompt, and not
trusting a workspace you are only reading stops the task outright.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/rules/auto_run_task.rs`, not this page.
