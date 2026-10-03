# opaque-hook

Severity **medium**, pack core 3.

A hook file clew cannot review as text

## What it means

A hook runs on agent events with the agent's permissions, and this one cannot
be read as text: it is not UTF-8, is larger than the file limit, or is a
symbolic link that clew will not follow. What it runs cannot be reviewed.

## What to do

Replace the hook with a script that can be reviewed, or establish where the
file came from and what it does. If it is text that is only large, raise
CLEW_MAX_FILE_BYTES.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.
