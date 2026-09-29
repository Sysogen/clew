# invisible-unicode

Severity **high**, pack core 1.

Non-printing Unicode in a file an agent reads as instructions

## What it means

An instruction, rules, skill or hook file holds a character that renders as
nothing: zero-width, bidirectional, tag-block or another default-ignorable
character. The model reads it and a reviewer does not, which is how the Rules
File Backdoor, disclosed by Pillar Security on 18 March 2025, hid instructions
in rules files. In a hook script it is Trojan Source, CVE-2021-42574.

## What to do

Open the file in an editor that shows invisible characters and remove the
character unless it was put there on purpose. The evidence shows it as
<U+XXXX>, never the character itself.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.
