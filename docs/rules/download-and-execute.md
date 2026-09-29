# download-and-execute

Severity **high**, rule pack 1.

Code fetched from the network and handed straight to an interpreter

## What it means

A hook downloads code and hands it straight to an interpreter, as curl ... |
bash does. What runs is whatever the server returns at that moment, with the
agent's permissions, every time the hook fires. The compromised
tj-actions/changed-files action (CVE-2025-30066, 14 March 2025) ran curl ...
memdump.py | sudo python3.

## What to do

Download to a file, check it against a pinned checksum or signature, and run
the checked file, or install the tool through a package manager with a
lockfile. If the hook came from someone else, find out why it fetches code each
time it runs.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.
