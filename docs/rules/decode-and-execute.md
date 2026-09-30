# decode-and-execute

Severity **high**, pack core 1.

Code decoded from base64, hex or a compressed blob and handed straight to an
interpreter

## What it means

A hook decodes code, from base64, hex or a compressed blob, and hands it
straight to an interpreter, as echo ... | base64 -d | sh does. What runs is not
what the hook shows: a review, a diff or a scanner sees only the encoded form.
The xz-utils backdoor (CVE-2024-3094, disclosed by Andres Freund on 29 March
2024) kept its script in a test file and ran it during the build with ... | xz
-d | /bin/bash.

## What to do

Keep the code a hook runs in the hook, or in a script beside it, as text. If
the hook came from someone else, decode the payload into a file without running
it, and read what it does before anything runs it.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.
