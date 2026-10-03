# unverified-download

Severity **medium**, pack core 2.

A downloaded file run with no checksum or signature checked first

## What it means

A hook downloads a file and later runs it, or unpacks it and runs what it held,
without checking a checksum or a signature first. A moved tag, a mutable URL or
a compromised host changes what runs, with the agent's permissions, the next
time the hook fires. The loader in the keyv and cacheable compromise (Socket, 4
August 2026) downloaded a Bun release over HTTPS with no checksum or signature
verification and ran it.

## What to do

Pin the download to a version and check it against a published checksum or
signature before running it (sha256sum -c, gpg --verify, cosign verify-blob),
or install the tool through a package manager with a lockfile.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.
