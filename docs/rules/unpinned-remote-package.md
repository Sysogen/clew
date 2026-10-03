# unpinned-remote-package

Severity **low**, pack core 3.

A registry package run at a tag that moves, such as @latest

## What it means

A hook runs a package from a registry at a tag that moves, as npx
claude-flow@latest does, so it runs whichever version was published last, every
time it fires, with the agent's permissions. In the Shai-Hulud attack
(StepSecurity, 15 September 2025), compromised versions of @ctrl/tinycolor and
40 other npm packages carried a postinstall payload; a runner fetching the
latest release at that moment fetched it.

## What to do

Pin the package to an exact version (npx tool@1.4.2), or add it to the
project's dependencies so the lockfile decides the version and checks its
integrity.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.
