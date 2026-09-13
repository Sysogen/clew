# clew

Discover AI coding agent configuration surfaces in a repository.

A clew is the ball of thread Ariadne gave Theseus to find his way through the
labyrinth, and the root of the English word "clue".

## Install

```sh
cargo install clew-cli
```

The crate is `clew-cli`; the binary it installs is `clew`.

## Use

```sh
clew path .
```

Reports every recognised agent surface it finds: MCP server definitions, hook
configuration, and instruction files, across Claude Code, Codex, Cursor, VS
Code, Continue, Cline, Aider, Copilot, and devcontainers.

```
.claude/settings.json             Claude Code
.mcp.json                         MCP servers
.github/copilot-instructions.md   Copilot

3 agent surface(s).
```

`--format json` writes the same report as one document for tools to read:

```sh
clew path . --format json | jq '.scans[0].findings'
```

The document carries a `version`, raised whenever a field changes meaning or
goes away, and one entry in `scans` for each tree read: one for `path`, two for
`system`. A control or default-ignorable character in any string, variation
selectors included, is written as a `\u` escape, so a finding's payload never
appears raw.

`--format sarif` writes a SARIF 2.1.0 log for code scanning:

```sh
clew path . --format sarif > clew.sarif
```

A finding is a result at its line and column, and a scan that could not read
everything says so with `executionSuccessful: false`. Only `path` writes one:
SARIF places a result by its path in a repository, and `system` reads none.

## What it does not do

`clew` never reads a credential value, and never executes a hook, script, or
command it discovers. It reads files and reports paths.

Both are checked, not claimed. CI asserts that the released Linux and macOS
binaries import no process-spawning symbol, which is what a linked artifact that
never reaches `Command` looks like, and a test puts a password in an MCP `env`
block and asserts it never reaches the output.

The source scan runs on every build; the symbol scan needs `nm`, so it covers
the ELF and Mach-O artifacts rather than the Windows one.

```
$ ./scripts/check-no-exec.sh target/release/clew
no-exec: no process-spawning API in 19 source files
no-exec: clew imports none of 75 undefined symbols that can spawn
```

That is why clew is safe to point at a repository you do not control, and safe
to run unattended in CI.

This is an early release covering discovery only.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLEW_MAX_DEPTH` | `12` | Directory recursion limit |

## License

Apache-2.0. Copyright (c) 2026 Sysogen Lda.

Secrets are recognised with the default rule set and wordlist of
[betterleaks](https://github.com/betterleaks/betterleaks), vendored unedited in
`crates/domain/vendor/betterleaks` under its MIT licence, Copyright (c) 2026
Zachary Rice.
