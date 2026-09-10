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

## What it does not do

`clew` never reads a credential value, and never executes a hook, script, or
command it discovers. It reads files and reports paths.

This is an early release covering discovery only.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLEW_MAX_DEPTH` | `12` | Directory recursion limit |

## License

Apache-2.0. Copyright (c) 2026 Sysogen Lda.
