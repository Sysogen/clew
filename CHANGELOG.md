# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Everything in this section lands in 0.1.0, the first release cut from the public
repository.

### Added

- Read Markdown frontmatter, so a skill reports the tools it is allowed to use.
  The opening fence must be the first line, as the tools themselves require, and
  a fence that never closes is an error rather than an empty result.

- Read TOML, so Codex `config.toml` reports the MCP servers it declares. Every
  format parses into the same value, so every extractor works on any of them.

- Release automation: a version bump on `main` tags itself, then publishes the
  workspace to crates.io and attaches binaries for five targets.

- Report the MCP servers a configuration declares, with how each is reached
  and the names of the environment variables it is given. Names only: a value
  there is routinely a credential.
- Report the operations a Claude Code settings file pre-approves, summarised
  per file, naming any grant that covers a whole tool rather than one use.
- Recognise hook scripts and skill definitions: anything in a `hooks`
  directory under `.claude`, including the `.claude/skills/<name>/hooks`
  layout, and `.claude/skills/<name>/SKILL.md`.
- Report the hooks a Claude Code settings file registers, under the file that
  registers them.
- Report directories that could not be read, and exit non-zero when a scan was
  incomplete. Previously an unreadable directory was skipped in silence, so a
  permission-denied scan printed a clean result.
- `--version` and `--help`, and a `path` subcommand naming what the tool does.

### Changed

- Catalogue rows declare what to extract. A row without `extract` is inventory:
  reported, never opened. Adding a tool is now a data change.
- Cursor and Cline MCP files are parsed for the servers they declare, which they
  were not before.
- A file is parsed once however many extractions its row declares, rather than
  once per extraction.
- Surface patterns move from Rust into `crates/domain/catalogue.toml`, one row
  each, carrying the tool, the kind, the date it was last checked and the
  documentation it was checked against.
- The library crates change shape ahead of their first publication. Only
  `clew-cli` 0.0.0 has been released and it carried no library API, so nothing
  downstream can break:
  - `clew_domain::classify` is removed. `clew_domain::catalogue().lookup` now
    returns a `Matched` carrying the row, the kind and the extractions, rather
    than a tuple.
  - `clew_domain::tools` is removed with it. `CodingTool`, `ClaudeCode` and
    `REGISTRY` have no replacement: a tool is a catalogue row now.
  - `ParseError` moves from `clew_domain::tools` to `clew_domain::extract`.

- Restructure into five crates along ports and adapters: `clew-domain`,
  `clew-application`, `clew-adapter-cli`, `clew-adapter-fs`, and `clew-cli` as
  the composition root. The compiler enforces the dependency direction, and the
  traversal is tested against an in-memory tree rather than a temporary
  directory.
- Move to edition 2024 and resolver 3, pinned to Rust 1.98.1, with the declared
  minimum verified in CI.
- Reject an unknown subcommand instead of falling through to a default.

### Security

- Never follow a symbolic link. A link is reported and not traversed, so a scan
  cannot be walked out of its own root.

## [0.0.0] - 2026-09-10

Published to crates.io before this repository was public. The tree it was built
from is not in this history and no `v0.0.0` tag exists, so 0.1.0 will be the
first tagged release.

### Added

- `clew path [DIR]` reports recognised AI coding agent configuration surfaces:
  MCP server definitions, hook configuration, and instruction files across
  Claude Code, Codex, Cursor, VS Code, Continue, Cline, Aider, Copilot, and
  devcontainers.
- `CLEW_MAX_DEPTH` sets the directory recursion limit.

[Unreleased]: https://github.com/sysogen/clew/commits/main
[0.0.0]: https://crates.io/crates/clew-cli/0.0.0
