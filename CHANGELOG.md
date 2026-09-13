# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Everything in this section lands in 0.1.0, the first release cut from the public
repository.

### Added

- Read hook scripts. A bidirectional character in code is Trojan Source
  (CVE-2021-42574): the script reads one way to a reviewer and runs another,
  so `invisible-unicode` now reads them. A hook that is not text, is larger
  than the file limit, or is a link that clew will not follow is an
  `opaque-hook` finding, severity medium, rather than a gap in the scan: what
  it runs cannot be reviewed. A hook that clew was not allowed to open is
  still a gap.

- Findings. A rule says something is wrong, where a row only says what a file
  declares. Findings sit on the report beside surfaces, sorted by path and
  position, and a finding does not make a scan incomplete: it is a scan that
  worked and found something.

- The `invisible-unicode` rule, severity high. It flags zero-width,
  bidirectional, tag-block and other non-printing characters in instruction,
  rules and skill files: the Rules File Backdoor, disclosed by Pillar Security
  on 18 March 2025. Non-printing means Unicode's Default_Ignorable_Code_Point,
  so blank fillers such as U+3164 are caught and visible format marks such as
  the Arabic number signs are not. A catalogue row names the rules that read
  it with `check`, so settings a tool keeps beside its rules are never quoted.
  A run of hidden characters is one finding, so a smuggled instruction does
  not fill the report. A byte order mark opening a file is left alone, as are
  variation selectors and non-breaking spaces. The evidence escapes the
  character as `<U+XXXX>` so a report never carries the payload, and quotes at
  most `CLEW_EVIDENCE_WIDTH` characters of the line, never fewer than 12.

- `clew system` also reads the rules an administrator deploys to the machine,
  `/etc/devin/rules` and the legacy `/etc/windsurf/rules`. Nobody being scanned
  chose those, and they are in neither tree that engineer owns.

- `clew system`, which scans the home directory for the agent configuration
  kept outside any repository: user-level MCP servers, global rules, and
  global skills for Claude Code, Gemini CLI, Kiro, Windsurf, Zed, and Cline.
  A repository holds what a team shares and reviews; this is the half nobody
  reviews. The scan enters only the directories those rows name rather than
  walking a home directory, and a root that is absent means the tool is not
  installed rather than a gap in the scan.

- Catalogue rows carry a `scope`, `repository` or `home`. The two trees are
  matched separately, so a path both use is never reported against the wrong
  one.

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

### Added

- Find `.env` and `.env.*`, reported and never opened: the file is credential
  values, and clew records none. `.envrc` is a direnv script and not matched.

- Find Cline rules in `.clinerules`, and the `GEMINI.md` and `AGENT.md`
  instruction files. The shared names are matched last, so a rules directory
  holding one keeps its own row.

- Find Zed project settings, skills, and `.rules`. Its MCP servers sit under
  `context_servers`, so that key is read alongside the two common spellings.
  Zed writes JSON with `//` comments, so that row is read as `jsonc`.

- A `*` in a catalogue glob now stays inside one path segment. It crossed `/`
  before, so `.env.*` also took a directory named `.env.local`, and a row had
  no way to say "one directory deep".

- Find Windsurf rules: `.devin/rules`, the legacy `.windsurf/rules`, and the
  legacy `.windsurfrules`. Its MCP configuration lives outside a repository
  and so has no row.

- Read Kiro agent hooks, which list entries naming their own trigger rather
  than keying a map by event. Both shapes are read from the same key.
  An injected prompt is reported alongside a shell command, since both fire
  unasked, and a hook switched off is reported as switched off rather than
  hidden. The report says which: `runs on`, `injects on`, and `(disabled)`.

- Find Kiro surfaces: its workspace MCP configuration, reported with the
  servers it declares, plus steering files as inventory. A steering file
  setting `inclusion: always` enters every interaction.

- Find Gemini CLI project settings and report the MCP servers they declare.
- Find `.vscode/tasks.json`. A task can set `runOn: folderOpen`, which runs it
  when the folder is opened. Reported, never opened.

### Fixed

- Report a named directory whose link points nowhere as a gap rather than as a
  tool that is not installed. Something put the link there.

- Never walk into a directory reached by a symbolic link found while walking.
  A directory clew was told to read is read even when it is a link: `/etc` is
  one on macOS, and a dotfile manager commonly makes `~/.claude` one. The check followed
  the link, so a home root such as `~/.claude -> /elsewhere` was traversed and
  reported files outside the tree being scanned. The root the operator names is
  still followed; everything discovered below it is not.

- Stop redacting the argument after a value that merely reads like a
  credential. `docker run -e JIRA_API_TOKEN ghcr.io/org/image` hid the image,
  which is what a typosquat check reads. Only a flag introduces a value.

- Five catalogue citations pointed at pages that had moved or gone. Every
  source now resolves and names the file its row claims, and `.cursorrules`
  cites the page saying it is legacy, which is why the row stays.

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

- Mask credential values in the evidence a finding quotes. A token beside a
  hidden character in an instruction file was quoted whole. A value is masked
  when set against a credential key (`API_KEY=`, `password:`, `"api_key":`, a
  `?token=` query), after a credential flag, after `Bearer` or `Basic`, or when
  one of gitleaks' rules knows its shape; a quoted value is masked whole. The
  line is masked before any rule can quote it, so a secret cut at the edge of
  the quoted window is still masked.

- Never record a credential written into an MCP argument or url. A value behind
  a flag naming a credential, one written as `key=value`, and one whose shape a
  gitleaks rule knows are replaced by `<redacted>`; a url keeps its host and path
  and drops its userinfo and query. Only the names of environment variables
  were held back before, so a token passed as `--api-key` reached the report.
  The value is dropped as the file is read, so nothing downstream holds one.

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
