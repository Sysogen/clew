# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-10-04

### Added

- `plaintext-transport` flags a remote MCP server declared with an `http`
  endpoint, so the session that carries the agent's arguments, the results it
  reads back and whatever header authenticates it crosses the network in the
  clear. Fourteen catalogue rows across nine tools run it, the broadest reach
  any one rule has. Silent on `https`, on a server launched locally, and on an
  endpoint that stays on the machine, which is what keeps it quiet on Gemini
  CLI's own documented `http://localhost:8080` example. Loopback is decided by
  parsing the host rather than matching a prefix, so
  `127.0.0.1.example.invalid` is still a finding.

  The first rule whose backing is a specification rather than an incident: the
  MCP Streamable HTTP transport requires a server to validate `Origin`, asks it
  to bind loopback rather than every interface, and says it should authenticate
  every connection. The specification never requires TLS, so the rule says this
  is a weakness in how a server is deployed rather than a breach of the
  protocol.

- `auto-run-task` flags a task whose `runOptions.runOn` is `folderOpen`, which
  VS Code runs when the containing folder is opened. Opening a repository is
  what a reviewer does before reading any of it, so the command runs before
  anyone has looked at what it is, and a task naming no command of its own
  still runs the ones it depends on. CVE-2026-10591 is where this led: AWS
  fixed Kiro IDE 0.11 because its file write tool let crafted instructions
  write this trigger. The rule's own text carries the two limits rather than
  discounting them from its grade, that an automatic task never runs in an
  untrusted workspace and that `task.allowAutomaticTasks` defaults to prompting
  once.

- `**/.vscode/tasks.json` is read for the tasks it declares, each reported with
  what it runs and when, including a compound task that names only
  `dependsOn`. A task's command is masked as it is read, since a deploy task is
  a routine place for a token.

- `**/.vscode/mcp.json` is read for the servers it declares. The row had been
  inventory only, and filling it in alone would still have found none of them:
  VS Code spells the table `servers`, keeping `mcpServers` for the portable
  `.mcp.json`.

- A server declared with `httpUrl`, which Gemini CLI documents for streamable
  HTTP, is reported. Such a server names no command, so it used to be discarded
  rather than reported, and `trusted-server` never saw the ones that declared
  `trust`. A scan that lists nothing reads as a clean result.

### Changed

- The `core` pack is at version 3 and the catalogue at revision 4.

### Fixed

- A server declaring both `url` and `httpUrl` is reported at the endpoint a
  tool actually connects to. Gemini CLI takes `httpUrl` first and logs that it
  is ignoring `url`, so naming the other pointed a reader at a host nothing
  reaches.

- A url is read the way the client that fetches it will read it. The URL
  Standard strips leading controls and spaces, removes every tab and newline
  anywhere in the input, and reads a backslash as a slash for a special scheme,
  all before parsing, so a value written with a tab inside its scheme is
  fetched as plain `http`. Six of seven such forms went unreported, two of them
  because redaction could find no scheme and withheld the url entirely.

### Security

- No report carries a credential a scanned file holds. A hook's event, type and
  command, a grant's tool and scope, a mode's key and value, and a server's
  name, executable, endpoint path and environment keys were all reported as
  written, so a token inline in a hook command was printed in full by the text
  output and carried verbatim in the JSON one. Each is redacted as it enters the
  report, after the rules have read what the file wrote, so a finding still
  lands where the declaration sits and the files a hook names are still
  followed.

- A scanned file cannot write a line of a report. Every name, path and command
  the text output prints is read out of a file under review, and none was
  escaped, so a newline in a declared value split the output and the forged half
  read as a line clew had written. A server named
  `evil\n  server "trustworthy": https://safe` rendered as two entries, the
  second naming a server nothing declared. `json` and `sarif` were never
  affected, since both escape a control character on the way out.

## [0.7.0] - 2026-09-30

### Added

- Rules belong to a named pack with a version of its own, so a set can be added
  without renumbering the rules already there and one pack can change without
  invalidating a run that cited another. One pack ships, `core`. The pack's
  `rules` list is where a rule is registered, and a rule in no pack, or in two,
  fails a test rather than being quietly not run.

- Every report names the packs that judged, rather than one number: a scan's
  JSON carries `packs` where it carried `rule_pack`, the SARIF driver carries
  `rulePacks`, `clew --version` names each pack, and a rule in `clew rules` or
  `clew explain` carries the pack and version that judged it. One number would
  have had a second pack's findings citing the first pack's version.

- Each rule is one file under `crates/domain/src/rules/`, holding its id,
  severity, wording, what it reads and what it finds. The eight matches that
  used to spread one rule across the crate are gone, replaced by a single arm in
  `rule::of` that the compiler still checks.

- A rule is a value clew holds rather than a name threaded through every match
  that wanted to know about it. `clew_domain::rule::Rule` says what a rule reads
  and what it says about one thing, `shipped` is the registry, and one dispatcher
  replaces the six entry points a scan used to call. Adding a rule meant editing
  nine places across seven matches; the compiler caught an omission, and a test
  comparing the registry against the rule pack now does. The six functions that
  judge are reachable only through the registry, so a rule cannot run without
  being one.

- `clew rules` lists every rule clew applies, and `clew explain RULE` says what
  one means, what to do about a finding under it, and where it is written up.
  Both take `--format json`, and each document names the rule pack, so a study
  can record what judged. Neither takes `--fail-on` or `--format sarif`: both
  belong to a scan, and a flag that promises to change the exit status is
  refused rather than accepted and dropped. An id that names no rule is refused
  with the ids that exist rather than resolved to the one it nearly named.

- A page per rule under `docs/rules/`, and a SARIF `helpUri` pointing at it, so
  a code scanning alert leads somewhere. The pages and the README's rule table
  are generated from the rule pack by `./scripts/rule-pages.sh`, and CI fails if
  they drift: the same words reach an alert, a terminal and a page, and four
  copies of a sentence is how one rule comes to mean three things. A page no
  rule claims, left by a rule removed or renamed, is reported too.

- A version per rule pack and a catalogue revision, so a finding can be cited
  and traced to the rules that made it. Each names the set of rules and rows,
  not the logic inside a rule: rewording a rule or re-dating a row leaves both
  alone, so two runs stay comparable when nothing about the set changed. A
  snapshot test compares each against the code, and `check-revisions.sh`
  compares it against the base, which is the only way to see a snapshot updated
  alongside its content without the number moving.

- The catalogue declares schema 2, and a file declaring another is refused
  rather than half read. `revision` became required when it was added, which is
  a change of shape, and the schema version had been parsed and ignored since it
  was introduced.

- `RuleId::all`, `RuleId::detail` and `RuleId::remediation` on `clew-domain`.
  What a rule means and what to do about it were written into the SARIF
  adapter, where the only way to read them was to generate a log; they sit
  beside the model now, so a log, a command and a page can say the same words.
  `all` is what lets the rule set be listed at all, which nothing could do
  before.

## [0.6.0] - 2026-09-24

### Added

- The `bypass-permissions` rule, severity high. It flags a configuration file
  that starts an agent with nothing asking first and nothing bounding what
  happens: Claude Code's `permissions.defaultMode` set to `bypassPermissions`,
  Codex's `sandbox_mode` set to `danger-full-access`, VS Code's
  `chat.tools.global.autoApprove` set to `true`, or Zed's
  `agent.tool_permissions.default` set to `allow`. Only those four fire. Codex
  `approval_policy = "never"` does not, because Codex still sandboxes, to
  `read-only` by default; the other three sandbox nothing, so there the prompt
  was the only control. Claude Code stopped honouring `bypassPermissions` from
  project and local settings in v2.1.257, so a repository setting it reaches
  only an older client, and Zed's built-in security rules still prompt for a
  few actions.

- `.vscode/settings.json` is read, for the switch that auto-approves every tool.
  It was not in the catalogue at all, so nothing in a VS Code workspace was.

- The `unrestricted-shell` rule, severity medium. It flags a configuration file
  or a skill that pre-approves the shell with nothing restricting what it runs:
  Claude Code's `Bash` or Gemini CLI's `run_shell_command`, bare or at `*`, in
  `permissions.allow`, `tools.allowed`, or a skill's `allowed-tools`. Every
  command the agent picks then runs without being shown to anyone. Only the
  shell is flagged: a bare `WebSearch` or `mcp__server__tool` is unscoped too,
  but neither takes an argument restriction, so a bare entry is the only way to
  write that grant. Scoped entries are silent, and so are the `deny` and `ask`
  lists, which clew does not read as grants. One file granting the same
  operation twice gives a finding at each entry.

- The `trusted-server` rule, severity medium. It flags an MCP server declared
  with `trust: true`, which Gemini CLI documents as bypassing all tool call
  confirmations for that server. A server decides for itself what tools it
  offers, so a tool added after the trust was granted is trusted too, and a tool
  whose description changes is never shown again. Only a boolean is the switch,
  so the string `"true"` is not, and `trust` is Gemini's spelling: the same key
  in a file read by a tool that ignores it is reported as part of the
  declaration rather than flagged. The finding is placed at the name the server
  is declared under.

- The mode a settings file starts an agent in is reported beside the hooks,
  permissions and servers it declares, whether or not a rule objects to it. It
  is the first thing clew reads out of a settings file that is not a grant.

## [0.5.0] - 2026-09-17

### Added

- A script a hook runs is read as a hook script wherever it sits in the
  repository. Only files under a `hooks` directory were read, so
  `bash scripts/check.sh` or `"$CLAUDE_PROJECT_DIR"/tools/hook.py` ran code no
  rule saw. What runs comes from the command's shell syntax, parsed with
  tree-sitter and never executed: a path in command position, or the file
  handed to an interpreter such as `bash`, `python3`, `node` or `uv run`, never
  a file a command only reads or writes. A path that might leave the checkout,
  absolute, under `~`, through another variable or `..`, is never followed,
  and only a repository scan follows at all: anywhere else a relative path
  belongs to whichever project the agent was started in.

- The `download-and-execute` rule, severity high. It flags a hook script, or a
  hook command in a settings file, that hands what it downloads straight to a
  shell or an interpreter: `curl ... | bash`, `wget -qO- ... | sh`,
  `curl ... | sudo python3`, `bash <(curl ...)`, `eval "$(curl ...)"`, a
  `bash -c` line doing the same, and PowerShell's `irm ... | iex`. It reads
  shell syntax, never words, so a guard whose `grep` pattern names `curl | sh`
  is silent, a download that goes only to `tar` or `jq` is silent, and a hook
  file is read as commands only when its name or its `#!` line makes it a
  shell script.

- The `decode-and-execute` rule, severity high. It flags a hook that hands
  what it decodes straight to an interpreter: `base64 -d`, `base32 -d`,
  `openssl ... -d`, `xxd -r`, or a decompressor writing to standard output,
  piped into a shell, run through `eval "$(...)"`, `sh -c "$(...)"` or
  `bash <(...)`, or in a `bash -c` line, as the xz-utils backdoor's
  `... | xz -d | /bin/bash` was. PowerShell's `-EncodedCommand`, a `-Command`
  line handing `FromBase64String` to `iex`, and a `python3 -c`, `node -e` or
  `php -r` line that both decodes and runs are flagged too. Decoded text that
  nothing runs is silent, and so are `eval "$(ssh-agent -s)"` and
  `-ExecutionPolicy`.

- The `credential-exfiltration` rule, severity high. It flags a hook that sends
  a credential over the network: the environment (`env`, `printenv`), a token
  a tool prints (`gh auth token`, `gcloud auth print-access-token`), a
  credential file (`~/.aws/credentials`, `~/.npmrc`, a private SSH key, a
  `.env` sent whole), what a cloud metadata service answers, or a variable
  assigned one of these. It is followed into what `curl`, `wget` or `nc`
  sends: piped or redirected in, named as a file with `@` or `-T`, or
  substituted into the payload or the address. A token in a header or user
  that authenticates the request is silent, as is anything sent to localhost,
  a public key, and configuration read out of `.env`.

- The `unverified-download` rule, severity medium. It flags a hook that
  downloads a file and later runs it, or unpacks it and later runs something
  from where it unpacked it, with no checksum or signature checked in between:
  `curl -o f && ./f`, `curl -O a.tgz; tar xf a.tgz; ./a/bin/a`, and
  `curl ... | tar -xz -C d; d/bin/tool`. A variable may hold anything the script
  assigned it earlier, so a download named through one is still followed. A
  `sha256sum -c`, `shasum -c`, `gpg --verify`, `cosign verify-blob`,
  `minisign -V` or `gpgv` silences it, and a tool run by name is taken to be
  the one on `PATH`.

- The `unpinned-remote-package` rule, severity low. It flags a hook that runs a
  registry package at a tag that moves, `latest`, `next`, `canary`, `beta` and
  the like, through `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx` or
  `pipx run`: whatever was published last runs, each time the hook fires.
  Without a version a runner takes what the project installed, and with one it
  takes that version, so neither is flagged. The rules that read commands now
  look through `xargs`, whose `-I {}` and other valued flags are skipped.

### Fixed

- A hook written in exec form, with an `args` list, is reported with its
  arguments. Only `command` was read, so a script named in `args`, or the
  payload handed to `bash -c`, never reached the report. The arguments are
  quoted into one line that splits back into them.

## [0.4.0] - 2026-09-14

### Added

- A GitHub Action, `Sysogen/clew`, that scans the checkout and uploads the
  SARIF log to code scanning. It installs the clew release it names for the
  runner, refusing one that does not match its published checksum, prints the
  report to the job log and the run's summary page, passes `fail-on` through,
  and ends the step as clew exits, after the upload.

- A SARIF log tags each rule it lists `security` and gives it a
  `security-severity` score in GitHub's band for the rule's severity, so code
  scanning shows its findings as security alerts ranked high or medium, as
  clew ranks them.

## [0.3.0] - 2026-09-13

### Added

- `--fail-on low|medium|high` on `path` and `system`: exit `2` when a finding
  is at that severity or worse. Without it a finding still does not change the
  exit status, and an incomplete scan still exits `1`, even beside a finding,
  since what it could not read may hold more.

### Fixed

- Piping the text report into a reader that stops early, such as
  `clew path . | head`, no longer panics when the pipe closes. The scan finishes
  and exits with its usual status.

- A release waits for CI to finish on its commit rather than failing because
  it has not. `Tag` starts the release as soon as a version change lands, while
  CI on that commit is still running, which stopped the first 0.2.0 attempt.

## [0.2.0] - 2026-09-13

### Added

- `--format sarif` on `path`: a SARIF 2.1.0 log for code scanning. A finding at
  a place is a result at its line and column, and one about a whole file names
  the file. Severities high, medium and low are `error`, `warning` and `note`,
  and a scan that could not read everything reports
  `executionSuccessful: false` with a notification for each path. `system`
  refuses it: SARIF places a result by its path in a repository, and neither
  tree `system` reads is one.

- `--format json` on `path` and `system`: the whole report as one JSON document
  under `"version": 1`, with an entry in `scans` for each tree read. Any control
  or default-ignorable character, variation selectors included, is written as a
  `\u` escape, so the document decodes to exactly what was found without
  carrying the character itself.

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

- Recognise a secret by its shape with the default rules of betterleaks,
  gitleaks' successor by the same author, vendored unedited under its MIT
  licence. Each rule's Expr filter runs, token efficiency included, so a
  placeholder or a readable word is not taken for a secret. A rule's
  `validate` is never run: it would send the credential to its issuer.

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

- Catalogue rows carry a `scope`: `repository`, `home` or `system`. Each tree
  is matched separately, so a path two trees both use is never reported
  against the wrong one.

- Find `.env` and `.env.*`, reported and never opened: the file is credential
  values, and clew records none. `.envrc` is a direnv script and not matched.

- Find Cline rules in `.clinerules`, and the `GEMINI.md` and `AGENT.md`
  instruction files. The shared names are matched last, so a rules directory
  holding one keeps its own row.

- Find Zed project settings, skills, and `.rules`. Its MCP servers sit under
  `context_servers`, so that key is read alongside the two common spellings.
  Zed writes JSON with `//` comments, so that row is read as `jsonc`.

- Find Windsurf rules: `.devin/rules`, the legacy `.windsurf/rules`, and the
  legacy `.windsurfrules`. Its MCP configuration lives outside a repository,
  so it is read by `clew system`.

- Read Kiro agent hooks, which list entries naming their own trigger rather
  than keying a map by event. Both shapes are read from the same key.
  An injected prompt is reported alongside a shell command, since both fire
  unasked, and a hook switched off is reported as switched off rather than
  hidden. The report says which: `runs on`, `injects on`, and `(disabled)`.

- Find Kiro surfaces: its workspace MCP configuration, reported with the
  servers it declares, plus steering files. A steering file setting
  `inclusion: always` enters every interaction.

- Find Gemini CLI project settings and report the MCP servers they declare.

- Find `.vscode/tasks.json`. A task can set `runOn: folderOpen`, which runs it
  when the folder is opened. Reported, never opened.

- Find Cursor project rules under `.cursor/rules`, `.mdc` files only, since
  Cursor ignores a plain `.md` there.

- Read Markdown frontmatter, so a skill reports the tools it is allowed to use.
  The opening fence must be the first line, as the tools themselves require, and
  a fence that never closes is an error rather than an empty result.

- Read TOML, so Codex `config.toml` reports the MCP servers it declares. Every
  format parses into the same value, so every extractor works on any of them.

- CI proves clew cannot execute what it finds: a source scan for any
  process-spawning API on every build, and a symbol scan of the Linux and macOS
  release binaries for any process-spawning import.

### Changed

- A `*` in a catalogue glob now stays inside one path segment. It crossed `/`
  before, so `.env.*` also took a directory named `.env.local`, and a row had
  no way to say "one directory deep".

### Fixed

- Report a named directory whose link points nowhere as a gap rather than as a
  tool that is not installed. Something put the link there.

- Never walk into a directory reached by a symbolic link found while walking.
  A directory clew was told to read is read even when it is a link: `/etc` is
  one on macOS, and a dotfile manager commonly makes `~/.claude` one. The check
  followed the link, so a home root such as `~/.claude -> /elsewhere` was
  traversed and reported files outside the tree being scanned. The root the
  operator names is still followed; everything discovered below it is not.

- Stop redacting the argument after a value that merely reads like a
  credential. `docker run -e JIRA_API_TOKEN ghcr.io/org/image` hid the image,
  which is what a typosquat check reads. Only a flag introduces a value.

- Five catalogue citations pointed at pages that had moved or gone. Every
  source now resolves and names the file its row claims, and `.cursorrules`
  cites the page saying it is legacy, which is why the row stays.

### Security

- Mask credential values in the evidence a finding quotes. A token beside a
  hidden character in an instruction file was quoted whole. A value is masked
  when set against a credential key (`API_KEY=`, `password = `, `password:`,
  `"api_key":`, a `?token=` query), after a credential flag, after `Bearer` or
  `Basic`, or when one of betterleaks' rules knows its shape; a quoted value is
  masked whole. The line is masked before any rule can quote it, so a secret
  cut at the edge of the quoted window is still masked.

- Never record a credential written into an MCP argument or url. A value behind
  a flag naming a credential, one written as `key=value`, and one whose shape a
  betterleaks rule knows are replaced by `<redacted>`; a url keeps its host and
  path and drops its userinfo and query. Only the names of environment
  variables were held back before, so a token passed as `--api-key` reached the
  report. The value is dropped as the file is read, so nothing downstream holds
  one.

## [0.1.0] - 2026-09-11

The first release cut from the public repository.

### Added

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
from is not in this history and no `v0.0.0` tag exists, so 0.1.0 is the first
tagged release.

### Added

- `clew path [DIR]` reports recognised AI coding agent configuration surfaces:
  MCP server definitions, hook configuration, and instruction files across
  Claude Code, Codex, Cursor, VS Code, Continue, Cline, Aider, Copilot, and
  devcontainers.
- `CLEW_MAX_DEPTH` sets the directory recursion limit.

[Unreleased]: https://github.com/sysogen/clew/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/sysogen/clew/releases/tag/v0.8.0
[0.7.0]: https://github.com/sysogen/clew/releases/tag/v0.7.0
[0.6.0]: https://github.com/sysogen/clew/releases/tag/v0.6.0
[0.5.0]: https://github.com/sysogen/clew/releases/tag/v0.5.0
[0.4.0]: https://github.com/sysogen/clew/releases/tag/v0.4.0
[0.3.0]: https://github.com/sysogen/clew/releases/tag/v0.3.0
[0.2.0]: https://github.com/sysogen/clew/releases/tag/v0.2.0
[0.1.0]: https://github.com/sysogen/clew/releases/tag/v0.1.0
[0.0.0]: https://crates.io/crates/clew-cli/0.0.0
