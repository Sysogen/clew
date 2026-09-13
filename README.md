# clew

Find the configuration that steers AI coding agents: in a repository, under a
home directory, and where an administrator deployed it.

A clew is the ball of thread Ariadne gave Theseus to find his way through the
labyrinth, and the root of the English word "clue".

## Install

```sh
cargo install clew-cli
```

The crate is `clew-cli`; the binary it installs is `clew`. Each
[release](https://github.com/sysogen/clew/releases) also carries binaries for
Linux, macOS and Windows, each with a SHA-256 checksum beside it.

## Use

```sh
clew path .
```

```
.claude/hooks/format.sh  hook script
.claude/settings.json    Claude Code
  runs on PostToolUse: .claude/hooks/format.sh
  pre-approves 2 operation(s), 1 unscoped
    any use of WebFetch
.cursor/rules/style.mdc  Cursor
.mcp.json                MCP servers
  server "postgres": npx -y @modelcontextprotocol/server-postgres --api-key <redacted>
    reads DATABASE_URL
CLAUDE.md                instruction file

5 agent surface(s), 1 hook(s).

1 finding(s):
  CLAUDE.md:3:21  invisible-unicode  high
    Always run the tests<U+200B> before you commit.
```

`path` reports every file an agent reads as configuration, across Claude Code,
Codex, Cursor, VS Code, Gemini CLI, Kiro, Zed, Windsurf, Cline, Continue, Aider,
Copilot and devcontainers, plus `.env` files. From those it reads:

- the hooks each registers, the event each runs on, and whether it runs a
  command or injects a prompt, a hook switched off included;
- the operations a Claude Code settings file pre-approves, naming any grant
  that covers a whole tool;
- the MCP servers each declares, how each is reached, and the names, never the
  values, of the environment variables each is given;
- findings, where a rule says something is wrong.

```sh
clew system
```

`system` reads what never reaches a code review: the agent configuration each
engineer keeps under their home directory, and the rules an administrator
deploys to the machine, such as `/etc/devin/rules`. It enters only the
directories the catalogue names rather than walking a home directory.

### Findings

| Rule | Severity | What it flags |
| --- | --- | --- |
| `invisible-unicode` | high | A character that renders as nothing, such as a zero-width, bidirectional or tag character, in a file an agent reads as instructions or in a hook script |
| `opaque-hook` | medium | A hook that cannot be reviewed as text: binary, larger than the file limit, or a symbolic link |

`invisible-unicode` is the Rules File Backdoor, disclosed by Pillar Security in
March 2025: an instruction the model reads and a reviewer cannot see. In a hook
script it is Trojan Source. A finding quotes its line with the character written
as `<U+XXXX>` and every credential on it masked, so a report can be pasted into
a ticket. A credential is recognised by the key or flag in front of it, and by
its shape with [betterleaks](https://github.com/betterleaks/betterleaks)' rules.

### Output formats

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

A finding at a place is a result at its line and column, one about a whole file
names the file, and a scan that could not read everything says so with
`executionSuccessful: false`. `system` cannot write one: SARIF places a result
by its path in a repository, and neither tree `system` reads is one.

### Exit status

`0` when every tree was read and understood, `1` when part of one was not or the
command line was wrong. An incomplete scan lists what it could not read, so it
never passes for a clean one.

A finding changes the exit status only when asked to. `--fail-on` takes `low`,
`medium` or `high` and exits `2` when a finding is at that severity or worse,
which is what a CI job wants:

```sh
clew path . --fail-on high
```

An incomplete scan still exits `1`, even beside a finding: what it could not
read may hold more.

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
no-exec: no process-spawning API in 26 source files
no-exec: clew imports none of 80 undefined symbols that can spawn
```

That is why clew is safe to point at a repository you do not control, and safe
to run unattended in CI.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLEW_MAX_DEPTH` | `12` | Directory recursion limit |
| `CLEW_MAX_FILE_BYTES` | `1048576` | Largest configuration file read, 1 MiB |
| `CLEW_EVIDENCE_WIDTH` | `80` | Characters of an offending line a finding quotes, never fewer than 12 |

## License

Apache-2.0. Copyright (c) 2026 Sysogen Lda.

Secrets are recognised with the default rule set and wordlist of
[betterleaks](https://github.com/betterleaks/betterleaks), vendored unedited in
`crates/domain/vendor/betterleaks` under its MIT licence, Copyright (c) 2026
Zachary Rice.

The tests validate SARIF against SchemaStore's copy of the SARIF 2.1.0 schema,
vendored in `crates/adapters/inbound/schemas` under Apache-2.0.
