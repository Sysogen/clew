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
- the scripts those hooks run, read as hook scripts wherever they sit in the
  repository;
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
| `download-and-execute` | high | A hook script, or a hook command in a settings file, that hands what it downloads straight to a shell or an interpreter, as `curl ... \| bash` does |
| `decode-and-execute` | high | A hook that hands what it decodes from base64, hex or a compressed blob straight to an interpreter, as `echo ... \| base64 -d \| sh` does |
| `credential-exfiltration` | high | A hook that sends a credential file, a token a tool prints or the whole environment over the network, as `env \| curl -d @- ...` does |
| `unverified-download` | medium | A hook that downloads a file and later runs it, or unpacks it and runs what it held, with no checksum or signature checked in between |
| `unpinned-remote-package` | low | A hook that runs a registry package at a tag that moves, such as `npx tool@latest`, so whatever was published last runs |
<<<<<<< HEAD
| `bypass-permissions` | high | A configuration file that starts an agent with nothing asking first and nothing bounding what happens: Claude Code's `permissions.defaultMode` set to `bypassPermissions`, Codex's `sandbox_mode` set to `danger-full-access`, VS Code's `chat.tools.global.autoApprove` set to `true`, or Zed's `agent.tool_permissions.default` set to `allow` |
| `unrestricted-shell` | medium | A configuration file or skill that pre-approves the shell with nothing restricting it: Claude Code's `Bash` or Gemini CLI's `run_shell_command`, bare or at `*`, in `permissions.allow`, `tools.allowed` or `allowed-tools` |
=======
| `bypass-permissions` | high | A settings file that starts an agent with neither a permission prompt nor a sandbox: Claude Code's `permissions.defaultMode` set to `bypassPermissions`, or Codex's `sandbox_mode` set to `danger-full-access` |
| `unrestricted-shell` | medium | A settings file or skill that pre-approves the shell with nothing restricting it: `Bash`, `Bash()` or `Bash(*)` in `permissions.allow` or `allowed-tools` |
| `trusted-server` | medium | An MCP server declared with `trust: true`, which Gemini CLI documents as bypassing every tool call confirmation for that server |
>>>>>>> 6c73c75 (feat(domain): flag an unconfirmed MCP server)

`invisible-unicode` is the Rules File Backdoor, disclosed by Pillar Security in
March 2025: an instruction the model reads and a reviewer cannot see. In a hook
script it is Trojan Source. A finding quotes its line with the character written
as `<U+XXXX>` and every credential on it masked, so a report can be pasted into
a ticket. A credential is recognised by the key or flag in front of it, and by
its shape with [betterleaks](https://github.com/betterleaks/betterleaks)' rules.

`download-and-execute` reads a hook's shell syntax, never its words: a guard
whose `grep` pattern names `curl | sh` is not one, a download that goes only to
`tar` or `jq` is not one, and a README beside the hooks is never read as
commands. The compromised tj-actions/changed-files action ran
`curl ... | sudo python3` in March 2025.

`decode-and-execute` follows `base64 -d`, `xxd -r`, `openssl -d` and a
decompressor writing to standard output into an interpreter the same ways, and
flags PowerShell's `-EncodedCommand` and a `python3 -c` or `node -e` line that
both decodes and runs. Decoded text that nothing runs, such as a base64 round
trip into a variable or `jq`, is silent. The xz-utils backdoor ran its hidden
script with `... | xz -d | /bin/bash` in March 2024.

`credential-exfiltration` follows the environment, `gh auth token` and its
kin, a credential file such as `~/.aws/credentials`, and a variable assigned
one of these, to what `curl`, `wget` or `nc` sends. A token in the header or
user that authenticates a request is how a service is used, and anything sent
to localhost stays on the machine, so both are silent, as is configuration read
from `.env`. The Shai-Hulud worm sent a workflow's secrets with
`curl -d "$CONTENTS" ...` in September 2025.

`unverified-download` follows a downloaded file, and the directory it was
unpacked into, to a later run, through the variables that name them. A
`sha256sum -c`, `gpg --verify` or `cosign verify-blob` in between silences it,
and a tool run by name is the one on `PATH`, not the download.

`unpinned-remote-package` flags `npx`, `bunx`, `pnpm dlx`, `yarn dlx`,
`npm exec`, `uvx` and `pipx run` given a package at `@latest` or another tag
that moves, and looks through `xargs` to find them. `npx prettier`, which runs
what the project installed, and `npx tool@1.4.2` are silent.

`bypass-permissions` is the one rule that reads a configuration file rather than
a hook. Only the four values above fire. Codex `approval_policy = "never"` does
not, because Codex still sandboxes, to `read-only` by default, so the agent is
bounded even when nobody is asked; the other three tools sandbox nothing, so
there the prompt was the only control. Two limits are worth knowing: Claude Code
stopped honouring `bypassPermissions` from project and local settings in
v2.1.257, so a repository setting it reaches only an older client, and Zed's
built-in security rules still prompt for a few actions.

`unrestricted-shell` flags the grant the other permission entries exist to avoid
needing: every command the agent picks runs without being shown to anyone. Only
the shell is flagged. A bare `WebSearch` or `mcp__server__tool` is unscoped too,
but neither takes an argument restriction, so a bare entry is the only way to
write that grant and flagging it would say nothing. `Bash(cargo test:*)`,
`run_shell_command(git)` and every other scoped entry are silent, as are the
`deny` and `ask` lists, which clew does not read as grants.

`trusted-server` flags `trust: true` on an MCP server. A server decides for
itself what tools it offers, so trusting one is not trusting a fixed list: a
tool added later is trusted too, and a tool whose description changes is never
shown again. `trust` is Gemini's spelling, and only Gemini's rows are checked
for it, so the same key copied into a file read by a tool that ignores it is
reported as part of the declaration and is not a finding. A per-tool list such
as Cline's `autoApprove` names what it approves rather than approving all of
it, so it is not this rule.

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
`executionSuccessful: false`. Each rule is tagged `security` with a
`security-severity` score in GitHub's band for its severity, so code scanning
ranks an alert as clew does. `system` cannot write one: SARIF places a result
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

### GitHub Action

The action scans the checkout and uploads the SARIF log to code scanning, where
each finding is an alert on the line it was found:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v6
  - uses: Sysogen/clew@v0.6.0
    with:
      fail-on: high
```

It downloads the clew release it names for the runner, on Linux, macOS or
Windows, and refuses the download unless it matches the checksum published
beside it. Pin the action to a tag or a commit, since that decides which clew
runs.

| Input | Default | Meaning |
| --- | --- | --- |
| `fail-on` | none | Fail on a finding at `low`, `medium` or `high` or worse |
| `path` | the workspace | Where the repository is checked out, scanned as its root |
| `upload` | `true` | Upload to code scanning; `false` where it is not enabled |
| `version` | the action's own | The clew release to run |

The report is also printed to the job log and the run's summary page, so a
finding can be read without opening code scanning. The step ends as clew
exits, after the upload: it fails on an incomplete scan, and on a finding at
`fail-on`. A pull request from a fork gets a read-only token, so set `upload`
to `false` there.

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
