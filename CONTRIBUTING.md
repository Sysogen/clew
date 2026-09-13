# Contributing

## Toolchain

`rust-toolchain.toml` pins the channel, so `rustup` installs the right one on
first build and no setup step is needed.

Two version numbers do different jobs and are allowed to differ:

| Where | Meaning |
| --- | --- |
| `rust-toolchain.toml` | The toolchain this repository is developed and checked with |
| `rust-version` in `Cargo.toml` | The minimum a consumer needs, verified by the `MSRV` CI job |

The workspace is on edition 2024.

## Before you open a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs exactly these on Linux, macOS, and Windows, plus an `MSRV` job that
builds on the declared minimum and a `Commit messages` job.

## Architecture

Ports and adapters. The dependency direction is one-way and the compiler
enforces it, because each layer is its own crate.

| Crate | Layer | May depend on |
| --- | --- | --- |
| `clew-domain` | Domain: types, rules, ports, the catalogue | parsers and matchers only: no IO, no async, no runtime |
| `clew-application` | Use cases | domain |
| `clew-adapter-cli` | Inbound: parse and render | application, domain |
| `clew-adapter-fs` | Outbound: `FileTree` over `std::fs` | domain |
| `clew-cli` | Composition root, the binary | all of the above |

Two rules follow from this and are checked in review:

- `std::fs`, `std::net`, and `std::process` appear only in an outbound adapter.
  The domain and application layers must compile without them.
- Every outside capability is a trait in `clew_domain::ports`, one per file with
  its own error type. This is why the traversal is tested against an in-memory
  tree rather than a temporary directory.

## Adding a surface

Add a row to `crates/domain/catalogue.toml`. No Rust required.

```toml
[[surface]]
glob          = "**/.cursor/rules/**/*.mdc"
tool          = "cursor"
kind          = "cursor"
last_verified = "2026-09-11"
source        = "https://cursor.com/docs/rules"
```

Add `extract` when the file should be read:

```toml
extract = ["hooks", "permissions", "mcp-servers"]
```

Omit it, and `check` below, and the file is inventory only: reported, never
opened. That matters when it may be a compiled binary, and it is why a hook
script is never read.

Add `check` when a rule should read the file:

```toml
check = ["invisible-unicode"]
```

Declare it on prose an agent reads as instructions, never on settings. The row
decides rather than the tool, because one tool keeps both side by side and
evidence quoted from settings would print them.

Add `format` when the file is not JSON:

```toml
format = "toml"
```

`markdown` reads the YAML block a file opens with and ignores the prose. Every
format parses into the same value, so an extractor never knows which it came
from and a new format costs one arm rather than a second copy of every
extractor.

Only declare an extraction whose shape you have checked. `mcp-servers` reads the
`mcpServers` key and Codex's `mcp_servers`; a tool using a third spelling needs
that spelling added, and a tool with a different shape needs its own extractor.
`permissions` reads settings' `permissions.allow` and frontmatter's
`allowed-tools`, which may be a list or one comma-separated line. Each format
reads only its own spelling, since reporting the other would invent a grant.

`source` must be the tool's own documentation, not a blog post, and
`last_verified` is the day you checked it. Loading rejects a row missing either,
naming an unknown kind, an unknown extraction, or an unknown check.

The first matching row wins, so put a specific pattern above a general one.

A literal segment matches exactly. `**/.claude/settings.json` matches at any
depth; a `settings.json` sitting anywhere else does not. A `hooks` directory must
sit below `.claude`, which is why the glob is `**/.claude/**/hooks/**` rather
than `**/hooks/**`.

A `*` stays inside one segment and `**` crosses them, so
`**/.agents/skills/*/SKILL.md` is one directory deep and no more.

## Two rules that are not style preferences

`clew` never executes anything it discovers, and never reads a credential
value. A change that breaks either is a security defect, not a feature. See
[SECURITY.md](SECURITY.md).

## Commit messages

This repository follows the [Angular commit message
guidelines](https://github.com/angular/angular/blob/main/contributing-docs/commit-message-guidelines.md).
CI rejects a branch containing a message that does not.

```
<type>(<optional scope>): <summary>
                                        <- blank line
<body>
                                        <- blank line
<footer>
```

### Type

One of eight. There is no `chore`; pick the one that describes the change.

| Type | For |
| --- | --- |
| `build` | The build system, packaging, or dependencies |
| `ci` | CI configuration and scripts |
| `docs` | Documentation only |
| `feat` | A new feature |
| `fix` | A bug fix |
| `perf` | A change that improves performance |
| `refactor` | A change that neither fixes a bug nor adds a feature |
| `test` | Adding or correcting tests |

Scope is optional and lower case. Use the crate it touches without the `clew-`
prefix: `domain`, `application`, `adapter-cli`, `adapter-fs`, `cli`.

### Summary

Imperative present tense, "add" rather than "added" or "adds". No capital first
letter, no full stop at the end. Aim for 50 characters and never exceed 72, so
`git log --oneline` and review interfaces do not truncate it.

### Body

**Mandatory on every type except `docs`**, and at least 20 characters. Wrap at
72 columns. Explain the motivation and what changed in behaviour, not the
mechanics the diff already shows. Imperative present tense here too.

### Footer

Optional. A breaking change starts with `BREAKING CHANGE: `, a removal with
`DEPRECATED: `, and issues are closed with `Fixes #12` or `Closes #12`.

### Examples

```
fix(domain): match a surface on segment boundaries

A bare settings.json was classified as Claude Code configuration because
matching used the file name. Compare the full path suffix instead.

Fixes #14
```

```
docs: correct the install command in the readme
```

### Checking before you push

Optional, and worth running if you want the feedback early:

```sh
./scripts/check-commit-message.sh --range origin/main..HEAD
```

Merge commits and reverts are exempt. Tense is documented but not linted,
because no regex distinguishes "embed" from "embedded" without rejecting
legitimate words.

Installing the hooks is optional and safe:

```sh
git config core.hooksPath .githooks
```

That checks your commit messages as you write them. The signing and identity
gates in the same directory stay switched off unless a repository opts in with
`hooks.maintainer`, so they will not refuse your commits.

### How your pull request gets merged

Pull requests are **squash merged**, so the whole branch lands on `main` as one
commit whose subject is the pull request title. Three things follow:

- **Your individual commit messages do not have to follow the convention.** CI
  reports on them so you can see the house style, but that check cannot block
  the merge. Commit however helps you work.
- **The pull request title does need to follow it**, because it becomes the
  subject of the commit that lands. If CI flags it, a maintainer can fix it by
  editing the title; you are not asked to rewrite history.
- **Your commits do not need to be signed.** GitHub signs the squash commit it
  creates, so `main` stays fully signed regardless.

What genuinely has to pass is `cargo fmt`, `cargo clippy`, and the tests, on
Linux, macOS, and Windows. Those are correctness, not style.

A maintainer can waive the title check for one pull request with the
`override: commit-convention` label.

## Releasing

Maintainers only.

1. Open a pull request that raises `version` in the root `Cargo.toml`, raises
   the five `clew-*` entries under `[workspace.dependencies]` to match, and
   moves `CHANGELOG.md`'s `Unreleased` section under the new number.
2. Merge it.

The internal dependency pins are not optional. Miss them and the published
crates ask for the previous release of each other, so the five are not a
coherent set. `./scripts/check-versions.sh` runs in CI and fails the pull
request if they drift.

From there `Tag` sees the version changed, creates `v<version>`, and starts
`Release`. A push that does not change the version produces no tag, so a
documentation change does not release.

Workflow files are parsed in CI. An unparseable one is accepted by the push and
fails only when it runs, reported against its path rather than its name, so it
is checked before merge.

`Release` refuses to publish unless CI already succeeded on that commit, the
tag matches the manifest version, and the tag is an ancestor of `main`. It
builds every binary before publishing, because a crates.io version can be
yanked but never replaced and a failed target must not leave crates published
without artifacts.

### The first release is manual

`Tag` only fires on a version change, so the current version never gets a tag
on its own. Push it by hand, or use `Release`'s `Run workflow` button and give
it the tag. The same applies to retrying a failed release.

### Before any release

`Release` needs a `CARGO_REGISTRY_TOKEN` secret in the `crates-io` environment,
scoped to `publish-update` for the five `clew-*` crates.

## Reporting a bug

Open an issue with the surface you expected, what `clew` reported, and the
directory layout that reproduces it. For a security problem, follow
[SECURITY.md](SECURITY.md) instead.

## Licence

Contributions are accepted under Apache-2.0, matching the project.
