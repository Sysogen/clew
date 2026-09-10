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
| `clew-domain` | Domain: types, rules, ports | nothing but `thiserror` |
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

Extend `SUFFIXES` in `crates/domain/src/catalog.rs` with the path suffix and its
`SurfaceKind`, then add a test in the same file.

Match on the full path suffix at a segment boundary, never the bare file name.
`.claude/settings.json` must match; a `settings.json` sitting anywhere else must
not. `RepoPath::ends_with_segments` exists for exactly this, and there are tests
that fail if you bypass it.

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

**You do not need to install the git hooks.** They exist for maintainers and
include a commit-signing gate that would refuse your commits unless you have SSH
signing configured. If you want them anyway:

```sh
git config core.hooksPath .githooks
```

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

## Reporting a bug

Open an issue with the surface you expected, what `clew` reported, and the
directory layout that reproduces it. For a security problem, follow
[SECURITY.md](SECURITY.md) instead.

## Licence

Contributions are accepted under Apache-2.0, matching the project.
