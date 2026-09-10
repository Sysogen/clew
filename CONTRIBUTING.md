# Contributing

## Before you open a pull request

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

CI runs exactly these on Linux, macOS, and Windows.

## Adding a surface

A surface is a file that configures an AI coding agent. To add one, extend
`SURFACES` in `src/main.rs` with the path suffix and a short label, then add a
test.

Match on the full path suffix, never the bare filename. `.claude/settings.json`
must match; a `settings.json` sitting anywhere else must not. There is a test
for this and it will fail if you get it wrong.

## Two rules that are not style preferences

`clew` never executes anything it discovers, and never reads a credential
value. A change that breaks either is a security defect, not a feature. See
[SECURITY.md](SECURITY.md).

## Reporting a bug

Open an issue with the surface you expected, what `clew` reported, and the
directory layout that reproduces it. For a security problem, follow
[SECURITY.md](SECURITY.md) instead.

## Licence

Contributions are accepted under Apache-2.0, matching the project.
