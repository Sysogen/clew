# Contributing

## Before you open a pull request

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

CI runs exactly these on Linux, macOS, and Windows.

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

## Reporting a bug

Open an issue with the surface you expected, what `clew` reported, and the
directory layout that reproduces it. For a security problem, follow
[SECURITY.md](SECURITY.md) instead.

## Licence

Contributions are accepted under Apache-2.0, matching the project.
