#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Write a page per rule, and the README's rule table, from the rule pack:
#
#   ./scripts/rule-pages.sh --write    bring them up to date
#   ./scripts/rule-pages.sh --check    fail if they are not
#
# Generated rather than written, because the same words reach a code scanning
# alert, `clew explain`, a page and the README, and four copies of a sentence is
# how one rule comes to mean three things. `clew rules --format json` is the one
# source they all come from.

set -euo pipefail

mode="${1:---check}"
case "$mode" in
--write | --check) ;;
*)
    echo "usage: $0 [--write|--check]" >&2
    exit 1
    ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

pack="$(mktemp)"
trap 'rm -f "$pack"' EXIT
cargo run --quiet --bin clew -- rules --format json >"$pack"

python3 - "$mode" "$pack" <<'PY'
import json
import pathlib
import sys

mode, pack_path = sys.argv[1], sys.argv[2]
pack = json.loads(pathlib.Path(pack_path).read_text())
stale = []


def wrap(text, width=79):
    words, lines, line = text.split(), [], ""
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        lines.append(line)
    return "\n".join(lines)


def settle(path, wanted):
    path = pathlib.Path(path)
    held = path.read_text() if path.exists() else None
    if held == wanted:
        return
    if mode == "--write":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(wanted)
        print(f"wrote {path}")
    else:
        stale.append(str(path))


wanted = set()
for rule in pack["rules"]:
    wanted.add(f"docs/rules/{rule['id']}.md")
    page = (
        f"# {rule['id']}\n\n"
        f"Severity **{rule['severity']}**, "
        f"pack {rule['pack']['name']} {rule['pack']['version']}.\n\n"
        f"{wrap(rule['description'])}\n\n"
        "## What it means\n\n"
        f"{wrap(rule['detail'])}\n\n"
        "## What to do\n\n"
        f"{wrap(rule['remediation'])}\n\n"
        "---\n\n"
        "Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule\n"
        f"in `crates/domain/src/rules/{rule['id'].replace('-', '_')}.rs`, not this page.\n"
    )
    settle(f"docs/rules/{rule['id']}.md", page)

# A rule removed or renamed leaves its page behind, still read as current by
# anybody who finds it, and nothing else would say so.
for path in sorted(pathlib.Path("docs/rules").glob("*.md")):
    if str(path) in wanted:
        continue
    if mode == "--write":
        path.unlink()
        print(f"removed {path}, which no rule claims")
    else:
        stale.append(f"{path} (no rule claims it)")

# The README table, between its markers, so the copy a reader sees first cannot
# drift from the binary.
readme = pathlib.Path("README.md")
text = readme.read_text()
open_at = "<!-- rules:start -->\n"
close_at = "<!-- rules:end -->"
start, end = text.index(open_at) + len(open_at), text.index(close_at)
rows = ["| Rule | Severity | What it flags |", "| --- | --- | --- |"]
for rule in pack["rules"]:
    flags = rule["description"].replace("|", "\\|")
    rows.append(f"| [`{rule['id']}`]({rule['page']}) | {rule['severity']} | {flags} |")
settle("README.md", text[:start] + "\n".join(rows) + "\n" + text[end:])

if stale:
    print("stale, run ./scripts/rule-pages.sh --write:", file=sys.stderr)
    for path in stale:
        print(f"  {path}", file=sys.stderr)
    sys.exit(1)
print(f"rule pages: {len(pack['rules'])} page(s) and the README table are current")
PY
