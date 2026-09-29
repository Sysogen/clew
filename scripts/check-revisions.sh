#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Refuse a snapshot whose content changed while its version did not:
#
#   ./scripts/check-revisions.sh [base-ref]
#
# The snapshot tests compare a snapshot against the code, which catches a change
# nobody wrote down. They cannot catch a change written down without raising the
# number, because updating both keeps them equal, and then one number names two
# different rule packs. A study citing that number would be citing nothing.
#
# Only a comparison against history can see it, which is why this is a script
# and not a test.

set -euo pipefail

base="${1:-origin/main}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! git rev-parse --verify --quiet "$base" >/dev/null; then
    echo "revisions: no $base to compare against; skipped" >&2
    exit 0
fi

# The rule pack snapshot carries a `pack <name> <version>` line per pack, and a
# rule row ending in the pack that holds it. Each pack is compared on its own:
# one pack's rows changing while another's version is raised would otherwise
# pass, and the unchanged number would name two different sets of rules.
check_packs() {
    local was="$1" now="$2" file="$3" bad=0 name
    for name in $(printf '%s\n%s\n' "$was" "$now" |
        grep -E '^pack ' | awk '{print $2}' | sort -u); do
        local was_rows now_rows was_version now_version
        was_rows="$(printf '%s\n' "$was" | grep -E " ${name}\$" || true)"
        now_rows="$(printf '%s\n' "$now" | grep -E " ${name}\$" || true)"
        was_version="$(printf '%s\n' "$was" | grep -E "^pack ${name} " || true)"
        now_version="$(printf '%s\n' "$now" | grep -E "^pack ${name} " || true)"

        if [ "$was_rows" = "$now_rows" ]; then
            continue
        fi
        if [ "$was_version" != "$now_version" ]; then
            echo "revisions: pack ${name} changed and its version was raised"
            continue
        fi
        printf 'revisions: %s: pack %s changed while its version stayed at %s\n' \
            "$file" "$name" "$(printf '%s' "$now_version" | awk '{print $3}')" >&2
        bad=$((bad + 1))
    done
    return "$bad"
}

# A snapshot with one number, and the line that carries it.
single=("crates/domain/catalogue.snapshot:revision")

stale=0

packs="crates/domain/rule-pack.snapshot"
if git cat-file -e "$base:$packs" 2>/dev/null; then
    # `$?` after `if ! cmd` is the negation, not the function's count.
    check_packs "$(git show "$base:$packs")" "$(cat "$packs")" "$packs" ||
        stale=$((stale + $?))
else
    echo "revisions: $packs is new; nothing to compare"
fi

for entry in "${single[@]}"; do
    file="${entry%%:*}"
    key="${entry##*:}"

    if ! git cat-file -e "$base:$file" 2>/dev/null; then
        echo "revisions: $file is new; nothing to compare"
        continue
    fi

    was="$(git show "$base:$file")"
    now="$(cat "$file")"

    number_of() { printf '%s\n' "$1" | grep -E "^${key} " || true; }
    content_of() { printf '%s\n' "$1" | grep -vE "^#|^${key} |^[[:space:]]*$" || true; }

    if [ "$(content_of "$was")" = "$(content_of "$now")" ]; then
        continue
    fi
    if [ "$(number_of "$was")" != "$(number_of "$now")" ]; then
        echo "revisions: $file changed and its $key was raised"
        continue
    fi

    printf 'revisions: %s changed while %s stayed at %s\n' \
        "$file" "$key" "$(number_of "$now" | awk '{print $2}')" >&2
    stale=$((stale + 1))
done

if [ "$stale" -gt 0 ]; then
    printf 'A snapshot may not change without its number. One number must name\n' >&2
    printf 'one set of rules, or a finding cannot be traced to what judged it.\n' >&2
    exit 1
fi
printf 'revisions: every changed snapshot raised its number\n'
