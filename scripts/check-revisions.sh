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

# Each snapshot, and the line that carries its number.
snapshots=(
    "crates/domain/rule-pack.snapshot:version"
    "crates/domain/catalogue.snapshot:revision"
)

stale=0
for entry in "${snapshots[@]}"; do
    file="${entry%%:*}"
    key="${entry##*:}"

    if ! git cat-file -e "$base:$file" 2>/dev/null; then
        echo "revisions: $file is new; nothing to compare"
        continue
    fi

    was="$(git show "$base:$file")"
    now="$(cat "$file")"

    # The number, and everything else that is not a comment or blank.
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
    printf 'one rule pack, or a finding cannot be traced to what judged it.\n' >&2
    exit 1
fi
printf 'revisions: every changed snapshot raised its number\n'
