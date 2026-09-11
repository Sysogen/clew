#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Every internal dependency must be pinned at the workspace version.
#
# A bump that misses them publishes crates that ask for the previous release of
# each other, so the five are not a coherent set. cargo accepts it, which is
# why this has to be checked rather than noticed.

set -euo pipefail

workspace="$(python3 -c "
import re
print(re.search(r'^version = \"([^\"]+)\"', open('Cargo.toml').read(), re.M).group(1))")"

mismatched=0
while read -r name pinned; do
    if [ "$pinned" != "$workspace" ]; then
        printf '  %s is pinned at %s, the workspace is at %s\n' "$name" "$pinned" "$workspace" >&2
        mismatched=$((mismatched + 1))
    fi
done < <(python3 -c "
import re
for m in re.finditer(r'^(clew-[a-z-]+) = \{ version = \"([^\"]+)\"', open('Cargo.toml').read(), re.M):
    print(m.group(1), m.group(2))")

if [ "$mismatched" -gt 0 ]; then
    printf 'version pins: %d internal dependenc(y|ies) do not match the workspace.\n' "$mismatched" >&2
    printf 'Raise them in the same commit as the workspace version.\n' >&2
    exit 1
fi

printf 'version pins: all internal dependencies at %s\n' "$workspace"
