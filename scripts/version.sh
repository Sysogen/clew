#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Print the workspace version, optionally from a past revision:
#
#   ./scripts/version.sh              the working tree
#   ./scripts/version.sh <revision>   that revision
#
# A script rather than a line inside a workflow, because a multi-line
# interpreter call in a YAML block scalar is one stray indent away from
# silently ending the block.

set -euo pipefail

manifest() {
    if [ "$#" -eq 0 ]; then
        cat Cargo.toml
    else
        git show "$1:Cargo.toml"
    fi
}

# The anchored form matches only the standalone key under [workspace.package],
# never the `version =` inside a dependency table.
manifest "$@" | sed -n 's/^version = "\(.*\)"$/\1/p' | head -1
