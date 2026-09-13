#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Wait for CI to finish on a commit, then succeed only if every CI run on it
# succeeded:
#
#   ./scripts/ci-passed.sh <sha>
#
# Tag starts a release the moment a version change lands on main, while CI on
# that commit is still running, so a check that does not wait finds no finished
# run and stops a release that would have passed.
#
# CI_APPEAR_SECONDS, CI_FINISH_SECONDS and CI_POLL_SECONDS set how long to wait
# for a run to appear, for every run to finish, and between looks.

set -euo pipefail

sha="${1:?usage: $0 <sha>}"
appear="${CI_APPEAR_SECONDS:-300}"
finish="${CI_FINISH_SECONDS:-1800}"
poll="${CI_POLL_SECONDS:-20}"

start=$SECONDS
while :; do
    runs="$(gh run list --commit "$sha" --workflow CI \
        --json status,conclusion --jq '.[] | "\(.status) \(.conclusion)"')"
    waited=$((SECONDS - start))
    if [ -z "$runs" ]; then
        if [ "$waited" -ge "$appear" ]; then
            echo "no CI run found for $sha; release only from a commit CI has checked" >&2
            exit 1
        fi
    elif ! grep -qv '^completed ' <<<"$runs"; then
        break
    elif [ "$waited" -ge "$finish" ]; then
        echo "CI on $sha has not finished after ${finish}s:" >&2
        echo "$runs" >&2
        exit 1
    fi
    sleep "$poll"
done

if grep -qv '^completed success$' <<<"$runs"; then
    echo "CI did not succeed on $sha:" >&2
    echo "$runs" >&2
    exit 1
fi
echo "CI succeeded on $sha"
