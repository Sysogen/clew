#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Scan a checkout into a SARIF log, and write the log's path and clew's exit
# status to GITHUB_OUTPUT as `sarif` and `status`. It exits 0 itself, so the
# log is uploaded before a failing status fails the step after it.
#
#   CLEW       the clew binary
#   SCAN_PATH  the checkout
#   FAIL_ON    low, medium or high; empty never fails on a finding

set -euo pipefail

sarif="$(mktemp -d "${RUNNER_TEMP:-/tmp}/clew.XXXXXX")/clew.sarif"
args=(path "$SCAN_PATH" --format sarif)
if [ -n "${FAIL_ON:-}" ]; then
    args+=(--fail-on "$FAIL_ON")
fi

status=0
"$CLEW" "${args[@]}" >"$sarif" || status=$?

echo "status=$status" >>"$GITHUB_OUTPUT"
# A command line clew rejects writes no log, and there is nothing to upload.
if [ -s "$sarif" ]; then
    echo "sarif=$sarif" >>"$GITHUB_OUTPUT"
fi
