#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Scan a checkout into a SARIF log, and write the log's path and clew's exit
# status to GITHUB_OUTPUT as `sarif` and `status`. It exits 0 itself, so the
# log is uploaded before a failing status fails the step after it. The report
# is also printed to the job log and the run's summary page, which code
# scanning's log is not.
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

# What clew prints quotes the repository, where a line opening with `::` would
# be run as a workflow command, so commands stop until a token the repository
# cannot know.
token="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
echo "::stop-commands::$token"

status=0
"$CLEW" "${args[@]}" >"$sarif" || status=$?

# The same scan as text. Its exit status is the SARIF scan's to report.
report="$("$CLEW" path "$SCAN_PATH" 2>&1 || true)"
printf '%s\n' "$report"
echo "::$token::"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    # Evidence writes a hidden character as <U+XXXX>, which the page would
    # otherwise read as a tag.
    {
        printf '### clew\n\n<pre>\n'
        printf '%s\n' "$report" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
        printf '</pre>\n'
    } >>"$GITHUB_STEP_SUMMARY"
fi

echo "status=$status" >>"$GITHUB_OUTPUT"
# A command line clew rejects writes no log, and there is nothing to upload.
if [ -s "$sarif" ]; then
    echo "sarif=$sarif" >>"$GITHUB_OUTPUT"
fi
