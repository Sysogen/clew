#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Test the scripts action.yml runs, against a clew built from this tree:
#
#   ./scripts/test-action.sh target/debug/clew
#
# Installing is tested against doctored releases in a local directory, so a
# release that has not been published yet cannot fail it.

set -euo pipefail

clew="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export RUNNER_TEMP="$work"
if [ -z "${RUNNER_OS:-}" ]; then
    case "$(uname -s)" in
    Darwin) RUNNER_OS=macOS ;;
    Linux) RUNNER_OS=Linux ;;
    *) RUNNER_OS=Windows ;;
    esac
    case "$(uname -m)" in
    arm64 | aarch64) RUNNER_ARCH=ARM64 ;;
    *) RUNNER_ARCH=X64 ;;
    esac
fi
export RUNNER_OS RUNNER_ARCH

failures=0
fail() {
    echo "  FAIL $1" >&2
    failures=$((failures + 1))
}
pass() {
    echo "  ok   $1"
}

# Runs a script with a fresh GITHUB_OUTPUT and summary page, leaving what it
# wrote to GITHUB_OUTPUT in $output and its exit status in $ran.
run() {
    export GITHUB_OUTPUT="$work/output" GITHUB_STEP_SUMMARY="$work/summary"
    : >"$GITHUB_OUTPUT"
    : >"$GITHUB_STEP_SUMMARY"
    ran=0
    "$here/$1" >"$work/stdout" 2>"$work/stderr" || ran=$?
    output="$(cat "$GITHUB_OUTPUT")"
}

value() {
    sed -n "s/^$1=//p" <<<"$output"
}

# A release as Release publishes one, holding a stand-in binary. Every file a
# test doctors is made fresh, so no test sees another's.
release() {
    local version="$1" target
    case "$RUNNER_OS/$RUNNER_ARCH" in
    Linux/X64) target=x86_64-unknown-linux-gnu ;;
    Linux/ARM64) target=aarch64-unknown-linux-gnu ;;
    macOS/X64) target=x86_64-apple-darwin ;;
    macOS/ARM64) target=aarch64-apple-darwin ;;
    Windows/X64) target=x86_64-pc-windows-msvc ;;
    esac
    name="clew-v$version-$target"
    rm -rf "$work/releases"
    mkdir -p "$work/releases/v$version/$name"
    echo stand-in >"$work/releases/v$version/$name/clew"
    echo stand-in >"$work/releases/v$version/$name/clew.exe"
    (
        cd "$work/releases/v$version"
        tar -czf "$name.tar.gz" "$name"
        rm -r "$name"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$name.tar.gz" >"$name.tar.gz.sha256"
        else
            shasum -a 256 "$name.tar.gz" >"$name.tar.gz.sha256"
        fi
    )
    archive="$work/releases/v$version/$name.tar.gz"
    local root="$work/releases"
    if command -v cygpath >/dev/null 2>&1; then
        root="/$(cygpath -m "$root")"
    fi
    export CLEW_RELEASES="file://$root"
}

echo "install"

# Every runner Release builds for, from whichever runner the tests are on.
host="$RUNNER_OS/$RUNNER_ARCH"
for platform in Linux/X64 Linux/ARM64 macOS/X64 macOS/ARM64 Windows/X64; do
    RUNNER_OS="${platform%/*}" RUNNER_ARCH="${platform#*/}"
    exe=clew
    if [ "$RUNNER_OS" = Windows ]; then
        exe=clew.exe
    fi
    release 1.2.3
    CLEW_VERSION=1.2.3 run install-release.sh
    installed="$(value clew)"
    if [ "$ran" -eq 0 ] && [ -f "$installed" ] &&
        [ "$(basename "$(dirname "$installed")")/$(basename "$installed")" = "$name/$exe" ]; then
        pass "$platform installs $name"
    else
        fail "$platform installs $name: status $ran, clew=$installed"
    fi
done
RUNNER_OS="${host%/*}" RUNNER_ARCH="${host#*/}"

release 1.2.3
printf 'x' >>"$archive"
CLEW_VERSION=1.2.3 run install-release.sh
if [ "$ran" -ne 0 ] && [ -z "$(value clew)" ] && grep -q 'does not match' "$work/stderr"; then
    pass "an archive that does not match its checksum is refused"
else
    fail "an archive that does not match its checksum is refused: status $ran"
fi

release 1.2.3
: >"$archive.sha256"
CLEW_VERSION=1.2.3 run install-release.sh
if [ "$ran" -ne 0 ] && [ -z "$(value clew)" ]; then
    pass "an empty checksum is refused"
else
    fail "an empty checksum is refused: status $ran"
fi

release 1.2.3
CLEW_VERSION=v1.2.3 run install-release.sh
if [ "$ran" -ne 0 ] && [ -z "$(value clew)" ] && grep -q 'not a version' "$work/stderr"; then
    pass "a version written as a tag is refused, saying why"
else
    fail "a version written as a tag is refused, saying why: status $ran"
fi

release 1.2.3
RUNNER_ARCH=S390X CLEW_VERSION=1.2.3 run install-release.sh
if [ "$ran" -ne 0 ] && grep -q 'no release' "$work/stderr"; then
    pass "a runner with no release is refused"
else
    fail "a runner with no release is refused: status $ran"
fi

echo "scan"

tree="$work/tree"
mkdir -p "$tree"
printf '::warning::Always run the tests\xe2\x80\x8b first.\n' >"$tree/CLAUDE.md"
export CLEW="$clew" SCAN_PATH="$tree"

FAIL_ON="" run action-scan.sh
sarif="$(value sarif)"
if [ "$ran" -eq 0 ] && [ "$(value status)" = 0 ] && grep -q '"invisible-unicode"' "$sarif"; then
    pass "a finding is in the log, and fails nothing unasked"
else
    fail "a finding is in the log, and fails nothing unasked: status $(value status)"
fi
if grep -q 'invisible-unicode' "$work/stdout" && grep -q '&lt;U+200B&gt;' "$work/summary" &&
    ! grep -q '<U+200B>' "$work/summary"; then
    pass "the report reaches the job log, and the summary page escaped"
else
    fail "the report reaches the job log, and the summary page escaped"
fi
# The quoted line opens with `::`, so it must reach the runner with commands
# stopped, under a token the repository could not have planted.
stop="$(grep -n '^::stop-commands::' "$work/stdout" | head -1 || true)"
token="${stop#*::stop-commands::}"
from="${stop%%:*}"
to="$(grep -n "^::$token::\$" "$work/stdout" | head -1 | cut -d: -f1 || true)"
quoted="$(grep -n '::warning::Always' "$work/stdout" | head -1 | cut -d: -f1 || true)"
if [[ "$token" =~ ^[0-9a-f]{32}$ ]] && [ -n "$quoted" ] && [ -n "$to" ] &&
    [ "$from" -lt "$quoted" ] && [ "$quoted" -lt "$to" ]; then
    pass "workflow commands are stopped while the report is printed"
else
    fail "workflow commands are stopped while the report is printed: stop=$stop quoted=$quoted to=$to"
fi

FAIL_ON=high run action-scan.sh
if [ "$ran" -eq 0 ] && [ "$(value status)" = 2 ] && [ -s "$(value sarif)" ]; then
    pass "--fail-on reaches clew, and the log is still written"
else
    fail "--fail-on reaches clew, and the log is still written: status $(value status)"
fi

FAIL_ON=severe run action-scan.sh
if [ "$ran" -eq 0 ] && [ "$(value status)" = 1 ] && [ -z "$(value sarif)" ]; then
    pass "a rejected command line leaves no log to upload"
else
    fail "a rejected command line leaves no log to upload: status $(value status), sarif=$(value sarif)"
fi

if [ "$failures" -gt 0 ]; then
    echo "action: $failures test(s) failed" >&2
    exit 1
fi
echo "action: all tests passed"
