#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# clew never executes anything it discovers. This proves it two ways.
#
# The source scan rejects any API that can start a process. The binary scan is
# the stronger one: a linked artifact that never reaches Command has no
# undefined reference to execvp, fork or posix_spawn, and one that does reaches
# for about a dozen of them. That holds whatever the source looks like.
#
#   ./scripts/check-no-exec.sh            source only
#   ./scripts/check-no-exec.sh <binary>   source and that binary

set -euo pipefail

# Matched with perl, so these are perl patterns. Written to catch the call, not
# the word: clew's own domain has a `command` field on every hook it reports.
readonly FORBIDDEN='(?x)
      (?: std:: )? process::Command
    | \bCommand::new\b
    | \blibc::(?: execv | execl | execle | execvp | execvpe | fork
                | system | posix_spawn )
    | \btokio::process\b
    | \bstd::os::unix::process::CommandExt\b
'

# Any of these in the symbol table means the artifact can start a process.
readonly SPAWN_SYMBOLS='execv|execl|execvp|execve|_fork$|posix_spawn|\bsystem\b|popen|CreateProcess'

fail() {
    printf 'no-exec: %s\n' "$1" >&2
    exit 1
}

scan_source() {
    local hits
    hits="$(find crates -name '*.rs' -print0 \
        | xargs -0 perl -ne "print qq(  \$ARGV:\$.: \$_) if /$FORBIDDEN/; close ARGV if eof" 2>/dev/null || true)"

    if [ -n "$hits" ]; then
        printf '%s\n' "$hits" >&2
        fail 'source can start a process'
    fi
    printf 'no-exec: no process-spawning API in %s source files\n' \
        "$(find crates -name '*.rs' | wc -l | tr -d ' ')"
}

scan_binary() {
    local binary="$1"
    [ -f "$binary" ] || fail "no binary at $binary"

    if ! command -v nm >/dev/null 2>&1; then
        printf 'no-exec: nm is unavailable, skipping the binary scan\n' >&2
        return 0
    fi

    # The release profile strips, and the two nm implementations disagree about
    # where undefined symbols then live: GNU needs -D to read the dynamic table,
    # macOS reports nothing for -D and everything for -u. Try both and require
    # that one of them actually read something.
    local undefined hits
    undefined=""
    for form in "-D -u" "-u"; do
        # shellcheck disable=SC2086
        undefined="$(nm $form "$binary" 2>/dev/null || true)"
        [ -n "$undefined" ] && break
    done
    [ -n "$undefined" ] || fail "read no symbols from $binary; the scan would pass vacuously"

    hits="$(printf '%s\n' "$undefined" | grep -iE "$SPAWN_SYMBOLS" || true)"
    if [ -n "$hits" ]; then
        printf '%s\n' "$hits" >&2
        fail "$binary imports a process-spawning symbol"
    fi
    printf 'no-exec: %s imports none of %s undefined symbols that can spawn\n' \
        "$(basename "$binary")" "$(printf '%s\n' "$undefined" | wc -l | tr -d ' ')"
}

scan_source
# An empty argument is treated as none: a caller passing "\${1:-}" should not
# get a confusing failure about a binary at the empty path.
[ "$#" -eq 0 ] || [ -z "$1" ] || scan_binary "$1"
