#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# clew never executes anything it discovers. This proves it two ways.
#
# The source scan rejects any API that can start a process. The binary scan is
# the stronger one: a linked artifact that never reaches Command has no
# undefined reference to execvp, fork or posix_spawn, and one that does reaches
# for about a dozen of them.

set -euo pipefail

# Matched with perl, so these are perl patterns. Written to catch the call, not
# the word.
readonly FORBIDDEN='(?x)
      (?: std:: )? process::Command
    | \bCommand::new\b
    | \blibc::(?: execv | execl | execle | execlp | execvp | execvpe | execve
                | fork | vfork | system | posix_spawn )
    | \btokio::process\b
    | \bstd::os::unix::process::CommandExt\b
'

# Matched against a bare symbol name, so pthread_atfork cannot look like fork.
readonly SPAWN_SYMBOL='^_?(execv|execl|execle|execlp|execvp|execvpe|execve|fork|vfork|posix_spawn[a-z_]*|system|popen|CreateProcess[AW]?)(@.*)?$'

fail() {
    printf 'no-exec: %s\n' "$1" >&2
    exit 1
}

scan_source() {
    command -v perl >/dev/null 2>&1 || fail 'perl is unavailable, so the source was not scanned'
    [ -d crates ] || fail 'no crates directory, so there is nothing to scan'

    local files count hits
    files="$(find crates -name '*.rs')"
    count="$(printf '%s\n' "$files" | grep -c . || true)"
    [ "$count" -gt 0 ] || fail 'found no Rust sources, so the scan would pass vacuously'

    # No `|| true`: a perl or xargs failure must not read as a clean scan.
    hits="$(printf '%s\n' "$files" \
        | xargs perl -ne "print qq(  \$ARGV:\$.: \$_) if /$FORBIDDEN/; close ARGV if eof")"

    if [ -n "$hits" ]; then
        printf '%s\n' "$hits" >&2
        fail 'source can start a process'
    fi
    printf 'no-exec: no process-spawning API in %s source files\n' "$count"
}

scan_binary() {
    local binary="$1"
    [ -f "$binary" ] || fail "no binary at $binary"
    command -v nm >/dev/null 2>&1 || fail 'nm is unavailable, so the binary was not scanned'

    # The release profile strips, and the two nm implementations disagree about
    # where undefined symbols then live: GNU needs -D to read the dynamic
    # table, macOS reports nothing for -D and everything for -u.
    local names form hits
    names=""
    for form in "-D -u" "-u"; do
        # shellcheck disable=SC2086
        names="$(nm $form "$binary" 2>/dev/null | awk 'NF { print $NF }' || true)"
        [ -n "$names" ] && break
    done
    [ -n "$names" ] || fail "read no symbols from $binary; the scan would pass vacuously"

    hits="$(printf '%s\n' "$names" | grep -E "$SPAWN_SYMBOL" || true)"
    if [ -n "$hits" ]; then
        printf '%s\n' "$hits" | sed 's/^/  /' >&2
        fail "$binary imports a symbol that can start a process"
    fi
    printf 'no-exec: %s imports none of %s undefined symbols that can spawn\n' \
        "$(basename "$binary")" "$(printf '%s\n' "$names" | grep -c . || true)"
}

scan_source
# An empty argument is treated as none, so a caller passing "${1:-}" does not
# get a confusing failure about a binary at the empty path.
[ "$#" -eq 0 ] || [ -z "$1" ] || scan_binary "$1"
