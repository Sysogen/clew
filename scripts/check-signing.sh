#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Refuse to produce or push an unsigned commit.
#
#   check-signing.sh --config       signing is configured and the key works
#   check-signing.sh --head         HEAD carries a good signature
#   check-signing.sh --range A..B   every commit in the range is signed
#
# Three checks because a signature can be lost in three different ways.
# --config catches an unconfigured machine before a commit exists. --head
# catches a commit that was created unsigned anyway. --range catches history
# that lost its signatures after the fact: filter-branch, a rebase without
# --gpg-sign, and cherry-pick all rewrite commit objects and drop signatures
# without running any commit hook.

set -euo pipefail

die() {
    printf 'commit signing: %s\n' "$1" >&2
    shift
    for line in "$@"; do printf '  %s\n' "$line" >&2; done
    exit 1
}

check_config() {
    local sign format key
    sign="$(git config --get commit.gpgsign || echo false)"
    if [ "$sign" != "true" ]; then
        die "commit.gpgsign is not enabled, so this commit would be unsigned." \
            "Enable it:" \
            "  git config --global gpg.format ssh" \
            "  git config --global user.signingkey ~/.ssh/<key>.pub" \
            "  git config --global commit.gpgsign true" \
            "  git config --global tag.gpgsign true"
    fi

    key="$(git config --get user.signingkey || true)"
    [ -n "$key" ] || die "commit.gpgsign is on but user.signingkey is unset."

    format="$(git config --get gpg.format || echo openpgp)"
    if [ "$format" = "ssh" ]; then
        # Expand a leading ~ that git stores literally.
        case "$key" in "~"*) key="$HOME${key#\~}" ;; esac
        [ -f "$key" ] || die "user.signingkey points at a file that does not exist: $key"

        local signers
        signers="$(git config --get gpg.ssh.allowedSignersFile || true)"
        case "$signers" in "~"*) signers="$HOME${signers#\~}" ;; esac
        if [ -z "$signers" ] || [ ! -f "$signers" ]; then
            die "gpg.ssh.allowedSignersFile is unset or missing." \
                "Without it git can sign but cannot verify, so an unsigned" \
                "commit cannot be told from a signed one." \
                "Create it, then:" \
                "  git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers"
        fi
    fi
}

# Verification states git reports for %G?.
#
# The gate exists to stop an UNSIGNED commit, so N (no signature) and B (bad
# signature) fail, as does any status not listed below: an unrecognised code
# means git is telling us something this script does not understand, and
# guessing in favour of the commit is the wrong default for a signing gate.
#
# The rest carry a signature this machine cannot fully validate, which is a
# different thing and common in normal use:
#
#   G  good
#   U  valid, but the key is not in the allowed signers file
#   E  a signature is present that git cannot check here. Usually a format
#      mismatch: a merge signed by the forge with PGP, read on a machine
#      configured for SSH signing. Blocking on this would refuse every push
#      after a web merge.
#   X  good, key expired since       Y  good, key expired at signing
#   R  good, key revoked
#
# X, Y, and R are reported loudly because they are real problems, but they are
# not what this gate is for and a maintainer needs to be able to push a fix.
verify_range() {
    local range="$1" bad=0 line status sha subject
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        status="${line%% *}"
        sha="${line#* }"
        sha="${sha%% *}"
        subject="${line#* * }"
        case "$status" in
        G) ;;
        U) printf '  note: %s %s (key not in allowed_signers)\n' "$sha" "$subject" >&2 ;;
        E) printf '  note: %s %s (signed, but not checkable with gpg.format=%s)\n' \
            "$sha" "$subject" "$(git config --get gpg.format || echo openpgp)" >&2 ;;
        X | Y | R) printf '  WARN (%s) %s %s (signing key expired or revoked)\n' \
            "$status" "$sha" "$subject" >&2 ;;
        N) printf '  UNSIGNED  %s %s\n' "$sha" "$subject" >&2; bad=$((bad + 1)) ;;
        B) printf '  BAD SIGNATURE  %s %s\n' "$sha" "$subject" >&2; bad=$((bad + 1)) ;;
        *) printf '  UNKNOWN (%s)  %s %s\n' "$status" "$sha" "$subject" >&2; bad=$((bad + 1)) ;;
        esac
    done < <(git log --no-merges --format='%G? %h %s' "$range")

    if [ "$bad" -gt 0 ]; then
        die "$bad commit(s) are unsigned or carry a bad signature." \
            "Re-sign them without changing content:" \
            "  git rebase -f --gpg-sign <commit-before-the-first-bad-one>" \
            "A rebase, cherry-pick, or filter-branch without --gpg-sign drops" \
            "signatures silently; that is usually how this happens."
    fi
}

case "${1:-}" in
--config) check_config ;;
--head)
    check_config
    verify_range "HEAD~1..HEAD" 2>/dev/null || verify_range "HEAD"
    ;;
--range) verify_range "${2:?--range needs A..B}" ;;
*)
    printf 'usage: %s --config | --head | --range A..B\n' "$0" >&2
    exit 2
    ;;
esac
