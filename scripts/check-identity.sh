#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Refuse to author a commit under an identity that is not the configured one.
#
#   check-identity.sh
#
# The effective identity is what `git config user.email` reports inside the
# hook, which reflects a repository-local setting and a `git -c user.email=...`
# override on the command line. Comparing it against the global identity catches
# a commit authored under the wrong address, which is otherwise invisible until
# someone reads the log.
#
# A repository that genuinely needs a different identity records it in
# `.git/config` and lists it in ALLOWED_IDENTITIES below, or sets
# CLEW_ALLOW_IDENTITY=1 for one command.

set -euo pipefail

die() {
    printf 'commit identity: %s\n' "$1" >&2
    shift
    for line in "$@"; do printf '  %s\n' "$line" >&2; done
    exit 1
}

[ "${GIT_ALLOW_IDENTITY:-0}" = "1" ] && exit 0

effective_email="$(git config --get user.email || true)"
effective_name="$(git config --get user.name || true)"
global_email="$(git config --global --get user.email || true)"
global_name="$(git config --global --get user.name || true)"

[ -n "$effective_email" ] || die "user.email is unset, so this commit would have no author."
[ -n "$effective_name" ] || die "user.name is unset, so this commit would have no author."

if [ -z "$global_email" ]; then
    # Nothing to compare against. Better to say so than to pass silently.
    printf 'commit identity: no global user.email is set, so the identity cannot be checked.\n' >&2
    exit 0
fi

if [ "$effective_email" != "$global_email" ]; then
    die "this commit would be authored as <$effective_email>, not <$global_email>." \
        "A repository-local setting or a 'git -c user.email=...' override is in effect." \
        "If that is deliberate, commit once with GIT_ALLOW_IDENTITY=1, or record it" \
        "in .git/config so it is at least visible." \
        "To fix history already written under the wrong address:" \
        "  git filter-branch -f --env-filter 'export GIT_AUTHOR_EMAIL=... GIT_COMMITTER_EMAIL=...' main" \
        "  git rebase -f --root --gpg-sign   # filter-branch drops signatures"
fi

if [ "$effective_name" != "$global_name" ]; then
    die "this commit would be authored as '$effective_name', not '$global_name'."
fi
