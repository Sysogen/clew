#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
#
# Download the clew release for this runner, refuse it unless it matches the
# checksum published beside it, and write the binary's path to GITHUB_OUTPUT
# as `clew`.
#
#   CLEW_VERSION   the version to install, such as 0.3.0
#   CLEW_RELEASES  where releases are downloaded from; the tests point it at a
#                  directory of doctored ones

set -euo pipefail

version="${CLEW_VERSION:?CLEW_VERSION is not set}"
releases="${CLEW_RELEASES:-https://github.com/Sysogen/clew/releases/download}"

if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "clew: not a version: $version" >&2
    exit 1
fi

case "${RUNNER_OS:-}/${RUNNER_ARCH:-}" in
Linux/X64) target=x86_64-unknown-linux-gnu ;;
Linux/ARM64) target=aarch64-unknown-linux-gnu ;;
macOS/X64) target=x86_64-apple-darwin ;;
macOS/ARM64) target=aarch64-apple-darwin ;;
Windows/X64) target=x86_64-pc-windows-msvc ;;
*)
    echo "clew: no release for ${RUNNER_OS:-this OS} on ${RUNNER_ARCH:-this CPU}" >&2
    exit 1
    ;;
esac

name="clew-v$version-$target"
dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/clew.XXXXXX")"
cd "$dir"
curl --fail --silent --show-error --location --retry 3 \
    --remote-name "$releases/v$version/$name.tar.gz" \
    --remote-name "$releases/v$version/$name.tar.gz.sha256"

# Compared by value: `--check` would trust the file name the checksum names.
# Windows runners have sha256sum and not shasum; macOS the reverse.
expected="$(cut -d ' ' -f 1 "$name.tar.gz.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$name.tar.gz" | cut -d ' ' -f 1)"
else
    actual="$(shasum -a 256 "$name.tar.gz" | cut -d ' ' -f 1)"
fi
if [ "$actual" != "$expected" ]; then
    echo "clew: $name.tar.gz does not match its published checksum" >&2
    exit 1
fi

tar -xzf "$name.tar.gz"
binary="$dir/$name/clew"
if [ "$RUNNER_OS" = Windows ]; then
    binary="$binary.exe"
fi
echo "clew=$binary" >>"$GITHUB_OUTPUT"
