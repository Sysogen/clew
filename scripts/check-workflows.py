#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Sysogen Lda
"""Parse every workflow file and check it declares what GitHub needs.

An unparseable workflow is accepted by the push and fails only when it runs,
reported against the file path rather than its name. A stray indent inside a
block scalar is enough to cause it.
"""

import pathlib
import sys

import yaml

WORKFLOWS = pathlib.Path(".github/workflows")


def main() -> int:
    problems = []
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if not files:
        print("no workflow files found", file=sys.stderr)
        return 1

    for path in files:
        try:
            parsed = yaml.safe_load(path.read_text())
        except yaml.YAMLError as error:
            problems.append(f"{path}: will not parse\n    {error}")
            continue

        if not isinstance(parsed, dict):
            problems.append(f"{path}: is not a mapping")
            continue
        # `on` is read as the boolean True unless quoted, which is why every
        # workflow here writes it as "on".
        for key in ("name", "jobs"):
            if key not in parsed:
                problems.append(f"{path}: has no {key}")
        if "on" not in parsed and True not in parsed:
            problems.append(f"{path}: has no triggers")
        if isinstance(parsed.get("jobs"), dict) and not parsed["jobs"]:
            problems.append(f"{path}: declares no jobs")

        print(f"  {path.name}: {parsed.get('name')!r}, "
              f"jobs {list(parsed.get('jobs', {}))}")

    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
