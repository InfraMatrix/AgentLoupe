#!/usr/bin/env python3
"""Build-time hygiene check: no personal data or captures may be tracked.

Fails (exit 1) when either holds for any file in ``git ls-files``:

  * the file's bytes contain a home-directory path (slash, "home",
    slash) — e.g. a capture or report rendered on a developer's
    machine, or a config hardcoding one user's install path; or
  * the file is a ``*.jsonl`` capture tracked anywhere other than
    ``test/fixtures/`` (the only place synthetic captures belong).

The needle is assembled at runtime so this script does not itself
contain the literal it searches for (it is, after all, tracked).

Usage: check_tracked_files.py   (run from anywhere in the repo)
Exit:  0 = clean; 1 = violation, not a git checkout, or git failed.
"""
import subprocess
import sys
from pathlib import Path

NEEDLE = b"/" + b"home" + b"/"
FIXTURE_PREFIX = "test/fixtures/"


def main() -> int:
    try:
        root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
        raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"check-tracked-files: FAIL — cannot list tracked files: {e}")
        return 1

    tracked = [p for p in raw.decode("utf-8", "surrogateescape").split("\0") if p]
    failures = []
    for rel in tracked:
        if rel.endswith(".jsonl") and not rel.startswith(FIXTURE_PREFIX):
            failures.append(
                f"{rel}: tracked *.jsonl capture outside {FIXTURE_PREFIX}"
            )
        try:
            data = (Path(root) / rel).read_bytes()
        except OSError:
            continue  # tracked but absent from this worktree; nothing to scan
        if NEEDLE in data:
            failures.append(f"{rel}: contains a home-directory path")

    if failures:
        print("check-tracked-files: FAIL — personal data / captures must not be tracked:")
        for f in failures:
            print("  " + f)
        print("  (remove the file from the index with: git rm --cached <file>)")
        return 1
    print(f"check-tracked-files: OK ({len(tracked)} tracked files, no home paths, "
          f"no *.jsonl outside {FIXTURE_PREFIX})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
