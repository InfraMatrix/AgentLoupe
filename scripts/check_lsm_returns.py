#!/usr/bin/env python3
"""Build-time safety check: every BPF LSM program must only ever return 0.

A non-zero return from a BPF LSM hook DENIES the kernel operation, which
would turn this observe-only tool into an enforcement mechanism. This
script statically extracts the body of every function defined with
SEC("lsm...") or SEC("lsm.s...") in the given C file and fails unless
every `return` statement in those bodies is literally `return 0;`.

It intentionally checks the hook functions themselves (not helpers they
call — helpers return data to the hook, never to the kernel).

Usage: check_lsm_returns.py <file.bpf.c> [<file> ...]
Exit:  0 = all LSM hooks return only 0; 1 = violation or no LSM hooks found.
"""
import re
import sys


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments, PRESERVING string literals.

    The SEC("lsm/...") section names the checker searches for are string
    literals — stripping strings here (the original bug) deletes exactly
    what the regex is looking for, and the checker then reports 'no LSM
    programs found' on perfectly good source.
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j == -1 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
        elif src[i] in "\"'":
            # Copy the literal verbatim so SEC("...") survives.
            q = src[i]
            out.append(src[i])
            i += 1
            while i < n and src[i] != q:
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i : i + 2])
                    i += 2
                else:
                    out.append(src[i])
                    i += 1
            if i < n:
                out.append(src[i])
                i += 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def strip_strings(src: str) -> str:
    """Blank out string/char literal contents (return-scan of a body)."""
    out = []
    i, n = 0, len(src)
    while i < n:
        if src[i] in "\"'":
            q = src[i]
            out.append(" ")
            i += 1
            while i < n and src[i] != q:
                i += 2 if src[i] == "\\" else 1
            i += 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def extract_bodies(src: str):
    """Yield (section, function_name, body) for LSM program definitions."""
    clean = strip_comments(src)  # strings preserved: SEC("lsm/...") must match
    for m in re.finditer(r'SEC\("(lsm[^"]*)"\)\s*(?:int\s+)?(?:BPF_PROG\((\w+)|(\w+)\s*\()', clean):
        section, name = m.group(1), m.group(2) or m.group(3)
        open_idx = clean.find("{", m.end())
        if open_idx == -1:
            continue
        depth, i = 0, open_idx
        while i < len(clean):
            if clean[i] == "{":
                depth += 1
            elif clean[i] == "}":
                depth -= 1
                if depth == 0:
                    yield section, name, clean[open_idx : i + 1]
                    break
            i += 1


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    total = 0
    failures = []
    for path in argv[1:]:
        with open(path) as f:
            src = f.read()
        for section, name, body in extract_bodies(src):
            total += 1
            # Scan with literals blanked so a "return" inside a string
            # or format text is never mistaken for a real return.
            returns = re.findall(r"\breturn\b([^;]*);", strip_strings(body))
            if not returns:
                failures.append(f"{path}: {name} ({section}): no return statement found")
            for expr in returns:
                if expr.strip() != "0":
                    failures.append(
                        f"{path}: {name} ({section}): forbidden 'return{expr};' — LSM hooks must return 0 only"
                    )
    if total == 0:
        print("check-lsm-returns: FAIL — no SEC(\"lsm...\") programs found (checker or source layout broken)")
        return 1
    if failures:
        print("check-lsm-returns: FAIL")
        for f_ in failures:
            print("  " + f_)
        return 1
    print(f"check-lsm-returns: OK ({total} LSM programs, all returns are 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
