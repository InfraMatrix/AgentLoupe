#!/usr/bin/env python3
"""Export one real-agent run to examples/canned/ for the offline demo.

Keeps only the session whose root ran in --keep-cwd (the loader's
--catalog-only claude-code also adopts any other Claude Code process on
the host; those sessions are dropped), plus the capture_meta record, and
the harness spans file. Every string is sanitized: the work dir becomes
/work, $HOME becomes /u/demo, the user name becomes "demo". Then renders
report.json (forkline-timeline --json) and, if AgentCutter is available,
analysis.md (real model call when META_MODEL_API_KEY is set, else its
--dry-run, labelled as such).

Usage:
  scripts/make_canned.py --capture OUT/capture.jsonl --spans OUT/capture.spans.jsonl \\
      --keep-cwd WORK/networkx --work WORK --out examples/canned
"""
import argparse
import getpass
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOME_RE = re.compile(r"/" + "home" + r"/[^/\s\"']+")


def make_sanitizer(work: str):
    home = os.path.expanduser("~")
    user = getpass.getuser()
    pairs = sorted({(work.rstrip("/"), "/work"), (home, "/u/demo")}, key=lambda p: -len(p[0]))

    def clean(s: str) -> str:
        for old, new in pairs:
            if old and old != "/":
                s = s.replace(old, new)
        s = HOME_RE.sub("/u/demo", s)
        if user and len(user) >= 3:
            s = s.replace(user, "demo")
        return s

    def walk(v):
        if isinstance(v, str):
            return clean(v)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {clean(k): walk(x) for k, x in v.items()}
        return v

    return walk


def cwd_matches(cwd: str, want: str) -> bool:
    """LSM-mode exec cwd comes from a bounded dentry walk that can miss a
    mount prefix (e.g. /tmp on tmpfs shows as /forkline-real-agent/...),
    so accept a cwd that is a suffix of the wanted path too."""
    cwd, want = cwd.rstrip("/"), want.rstrip("/")
    return bool(cwd) and (cwd == want or cwd.startswith(want + "/") or want.endswith(cwd))


def pick_session(capture: Path, keep_cwd: str) -> int:
    roots = {}
    for line in capture.open(encoding="utf-8"):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        sid = ev.get("session_id")
        if ev.get("type") == "session_start" and sid not in roots:
            roots[sid] = ev.get("pid")
        if (ev.get("type") == "exec" and roots.get(sid) == ev.get("pid")
                and cwd_matches(ev.get("cwd") or "", keep_cwd)):
            return sid
    sys.exit(f"make_canned: no session whose root exec'd in {keep_cwd}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", type=Path, required=True)
    ap.add_argument("--spans", type=Path, required=True)
    ap.add_argument("--keep-cwd", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", type=Path, default=ROOT / "examples" / "canned")
    ap.add_argument("--timeline", type=Path, default=ROOT / "forkline-timeline")
    ap.add_argument("--agentcutter", type=Path, default=ROOT.parent / "AgentCutter")
    args = ap.parse_args()

    walk = make_sanitizer(args.work)
    sid = pick_session(args.capture, args.keep_cwd)
    # Also keep nested sessions (parent_session_id chain), e.g. Claude
    # Code re-executing its own binary as rg.
    keep = {sid}
    parents = {}
    for line in args.capture.open(encoding="utf-8"):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "session_start" and ev.get("parent_session_id"):
            parents[ev["session_id"]] = ev["parent_session_id"]
    changed = True
    while changed:
        changed = False
        for child, par in parents.items():
            if par in keep and child not in keep:
                keep.add(child)
                changed = True
    args.out.mkdir(parents=True, exist_ok=True)
    cap_out = args.out / "capture.jsonl"
    spans_out = args.out / "capture.spans.jsonl"
    kept = 0
    with cap_out.open("w", encoding="utf-8") as w:
        for line in args.capture.open(encoding="utf-8"):
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "capture_meta" or ev.get("session_id") in keep:
                w.write(json.dumps(walk(ev), separators=(",", ":")) + "\n")
                kept += 1
    with spans_out.open("w", encoding="utf-8") as w:
        for line in args.spans.open(encoding="utf-8"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            w.write(json.dumps(walk(rec), separators=(",", ":")) + "\n")
    print(f"make_canned: sessions {sorted(keep)}: {kept} events -> {cap_out}")

    rep = subprocess.run([str(args.timeline), "--json", str(cap_out)],
                         check=True, capture_output=True, text=True).stdout
    (args.out / "report.json").write_text(rep, encoding="utf-8")

    cutter = args.agentcutter / ".venv" / "bin" / "agentcutter"
    analysis = args.out / "analysis.md"
    if cutter.exists():
        # Relative names, run from the output dir: no absolute paths
        # end up in the analysis text.
        cmd = [str(cutter), "analyze", cap_out.name, "--binary", str(args.timeline.resolve()),
               "--report", "analysis.report.json", "--output", analysis.name]
        if not os.environ.get("META_MODEL_API_KEY"):
            cmd.append("--dry-run")
        subprocess.run(cmd, check=True, cwd=args.out)
    else:
        print(f"make_canned: {cutter} not found; skipping analysis.md")

    for f in args.out.iterdir():
        data = f.read_bytes()
        if b"/" + b"home" + b"/" in data:
            sys.exit(f"make_canned: {f} still contains a home path; refusing")
    print(f"make_canned: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
