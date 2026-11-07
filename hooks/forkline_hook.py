#!/usr/bin/env python3
"""Forkline harness hook for Claude Code: one JSONL line per tool event.

Install as a PreToolUse, PostToolUse and PostToolUseFailure command hook
(see hooks/claude-settings.example.json). Claude Code pipes the hook
payload to stdin; this script appends one line to the spans file and
exits 0 without printing anything, so it can never block, deny, or alter
a tool call. Standard library only.

Spans file: $FORKLINE_SPANS, else
$FORKLINE_CAPTURE_DIR/spans.jsonl, else /tmp/forkline/spans.jsonl.
Name it <capture>.spans.jsonl next to the capture and forkline-timeline
picks it up automatically.

Record fields:
  event        "pre" | "post" | "post_failure"
  tool_name    Claude Code tool name (Bash, Read, Edit, Grep, ...)
  tool_use_id  pairs pre with post
  session_id   Claude Code's session id (not Forkline's)
  ts_ns        CLOCK_REALTIME, ns since the Unix epoch
  mono_ns      CLOCK_MONOTONIC, ns — the clock the kernel probes use
               (bpf_ktime_get_ns); with the capture's capture_meta
               record this maps to capture time exactly
  pid, ppid    this hook process and its parent
  ancestors    pids from ppid upward (up to 8), so the reducer can find
               the agent process even through a wrapper shell
  input        a bounded summary of tool_input: known scalar keys only
               (command, file_path, pattern, url, ...), each truncated;
               never file contents or edit payloads
  duration_ms  (post) Claude Code's own tool execution time
  error, interrupted  (post_failure)
"""

import json
import os
import sys
import time

MAX_STR = 300
# Keys whose values are short, identifying, and safe to keep. Anything
# else (content, old_string, new_string, edits, ...) is reduced to a
# length so the record never carries file contents.
KEEP_KEYS = (
    "command", "description", "file_path", "path", "pattern", "glob",
    "url", "query", "notebook_path", "subagent_type", "output_mode",
    "type", "offset", "limit", "timeout", "run_in_background",
    "replace_all", "head_limit", "-n", "-i", "multiline",
)


def _trunc(v):
    if isinstance(v, str) and len(v) > MAX_STR:
        return v[:MAX_STR] + "…"
    return v


def summarize_input(tool_input):
    if not isinstance(tool_input, dict):
        return {}
    out = {}
    sized = {}
    for k, v in tool_input.items():
        if k in KEEP_KEYS and (v is None or isinstance(v, (str, int, float, bool))):
            out[k] = _trunc(v)
        elif isinstance(v, str):
            sized[k] = len(v)
        elif isinstance(v, (list, dict)):
            sized[k] = len(v)
    if sized:
        out["_sizes"] = sized  # e.g. {"content": 5321}: lengths only
    return out


def ancestors(start_pid, limit=8):
    chain = []
    pid = start_pid
    for _ in range(limit):
        if pid <= 1:
            break
        chain.append(pid)
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                stat = f.read().decode("utf-8", "replace")
            # comm may contain spaces/parens: ppid follows the last ')'.
            pid = int(stat[stat.rindex(")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return chain


def spans_path():
    p = os.environ.get("FORKLINE_SPANS")
    if p:
        return p
    d = os.environ.get("FORKLINE_CAPTURE_DIR", "/tmp/forkline")
    return os.path.join(d, "spans.jsonl")


EVENTS = {"PreToolUse": "pre", "PostToolUse": "post", "PostToolUseFailure": "post_failure"}


def build_record(payload, argv_event=None):
    hook_event = payload.get("hook_event_name") or argv_event or ""
    rec = {
        "event": EVENTS.get(hook_event, hook_event.lower() or "unknown"),
        "tool_name": payload.get("tool_name", ""),
        "tool_use_id": payload.get("tool_use_id", ""),
        "session_id": payload.get("session_id", ""),
        "ts_ns": time.time_ns(),
        "mono_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "ancestors": ancestors(os.getppid()),
        "input": summarize_input(payload.get("tool_input")),
    }
    if isinstance(payload.get("duration_ms"), (int, float)):
        rec["duration_ms"] = int(payload["duration_ms"])
    if rec["event"] == "post_failure":
        rec["error"] = _trunc(str(payload.get("error", "")))
        rec["interrupted"] = bool(payload.get("is_interrupt", False))
    return rec


def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        rec = build_record(payload, sys.argv[1] if len(sys.argv) > 1 else None)
        path = spans_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        line = (json.dumps(rec, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line)  # one O_APPEND write per record
        finally:
            os.close(fd)
    except Exception:  # never break the agent over observability
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
