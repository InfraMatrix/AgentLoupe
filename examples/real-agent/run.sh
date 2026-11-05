#!/usr/bin/env bash
# Real-agent demo: Claude Code fixes an injected NetworkX bug while
# AgentLoupe watches from the kernel and the AgentLoupe hook records
# every tool call. Produces a capture + harness spans file whose tool
# spans are named (Bash/Read/Edit/...) and carry per-call resources.
#
#   bash examples/real-agent/run.sh            # capture + render
#   SAVE_CANNED=1 bash examples/real-agent/run.sh   # also refresh examples/canned/
#
# Run from a real terminal, NOT from inside another Claude Code session:
# sudo needs the TTY, and a claude started under an already-tracked
# Claude Code process would be folded into that process's session.
#
# What it does:
#   1. clones NetworkX at a pinned commit (networkx-3.5) into $WORK,
#   2. injects a one-line bug in networkx/algorithms/shortest_paths/
#      weighted.py (`<` -> `<=` in Dijkstra's relaxation: equal-length
#      paths stop being recorded as predecessors; 4 tests fail),
#   3. installs the AgentLoupe hook in $WORK/networkx/.claude/settings.json,
#   4. runs the loader (sudo) with --catalog-only claude-code,
#   5. runs `claude -p` with a prompt to set up a venv, fix the failing
#      test without touching tests, and run the full suite,
#   6. stops the loader and renders scorecard, tool spans, and timeline.
#
# Needs: Linux >= 5.8 with BTF, go, clang, python3 >= 3.11, git, sudo,
# network access (clone + pip), and an authenticated `claude` CLI.
# The agent runs with --permission-mode acceptEdits and only the tools in
# ALLOWED_TOOLS, inside the scratch clone.
#
# Overrides: WORK (default /tmp/agentloupe-real-agent), MAX_RUNTIME (20m),
# CLAUDE_BIN (claude), MAX_BUDGET_USD (5), FILE_RW=1 (also per-call
# file_read/file_write events: much larger capture), SAVE_CANNED=1.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

NX_REPO="https://github.com/networkx/networkx"
NX_COMMIT="4fa222d2fb157e1b7f8c753c9f92e5907d1ddeb4" # tag networkx-3.5
BUG_FILE="networkx/algorithms/shortest_paths/weighted.py"
BUG_FROM="            elif u not in seen or vu_dist < seen[u]:"
BUG_TO="            elif u not in seen or vu_dist <= seen[u]:"

WORK="${WORK:-/tmp/agentloupe-real-agent}"
OUT="$WORK/out"
CAPTURE="$OUT/capture.jsonl"
SPANS="$OUT/capture.spans.jsonl" # <capture>.spans.jsonl: auto-detected
LOADER_LOG="$OUT/loader.log"
MAX_RUNTIME="${MAX_RUNTIME:-20m}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
MAX_BUDGET_USD="${MAX_BUDGET_USD:-5}"
ALLOWED_TOOLS="Bash Read Edit Write Grep Glob"
PROMPT="This is a checkout of NetworkX. Something in networkx/algorithms/shortest_paths is broken and some tests fail. \
Create a virtualenv in .venv, install this package into it in editable mode together with pytest, \
find the failing tests under networkx/algorithms/shortest_paths, and fix the bug in the library code (do not modify any tests). \
Then run the full test suite with '.venv/bin/python -m pytest -q networkx' and report the final pass/fail counts."

say()  { printf '\n== %s ==\n' "$*"; }
info() { printf 'real-agent: %s\n' "$*"; }
die()  { printf 'real-agent: ERROR: %s\n' "$*" >&2; exit 1; }

say "Checking prerequisites"
[ "$(uname -s)" = "Linux" ] || die "Linux only"
for tool in go clang python3 git sudo "$CLAUDE_BIN"; do
  command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "python3 >= 3.11 required (NetworkX 3.5)"
[ -e /sys/kernel/btf/vmlinux ] || die "no kernel BTF"
if [ -n "${CLAUDECODE:-}" ]; then
  die "running inside a Claude Code session (CLAUDECODE is set): run from a plain terminal"
fi
sudo -v || die "sudo authentication failed"

say "Building (as your user)"
make build
go build -o loupe-timeline ./cmd/loupe-timeline
go build -o loupe-scorecard ./cmd/loupe-scorecard

say "Preparing NetworkX @ ${NX_COMMIT:0:12} in $WORK"
rm -rf "$WORK"
mkdir -p "$OUT"
git init -q "$WORK/networkx"
git -C "$WORK/networkx" fetch -q --depth 1 "$NX_REPO" "$NX_COMMIT"
git -C "$WORK/networkx" checkout -q FETCH_HEAD
python3 - "$WORK/networkx/$BUG_FILE" "$BUG_FROM" "$BUG_TO" <<'PY'
import sys
path, old, new = sys.argv[1:4]
src = open(path, encoding="utf-8").read()
n = src.count(old + "\n")
if n != 1:
    sys.exit(f"bug injection: expected exactly 1 match, found {n}")
open(path, "w", encoding="utf-8").write(src.replace(old + "\n", new + "\n"))
PY
git -C "$WORK/networkx" diff --stat
mkdir -p "$WORK/networkx/.claude"
HOOK="python3 $ROOT/hooks/agentloupe_hook.py"
python3 - "$WORK/networkx/.claude/settings.json" "$HOOK" <<'PY'
import json, sys
path, cmd = sys.argv[1:3]
entry = [{"matcher": "*", "hooks": [{"type": "command", "command": cmd}]}]
json.dump({"hooks": {"PreToolUse": entry, "PostToolUse": entry, "PostToolUseFailure": entry}},
          open(path, "w"), indent=2)
PY
info "hook installed: $WORK/networkx/.claude/settings.json -> $SPANS"

say "Starting loader ($MAX_RUNTIME max, log: $LOADER_LOG)"
RW_FLAG=()
[ "${FILE_RW:-0}" = "1" ] && RW_FLAG=(--enable-file-rw-events)
sudo ./agentloupe \
  --catalog-only claude-code \
  --bpf-object bpf/agentloupe.bpf.o \
  --enable-syscall-summary \
  --enable-io-accounting \
  --enable-net-send-events \
  --drop-path-prefix /proc/ \
  --orphan-timeout 30s \
  --output "$CAPTURE" \
  --max-runtime "$MAX_RUNTIME" \
  "${RW_FLAG[@]}" >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!
stop_loader() {
  if kill -0 "$LOADER_PID" 2>/dev/null; then
    sudo kill -INT "$LOADER_PID" 2>/dev/null || true
    wait "$LOADER_PID" 2>/dev/null || true
  fi
}
trap stop_loader EXIT
for _ in $(seq 1 100); do
  grep -q "running (dev mode" "$LOADER_LOG" 2>/dev/null && break
  kill -0 "$LOADER_PID" 2>/dev/null || { tail -20 "$LOADER_LOG"; die "loader exited during startup"; }
  sleep 0.2
done
grep -q "running (dev mode" "$LOADER_LOG" || die "loader did not start (see $LOADER_LOG)"

say "Running Claude Code (this takes a few minutes)"
START=$(date +%s)
set +e
(
  cd "$WORK/networkx"
  AGENTLOUPE_SPANS="$SPANS" "$CLAUDE_BIN" -p "$PROMPT" \
    --permission-mode acceptEdits \
    --allowedTools "$ALLOWED_TOOLS" \
    --max-budget-usd "$MAX_BUDGET_USD" \
    --output-format json </dev/null >"$OUT/claude-result.json" 2>"$OUT/claude-stderr.log"
)
CLAUDE_RC=$?
set -e
info "claude exited $CLAUDE_RC after $(( $(date +%s) - START ))s"
sleep 3 # let exit/session_end events drain
stop_loader
trap - EXIT
sudo chown "$(id -u):$(id -g)" "$CAPTURE" "$LOADER_LOG"

say "Capture checks"
[ -s "$CAPTURE" ] || die "empty capture (see $LOADER_LOG)"
[ -s "$SPANS" ] || die "no hook records in $SPANS (hook not run? see $WORK/networkx/.claude/settings.json)"
info "events: $(wc -l <"$CAPTURE")  hook records: $(wc -l <"$SPANS")  capture size: $(du -h "$CAPTURE" | cut -f1)"
grep -Eq 'ringbuf_drops=[1-9]' "$LOADER_LOG" && printf 'real-agent: WARNING: ring-buffer drops (see %s)\n' "$LOADER_LOG" >&2
git -C "$WORK/networkx" diff -- networkx | head -20

say "Scorecard"
./loupe-scorecard "$CAPTURE"
say "Tool spans"
./loupe-timeline --tool-spans "$CAPTURE" | tee "$OUT/tool-spans.txt"
./loupe-timeline --html "$OUT/timeline.html" "$CAPTURE" >/dev/null

if [ "${SAVE_CANNED:-0}" = "1" ]; then
  say "Refreshing examples/canned/ (sanitized)"
  python3 scripts/make_canned.py --capture "$CAPTURE" --spans "$SPANS" \
    --keep-cwd "$WORK/networkx" --work "$WORK" --out examples/canned
fi
say "Done: outputs in $OUT"
