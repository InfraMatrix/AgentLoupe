#!/usr/bin/env bash
# AgentLoupe one-command demo.
#
# Builds everything, checks prerequisites, runs the loader against
# configs/loupe-demo.yaml (Claude Code + the loupe_demo python workload),
# runs the demo workload twice, then renders the scorecard, the text
# timeline, and an HTML timeline. If a Claude Code session is already
# running on this host it is adopted automatically and shows up in the
# capture too.
#
# Needs: Linux kernel >= 5.8 (5.11+ for LSM mode), kernel BTF, go,
# clang, python3, sudo (you will be prompted once). Nothing is pinned;
# the loader detaches everything on exit.
#
# Overrides: CAPTURE=..., LOADER_LOG=..., MAX_RUNTIME=90s, FORCE_TP=1
# (FORCE_TP rehearses the tracepoint-fallback probe set).
set -euo pipefail
cd "$(dirname "$0")/.."

CAPTURE="${CAPTURE:-demo-capture.jsonl}"
LOADER_LOG="${LOADER_LOG:-demo-loader.log}"
TIMELINE_TXT="${TIMELINE_TXT:-demo-timeline.txt}"
TIMELINE_HTML="${TIMELINE_HTML:-timeline-demo.html}"
MAX_RUNTIME="${MAX_RUNTIME:-45s}"

say()  { printf '\n== %s ==\n' "$*"; }
info() { printf 'demo: %s\n' "$*"; }
die()  { printf 'demo: ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- prereqs
say "Checking prerequisites"
[ "$(uname -s)" = "Linux" ] || die "AgentLoupe is Linux-only"
for tool in go clang python3 sudo; do
  command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool (see README 'Required toolchain')"
done

kver="$(uname -r)"
kmaj="${kver%%.*}"; krest="${kver#*.}"; kmin="${krest%%.*}"
info "kernel $kver"
if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -lt 8 ]; }; then
  die "kernel >= 5.8 required (found $kver)"
fi
[ -e /sys/kernel/btf/vmlinux ] || die "no kernel BTF (/sys/kernel/btf/vmlinux) — the CO-RE object cannot load"

MODE="tracepoint fallback"
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  MODE="LSM"
fi
if [ "${FORCE_TP:-0}" = "1" ]; then
  MODE="tracepoint fallback (forced)"
fi
info "probe mode on this host: $MODE"
if [ "$MODE" = "tracepoint fallback" ]; then
  info "note: no 'bpf' in /sys/kernel/security/lsm — running the (less exercised) fallback path"
fi

sudo -v || die "sudo authentication failed"

# ------------------------------------------------------------------ build
say "Building (as your user; only the loader run uses sudo)"
make build
go build -o loupe-timeline ./cmd/loupe-timeline
go build -o loupe-scorecard ./cmd/loupe-scorecard

# ----------------------------------------------------------------- loader
say "Starting loader ($MAX_RUNTIME window, log: $LOADER_LOG)"
FORCE_FLAG=()
if [ "${FORCE_TP:-0}" = "1" ]; then
  FORCE_FLAG=(--force-tracepoint-mode)
fi
sudo ./agentloupe \
  --config configs/loupe-demo.yaml \
  --bpf-object bpf/agentloupe.bpf.o \
  --enable-syscall-summary \
  --output "$CAPTURE" \
  --max-runtime "$MAX_RUNTIME" \
  "${FORCE_FLAG[@]}" >"$LOADER_LOG" 2>&1 &
LOADER_PID=$!
cleanup() {
  if kill -0 "$LOADER_PID" 2>/dev/null; then
    sudo kill -INT "$LOADER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

for _ in $(seq 1 50); do
  grep -q "running (dev mode" "$LOADER_LOG" 2>/dev/null && break
  kill -0 "$LOADER_PID" 2>/dev/null || { tail -20 "$LOADER_LOG"; die "loader exited during startup (see $LOADER_LOG)"; }
  sleep 0.2
done
grep -q "running (dev mode" "$LOADER_LOG" || { tail -20 "$LOADER_LOG"; die "loader did not reach running state (see $LOADER_LOG)"; }
grep "feature probe:" "$LOADER_LOG" | head -5 || true
if grep -q "adoption scan: adopted" "$LOADER_LOG"; then
  info "adopted an already-running agent (e.g. Claude Code) — it will appear in the capture"
fi

# --------------------------------------------------------------- workload
say "Running demo workload twice"
python3 tmp/loupe_demo.py
python3 tmp/loupe_demo.py

say "Waiting for the loader window to close"
wait "$LOADER_PID" 2>/dev/null || true
trap - EXIT

# ----------------------------------------------------------------- checks
say "Capture checks"
[ -s "$CAPTURE" ] || die "capture $CAPTURE is empty — no sessions matched (see $LOADER_LOG; the loader warns after 30s if nothing matched)"
info "events: $(wc -l < "$CAPTURE")  syscall_summary: $(grep -c '"type":"syscall_summary"' "$CAPTURE" || true)"
if grep -Eq 'ringbuf_drops=[1-9]' "$LOADER_LOG"; then
  printf 'demo: WARNING: nonzero ringbuf drops in %s\n' "$LOADER_LOG" >&2
else
  info "ringbuf_drops=0 throughout"
fi
grep '"type":"session_end"' "$CAPTURE" | grep -o '"reason":"[a-z_]*"' | sort | uniq -c || true

# ---------------------------------------------------------------- renders
say "Scorecard"
./loupe-scorecard "$CAPTURE"

say "Timeline (full text in $TIMELINE_TXT)"
./loupe-timeline "$CAPTURE" > "$TIMELINE_TXT"
head -40 "$TIMELINE_TXT"

./loupe-timeline --html "$TIMELINE_HTML" "$CAPTURE" >/dev/null
info "HTML timeline: $TIMELINE_HTML (open in any browser, works offline)"
info "loader log:     $LOADER_LOG"
info "raw capture:    $CAPTURE"
say "Demo complete"
