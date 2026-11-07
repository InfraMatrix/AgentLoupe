#!/usr/bin/env bash
# Smoke test for exec-time scoping and the startup journal (ABI v9), on the
# real kernel, in both exec-hook modes (LSM and tracepoint fallback).
#
#   bash scripts/smoke-startup.sh            # both modes
#   bash scripts/smoke-startup.sh lsm        # or: tp
#
# Run from a plain terminal as your user (sudo prompts once). Builds first.
# Everything it starts lives in a temp dir and is killed at the end.
#
# What it checks, per mode:
#   1. the BPF object loads and every program passes the verifier
#   2. --attach-comm scopes a process at exec (not only via /proc scans)
#   3. --attach-exe scopes a glob-matched binary at exec
#   4. a binary added to the glob's directory after start is picked up
#   5. a non-matching process is NOT captured
#   6. an agent running before the loader starts is adopted, and the
#      grandchildren it creates by double-forking during startup land in
#      its session (startup journal + re-scan), never in another session
#   7. exec overhead with the loader running (informational)
#   8. nothing is left loaded in the kernel afterwards
set -euo pipefail
cd "$(dirname "$0")/.."

MODES=("${1:-both}")
[ "${MODES[0]}" = both ] && MODES=(lsm tp)

say()  { printf '\n== %s ==\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '        %s\n' "$*"; }
FAILS=0

[ "$(uname -s)" = Linux ] || { echo "Linux only"; exit 1; }
[ -z "${CLAUDECODE:-}" ] || { echo "run from a plain terminal, not inside Claude Code"; exit 1; }

say "Building (as your user)"
make build >/dev/null
sudo -v

TMP="$(mktemp -d /tmp/forkline-smoke.XXXXXX)"
LOADER_PID=""
cleanup() {
  [ -n "$LOADER_PID" ] && sudo kill -INT "$LOADER_PID" 2>/dev/null || true
  pkill -f "$TMP/" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/bin" "$TMP/exe"
# Test processes are renamed copies of perl: a plain ELF binary, so a copy
# keeps its own name as both comm and exe (coreutils may be a multi-call
# binary that refuses to run under another name, and `#!/usr/bin/env`
# scripts take the interpreter's name).
PERL="$(command -v perl)" || { echo "perl is required"; exit 1; }
cp "$PERL" "$TMP/bin/lsmoke-comm"     # matched by --attach-comm
cp "$PERL" "$TMP/bin/lsmoke-other"    # matches nothing (negative control)
cp "$PERL" "$TMP/bin/lsmoke-gchild"   # what the agent's grandchildren exec
cp "$PERL" "$TMP/bin/lsmoke-agent"    # the fake agent (--attach-comm)
cp "$PERL" "$TMP/exe/lsmoke-exe-1"    # matched by --attach-exe glob
NAP=(-e 'select(undef, undef, undef, 0.2)')
# The fake agent double-forks continuously: the child renames itself (so it
# is not an agent by name), forks a grandchild that execs lsmoke-gchild, and
# exits. Some double forks always fall inside the loader's startup window.
cat >"$TMP/agent.pl" <<'PL'
my ($gchild, $seconds) = @ARGV;
my $end = time + $seconds;
while (time < $end) {
    my $pid = fork() // die "fork: $!";
    if ($pid == 0) {
        $0 = "lsmoke-mid";
        if (fork() == 0) { exec($gchild, "-e", "sleep 4") or exit 1 }
        exit 0;
    }
    waitpid($pid, 0);
    select(undef, undef, undef, 0.03);
}
PL

exec_loop() { # seconds for N execs of a tiny binary
  local n=$1 t0 t1
  t0=$(date +%s%N)
  for ((i = 0; i < n; i++)); do /bin/true; done
  t1=$(date +%s%N)
  echo $(( (t1 - t0) / 1000000 ))
}

say "Baseline: 2000 execs without the loader"
BASE_MS=$(exec_loop 2000)
info "${BASE_MS} ms"

for MODE in "${MODES[@]}"; do
  say "Mode: $MODE"
  CAP="$TMP/capture-$MODE.jsonl"
  LOG="$TMP/loader-$MODE.log"
  TP=()
  [ "$MODE" = tp ] && TP=(--force-tracepoint-mode)
  rm -f "$TMP/exe/lsmoke-exe-2" # each mode must add it after start itself

  # The agent starts BEFORE the loader, so only adoption can find it.
  "$TMP/bin/lsmoke-agent" "$TMP/agent.pl" "$TMP/bin/lsmoke-gchild" 8 &
  AGENT_PID=$!
  sleep 0.5

  sudo ./forkline \
    --bpf-object bpf/forkline.bpf.o \
    --config "$TMP/no-config.yaml" \
    --attach-comm lsmoke-comm --attach-comm lsmoke-agent \
    --attach-exe "$TMP/exe/lsmoke-exe-*" \
    --output "$CAP" --max-runtime 40s "${TP[@]}" >"$LOG" 2>&1 &
  LOADER_PID=$!
  for _ in $(seq 1 150); do
    grep -q "running (dev mode" "$LOG" 2>/dev/null && break
    kill -0 "$LOADER_PID" 2>/dev/null || break
    sleep 0.2
  done
  if ! grep -q "running (dev mode" "$LOG"; then
    fail "loader did not start (verifier/load error?) — log:"
    sed 's/^/          /' "$LOG" | tail -25
    kill "$AGENT_PID" 2>/dev/null || true
    LOADER_PID=""
    continue
  fi
  pass "BPF object loaded, hooks attached ($(grep -o 'attached [0-9]* hooks' "$LOG"))"

  "$TMP/bin/lsmoke-comm" "${NAP[@]}"
  "$TMP/exe/lsmoke-exe-1" "${NAP[@]}"
  "$TMP/bin/lsmoke-other" "${NAP[@]}"
  cp "$PERL" "$TMP/exe/lsmoke-exe-2"    # added after start
  sleep 1.5                              # watcher debounce + rule reload
  "$TMP/exe/lsmoke-exe-2" "${NAP[@]}"

  RUN_MS=$(exec_loop 2000)
  wait "$AGENT_PID" 2>/dev/null || true
  sleep 1
  sudo kill -INT "$LOADER_PID" 2>/dev/null || true
  wait "$LOADER_PID" 2>/dev/null || true
  LOADER_PID=""
  sudo chown "$(id -u):$(id -g)" "$CAP" "$LOG"

  if ! python3 -I - "$CAP" "$LOG" "$AGENT_PID" "$TMP" <<'PY'
import json, re, sys
cap, log, agent_pid, tmp = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
recs = [json.loads(l) for l in open(cap) if l.strip()]
logtext = open(log).read()
fails = 0
def ok(cond, msg, detail=""):
    global fails
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if detail:
        print("        " + detail)
    fails += 0 if cond else 1

execs = [r for r in recs if r.get("type") == "exec"]
def execd(name):
    return [r for r in execs if str(r.get("filename", "")).endswith("/" + name)]

m = re.search(r"rules: .* (\d+) process names", logtext)
ok(m and m.group(1) == "2", "both --attach-comm names loaded into the kernel", m.group(0) if m else "no rules line")
ok(bool(execd("lsmoke-comm")), "--attach-comm process scoped at exec")
ok(bool(execd("lsmoke-exe-1")), "--attach-exe glob match scoped at exec")
ok(bool(execd("lsmoke-exe-2")), "binary added to the glob directory later is scoped")
ok(not execd("lsmoke-other"), "non-matching process not captured")

agent_sids = {r["session_id"] for r in recs if r.get("pid") == agent_pid and r.get("session_id")}
ok(len(agent_sids) == 1, "pre-existing agent adopted into one session", f"sessions: {sorted(agent_sids)}")
g = execd("lsmoke-gchild")
wrong = [r for r in g if r.get("session_id") not in agent_sids]
ok(bool(g) and not wrong, "double-forked grandchildren land in the agent's session",
   f"{len(g)} grandchild execs captured, {len(wrong)} in another session")
j = re.search(r"startup journal: (\d+) records, (\d+) kept for adopted sessions, (\d+) discarded, (\d+) processes joined", logtext)
ok(bool(j), "startup journal ran", j.group(0) if j else "no 'startup journal:' line in the log")
if j and int(j.group(2)) == 0:
    print("        note: no double fork fell inside the window this run; rerun to exercise the journal path")
ok("abi version" not in logtext and "decode record" not in logtext, "no decode/ABI errors")
sys.exit(1 if fails else 0)
PY
  then
    FAILS=$((FAILS + 1))
  fi
  info "exec overhead: 2000 execs ${RUN_MS} ms with the loader vs ${BASE_MS} ms without"

  if command -v bpftool >/dev/null; then
    # Sleepable LSM programs are freed after an RCU tasks-trace grace
    # period, not at close: poll like the integration test does.
    left=1
    for _ in $(seq 1 50); do
      if ! sudo bpftool prog show 2>/dev/null | grep -qE 'handle_(fork|exec|bprm)'; then
        left=0
        break
      fi
      sleep 0.2
    done
    if [ "$left" = 0 ]; then
      pass "nothing left loaded in the kernel"
    else
      fail "BPF programs still loaded 10s after the loader exited"
    fi
  fi
  info "logs: $LOG (kept until the script exits; copy it if needed)"
done

say "Result"
if [ "$FAILS" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "$FAILS check group(s) FAILED"
  exit 1
fi
