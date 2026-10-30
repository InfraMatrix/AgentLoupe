# AgentLoupe

An agent observability tool: eBPF-based, observe-only visibility into what
AI agents do on a Linux host — process execution, file activity, and
network connections, scoped to agent processes only. No enforcement, no
kernel modules, nothing pinned.

## Status

MVP in development. The eBPF programs and dev-mode Go loader are written
and have been load-tested on a live kernel in LSM mode — see "Tested on"
below for exactly what has and has not been exercised. See "Safety"
before running anywhere that matters.

## Design summary

- **Scoping in the kernel.** Tools are matched at exec by binary
  `(dev, inode)` (interpreters are provisional until userspace confirms
  argv), services by cgroup v2 ID. Children inherit the session at fork.
  Untracked processes cost at most two map lookups per probe.
- **Session state lives in the kernel** (`sessions` map:
  PROVISIONAL / CONFIRMED / REJECTED). Rejecting or timing out a
  provisional session is one userspace map write; the fork hook never
  propagates REJECTED sessions.
- **Variable-length events**: a 72-byte `event_hdr` plus one fixed-size
  payload struct per event type over a single ring buffer, with per-type
  drop counters and separate map-full ("lost visibility") counters.
- **Paths are resolved in the kernel**: `bpf_d_path` under BPF LSM,
  bounded dentry walk on the tracepoint fallback; every path records how
  it was obtained (`d_path` / `dentry_walk` / `raw_arg`).
- **File byte counts** are keyed by `struct file *` (survives fork/dup),
  accumulated via fexit on `vfs_read/vfs_write{,v}`, and reported once on
  final release (`file_free_security`). io_uring may bypass `vfs_read` —
  documented gap. This accounting is **opt-in** (benchmark first).

Minimum kernel: 5.8 floor, **5.11+ for full (LSM) mode**; see
`bpf/agentloupe.h`. The loader probes features per hook at startup and
prints which hooks attached and which fallbacks are active.

## Required toolchain

| Tool | Needed for | Notes |
|---|---|---|
| Go 1.23+ | `make build`, `make test`, `make integration` | Version matches `go.mod`. Only the standard toolchain; modules are fetched from the Go module proxy on first build. |
| clang / LLVM (with BPF backend) | `make bpf`, `make check-header` | `clang --print-targets` must list `bpf`. |
| libbpf headers | `make bpf` | Provides `<bpf/bpf_helpers.h>`, `<bpf/bpf_tracing.h>`, etc. (Debian/Ubuntu: `libbpf-dev`). |
| bpftool | only `make vmlinux.h` and post-run leak checks | Not needed for a normal build: `bpf/vmlinux.h` is committed. Regenerate it only on/for the target kernel. |
| python3 | `make check` | Runs `scripts/check_lsm_returns.py`. |
| root + kernel 5.8+ (5.11+ for LSM mode) | running the loader, `sudo make integration` | See "Design summary" for the per-feature floor. CI needs none of this. |

Debian/Ubuntu install:

```sh
sudo apt-get install -y clang libbpf-dev bpftool golang python3
```

## Dev-mode quickstart (kernel 5.11+, BTF required)

On a host without `bpf` in `lsm=` (check `/sys/kernel/security/lsm`) the
loader automatically runs in tracepoint-fallback mode.

```sh
make check            # header ABI asserts + LSM return-0 safety check
make test             # unit tests: no kernel, no root
make build            # make bpf + go build -o agentloupe ./cmd/agentloupe
# Optional, only on the target kernel: make vmlinux.h

# Default probe set: process, file-open, network. Nothing is pinned;
# SIGINT/SIGTERM or --max-runtime detaches everything.
sudo ./agentloupe \
  --config configs/agents.example.yaml \
  --bpf-object bpf/agentloupe.bpf.o \
  --max-runtime 60s
```

Feature probe output (stderr) reports kernel/BTF/LSM status, the binary
identity self-test, every attached hook, and active fallbacks. JSONL
events go to stdout (or `--output file`).

Opt-in probes (off by default):

```sh
--enable-file-mutations    # unlink / rename / chmod events
--enable-io-accounting     # vfs_* byte counts + file_close (make bench-io first)
--enable-syscall-summary   # per-(session, process, syscall) counts, dumped by name
                           # in the stats log (top 25 per session) and, with
                           # --syscall-interval, as syscall_summary JSONL events
```

### Try the demo (one command)

```sh
make demo          # or: bash scripts/demo.sh
```

The script checks prerequisites (Linux ≥ 5.8, kernel BTF, toolchain,
sudo), builds everything as your user, then runs the loader for 45s
against `configs/loupe-demo.yaml` (the `examples/loupe_demo.py` python
workload) plus `--catalog-only claude-code` (the built-in catalog
resolves your per-user install and is skipped entirely on hosts
without Claude Code), runs the demo workload twice, and renders
the scorecard, the text timeline, and `timeline-demo.html`. It prompts
for sudo once; only the loader run is privileged. If a Claude Code
session is already running on the host it is adopted automatically and
appears in the capture alongside the demo sessions. Outputs:
`demo-capture.jsonl` (raw events), `demo-loader.log` (feature probe +
drop counters), `demo-timeline.txt`. Set `FORCE_TP=1` to rehearse the
tracepoint-fallback probe set on an LSM host (see Troubleshooting).

### Attaching to already-running agents

```sh
# Built-in catalog (Claude Code, Codex, Aider, Gemini CLI, Cursor —
# only entries present on this host are activated):
sudo ./agentloupe --catalog --bpf-object bpf/agentloupe.bpf.o
sudo ./agentloupe --catalog-only claude-code --bpf-object bpf/agentloupe.bpf.o

# Ad-hoc targets (repeatable; existing children are adopted too):
sudo ./agentloupe --attach-pid 1234 --attach-comm claude --attach-exe '/usr/bin/c*' \
  --bpf-object bpf/agentloupe.bpf.o
```

Adoption runs at startup and re-runs every 5s (and after config reloads),
so agents started after Loupe are adopted without a config entry.

### Reducing a capture

```sh
go build -o loupe-scorecard ./cmd/loupe-scorecard
./loupe-scorecard capture.jsonl          # per-session table
./loupe-scorecard --json capture.jsonl   # machine-readable
```

Per-agent timeline and breakdown (process swimlanes, file/network
markers, syscall rate over time):

```sh
go build -o loupe-timeline ./cmd/loupe-timeline
./loupe-timeline capture.jsonl                    # plain-text summary per session
./loupe-timeline --json capture.jsonl             # same breakdown as JSON
./loupe-timeline --html timeline.html capture.jsonl  # one self-contained
                                                  # HTML file (inline CSS/JS,
                                                  # no CDN, works offline):
                                                  # filter by agent/session,
                                                  # zoom/pan, hover details
```

In the HTML view the syscall rate chart is stacked **by category** by
default (process / file / network / memory / sync-wait / signals / time /
other — one name-based mapping in `cmd/loupe-timeline/categories.go`,
applied to both amd64 and arm64 syscall names). Memory and sync/wait are
hidden by default (they are mostly runtime background) with a toggle to
show them, and a drill-down selector re-stacks the chart by the
individual syscalls inside one category. Purple ◆ markers on the
swimlanes mark the first interval in which a session used a syscall it
had never used before. Per-session tables show the category breakdown
with per-syscall drill-down, an always-shown **notable syscalls** list
(execve, connect, bind, listen, accept, unlink/rename/chmod/chown
families, ptrace, setuid/setgid/capset, mount/umount, bpf, kill/tgkill,
module loading — each with first-seen time and count), and **per-program
attribution**: syscalls rolled up to the program that made them (e.g.
"python3 made 90% of the file syscalls"), by mapping each TGID to the
program it exec'd. The text and `--json` outputs carry the same
breakdowns.

`loupe-timeline` streams the capture (it never loads it whole) and
aggregates in Go, so multi-hundred-MB captures stay usable; markers per
lane and the syscall time series are downsampled/bucketed for the HTML
and the page says so when that happens. Captures without
`syscall_summary` events (older captures, or runs without
`--enable-syscall-summary`) still render everything else, with a note
that syscall rates are unavailable.

#### `syscall_summary` events

With `--enable-syscall-summary`, the loader also synthesises
`syscall_summary` events into the JSONL stream. The kernel counts per
(session, TGID, syscall number) — ABI v4 — and userspace turns snapshots
of that map into delta events. One event is emitted every `--syscall-interval`
(default `1s`; `0` disables the periodic emission), plus a final flush
for a session just before its `session_end` and for all live sessions
on shutdown, so per-session deltas sum exactly to the kernel's
cumulative totals. Sessions/intervals with zero activity are skipped.
The existing stderr syscall dump (on `--stats-interval`) is unchanged.

| Field | Meaning |
|---|---|
| `ts` | RFC3339Nano wall-clock timestamp of the emission. |
| `type` | `"syscall_summary"`. |
| `session_id` | Session the counts belong to. |
| `parent_session_id` | Parent session ID (`0` if none/unknown). |
| `agent_name` | Agent rule name for the session. |
| `pid`, `pid_in_ns`, `ppid`, `uid` | Unused for this synthesised event; always `0`. |
| `comm` | Unused; always `""`. |
| `interval_ms` | Milliseconds since the previous `syscall_summary` emission pass (the configured `--syscall-interval` in steady state). |
| `counts` | Object mapping syscall name → count for this interval only (**deltas**, not cumulative). Names come from the amd64/arm64 syscall tables; unknown numbers are `"sys_<nr>"`. |
| `per_process_counts` | Object mapping TGID (decimal string) → syscall name → count, same interval and delta semantics as `counts`. Summing it over TGIDs gives `counts`; it attributes syscalls to the process (and, via exec events, the program) that made them. |

Example:

```json
{"ts":"2026-10-30T16:05:36.915939035Z","type":"syscall_summary","session_id":14067088359163953153,"parent_session_id":0,"agent_name":"claude-code","pid":0,"pid_in_ns":0,"ppid":0,"uid":0,"comm":"","interval_ms":1010,"counts":{"close":1,"epoll_pwait2":5,"fstat":1,"futex":175,"madvise":10,"openat":1,"read":2,"statx":5,"write":2},"per_process_counts":{"5124":{"close":1,"epoll_pwait2":5,"fstat":1,"futex":175,"madvise":10,"openat":1,"read":2,"statx":5,"write":2}}}
```

### Session lifecycle: `root_exit` and orphans

A session is a process tree, not just its root process. When the
agent's root process exits, the loader emits a `root_exit` event
(same identity fields as the root's `exit` event, plus the exit
resource fields below)
and the session stays open while any tracked child processes remain
alive; their file/network/syscall activity keeps being attributed to
the session, and the final `syscall_summary` flush still precedes the
closing `session_end`. `session_end` carries a `reason`:

| `reason` | Meaning |
|---|---|
| `all_exited` | The root and every tracked process in the session have exited. |
| `orphan_timeout` | Tracked processes were still alive when `--orphan-timeout` expired after the root exit. The event lists their TGIDs in `still_running`; later events from them are dropped as stragglers, and the session does not reopen. |

`--orphan-timeout` (default `3m`, `0` = wait indefinitely) bounds how
long a session may outlive its root. `loupe-timeline` and
`loupe-scorecard` report the gap between `root_exit` and `session_end`
(the orphan window), the end reason, and any still-running TGIDs.

#### Per-process CPU and peak memory on `exit` / `root_exit` (ABI v4)

Every `exit` event — and the `root_exit` event that mirrors the root's
exit — carries the exiting process's own resource usage, sampled
in-kernel at `sched_process_exit`, so even short-lived tools that are
gone before any `/proc` sampling could see them have numbers:

| Field | Meaning |
|---|---|
| `cpu_user_ms` | Thread-group user CPU time, milliseconds (floor of the kernel ns total). "Self" only: the group's own threads (already-exited threads folded into `signal->utime` plus the exiting leader's `utime`); reaped children (`cutime`) are excluded — each child reports its own. Threads still alive when the leader exits are not included. |
| `cpu_sys_ms` | Same, for system CPU time (`stime`). |
| `max_rss_kb` | Peak resident set size of the thread group, in KiB (kernel `signal->maxrss`, the `ru_maxrss` unit). `task->mm` is already dropped at this hook, so the kernel-side hiwater folded into `signal->maxrss` by `exit_mm` is the valid source. `0` if the task never had an mm. |

These complement — not replace — the `cpu_user_ms`/`cpu_sys_ms` on
`session_end`, which remain the session **root's** totals sampled from
`/proc` and say nothing about child tools.

Useful loader flags: `--drop-path-prefix /proc/` (repeatable) suppresses
file-event noise (e.g. agents polling their own `/proc/<pid>/stat`);
`session_end` events carry `cpu_user_ms`/`cpu_sys_ms` (session root
process CPU, sampled from `/proc`). Network events cover TCP and UDP;
connects to port 53 are flagged `"dns": true` (no payload parsing).
Paths/argv are captured up to 512 bytes (ABI v4); `comm` remains capped
at 16 chars by the kernel (`TASK_COMM_LEN`) — use exec `filename`/`argv`
to disambiguate. `--force-tracepoint-mode` forces the tracepoint
fallback probe set even when BPF LSM is available, so the fallback
path can be rehearsed on any host.

### Troubleshooting

**Empty capture / no sessions.** Matching failures are silent by
design in the kernel (untracked processes are ignored), so the loader
helps from userspace: if agent rules are configured but no
`session_start` has been emitted after 30s, it logs a `warn: no agent
sessions seen …` line (repeated at most once a minute) instead of
leaving you with an empty file. Usual causes, in order:

1. The agent isn't running yet, or exited before the 5s adoption
   rescan. Start the agent, wait a few seconds, check again.
2. `exec_path` names a symlink or wrapper: the path is resolved and
   matching is by `(dev, inode)` of the binary actually exec'd, so
   point the rule at the real binary (e.g. Claude Code's
   `~/.local/share/claude/versions/<version>`), not a launcher script.
3. An interpreter rule's `argv_contains` doesn't appear in the
   agent's command line (check `/proc/<pid>/cmdline`).
4. The agent runs under a different user/install than the rule
   assumes — prefer `--catalog` (built-in rules) or `--attach-pid`
   to sidestep config matching while diagnosing.

Also check the startup log: the feature probe prints the kernel,
whether `bpf` is in `/sys/kernel/security/lsm`, the binary-identity
self-test result, and exactly which hooks attached. Zero
`ringbuf_drops` and zero map-full counters in the periodic `stats:`
lines mean nothing was lost; nonzero values mean the capture is
incomplete, not just quiet.

**Exercising the fallback.** On a host without `bpf` in `lsm=` the
loader selects tracepoint mode automatically. To rehearse that path
on an LSM host: `make demo FORCE_TP=1`, or run the loader with
`--force-tracepoint-mode`. Expect `handle_exec_tp` /
`handle_file_sys_enter` / `handle_file_sys_exit` in the attached-hook
list and the "fallbacks active" line in the log.

Verify nothing is left behind after exit (dev-mode guarantee):

```sh
sudo bpftool prog show | grep -i agentloupe   # expect: nothing
sudo bpftool map show  | grep -i agentloupe   # expect: nothing
```

## Testing

Three layers, deliberately kept separate:

- **Unit tests** — `make test` (`go test ./...`). No kernel, no root, no
  BPF compilation. This (plus `go vet` and staticcheck) is all CI runs,
  on every PR. There is intentionally no VM/kernel matrix in CI.
- **Static safety checks** — `make check`: ABI `_Static_assert`s plus
  the LSM return-0 checker (an LSM hook must never deny an operation).
- **Integration test** — `sudo make integration`. Real loader, real
  kernel, real workloads: a python process matched as an interpreter
  candidate and confirmed from argv, a child exec, a file open, and
  TCP and UDP connects to local listeners, with the syscall-summary
  probe enabled. It asserts the expected events with
  correct PID/comm/path/address, that `syscall_summary` JSONL events
  appear (with a final flush before `session_end`) and their deltas —
  session-level and per-process (`per_process_counts`) — sum
  exactly to the kernel `syscall_counts` totals, zero ring-buffer drops and zero
  map-full/lost counters, and that no BPF programs, maps, links, or
  pinned objects remain after shutdown. Root-only: the test skips
  unless run as root and never runs in CI. Run `make build` as your
  normal user first — the target deliberately does not build, so no
  artifact is created root-owned — and run `sudo` from a real terminal
  (it needs a TTY). Requires python3 and bpftool (the link leak check).

### Tested on

| Environment | Mode | Result |
|---|---|---|
| Ubuntu, kernel 7.0.0-42-generic, Go 1.26.8, clang 21.1.8, kernel BTF present, `bpf` in `/sys/kernel/security/lsm` | LSM, full requested probe set | `make test` pass, `sudo make integration` **PASS**, 2026-10-28 |
| Same host | LSM, `--catalog-only claude-code` under plain `sudo` | Catalog resolved the per-user install (`SUDO_USER` home), adopted 1 already-running Claude Code process tree, 29,035 events in 87s with zero ring-buffer drops / lost counters, reduced with `loupe-scorecard`, 2026-10-29 |
| Same host | LSM, `--config configs/loupe-demo.yaml --enable-syscall-summary` | Adopted an already-running Claude Code tree (child `gh` attributed per-program) alongside 2× `loupe_demo.py` sessions; 392 events / 75 syscall_summary in 120s, zero ring-buffer drops or lost counters; `root_exit` + `session_end` (`all_exited`) verified live; reduced with loupe-scorecard and loupe-timeline (text + HTML), 2026-10-30 |
| Same host | Tracepoint fallback, `--force-tracepoint-mode` (`FORCE_TP=1 make demo`) | Fallback probe set (`handle_exec_tp`, `handle_file_sys_enter/exit`) loaded and attached; adopted Claude Code tree plus 2× `loupe_demo.py` sessions with correct file/net attribution at raw-arg path fidelity, zero ring-buffer drops; `root_exit` + `session_end` (`all_exited`) verified, 2026-10-30 |
| Same host | LSM (integration + `make demo`) and tracepoint fallback (`FORCE_TP=1 make demo`), ABI v4 | Per-process CPU / peak RSS on `exit`/`root_exit` verified live in both modes: `sudo make integration` **PASS** (all 4 tests, zero ring-buffer drops); demo `exit` events carried plausible values in both modes (e.g. `echo` cpu 0–2ms / RSS ≈3.5 MB, `python3` cpu ≈20–30ms / RSS ≈3.7 MB), zero ring-buffer drops, 2026-10-30 |

Not yet tested on a live kernel:

- **Tracepoint fallback on a host without `bpf` in `lsm=`** (automatic
  selection). The identical probe set was loaded and run via
  `--force-tracepoint-mode` on the host above (see "Tested on"), but
  automatic selection on a genuinely LSM-less host has not been
  exercised. Expect lower path fidelity in this mode: file paths come
  from raw syscall arguments (relative paths stay relative) and the
  dentry walk may miss mount prefixes.
- **Opt-in probe sets** (`--enable-file-mutations`,
  `--enable-io-accounting`). Not attached in the tested configuration.
  (`--enable-syscall-summary` is enabled by the integration test and
  the adoption smoke above.)
- **Any other kernel version.** The 5.8 / 5.11 figures above are design
  floors, not tested versions.

One fidelity note: in LSM mode the exec event's `cwd` is resolved with
the bounded dentry walk (`cwd_src: "dentry_walk"` — best-effort, a
mount prefix may be missing), because `task->fs` is an `__rcu` field
whose pointer the verifier will not accept for `bpf_d_path`. Filename
and file paths still use `bpf_d_path` (`"path_src": "d_path"`).

## Safety

- All LSM hooks return 0 on every path — enforced at build time by
  `scripts/check_lsm_returns.py` (`make check-lsm-returns`, also a
  prerequisite of `make bpf`). A non-zero LSM return would deny the
  operation; that must never happen.
- All maps are fixed-size; map-full failures increment dedicated
  lost-visibility counters surfaced next to ring-buffer drop stats.
- No pinning in dev mode: programs/links are process fds only, so a
  crash (even SIGKILL) detaches everything.
- First load-testing should happen in a VM, not on a production host.

## Layout

```
bpf/            eBPF C (single TU) + shared ABI header
cmd/agentloupe/ loader entrypoint (flags, signals, --max-runtime)
cmd/loupe-scorecard/ per-session totals from a capture
cmd/loupe-timeline/  per-session timeline + breakdown (text / JSON / HTML)
internal/app/   loader: feature probe, attach, maps, events, housekeeping
internal/config/ agents.yaml parsing
configs/        example configuration
scripts/        build-time safety checks, one-command demo (demo.sh)
```
