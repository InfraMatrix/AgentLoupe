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

# Default probe set: process, file-open, file-mutations, network.
# Nothing is pinned;
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
--enable-io-accounting     # vfs_* byte counts + file_close (make bench-io first)
--enable-syscall-summary   # per-(session, process, syscall) counts, dumped by name
                           # in the stats log (top 25 per session) and, with
                           # --syscall-interval, as syscall_summary JSONL events
--enable-file-rw-events    # discrete file_read/file_write event per vfs call
                           # (ABI v5: this call's size + timestamps only;
                           # works without --enable-io-accounting)
--enable-net-send-events   # discrete net_send event per tcp/udp_sendmsg call
                           # and net_recv event per tcp/udp_recvmsg call
                           # (ABI v7: this call's bytes + destination +
                           # hostname — DNS qname / TLS SNI parsed from
                           # the send buffer; empty when it holds no name;
                           # ABI v8: recv carries latency_us, the send->recv
                           # time-to-first-byte; 0 when unpaired)
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

### Real-agent demo (Claude Code + hooks) and the offline canned run

```sh
make demo-canned   # offline, no sudo: scorecard + tool spans + AgentCutter
                   # analysis of the canned run in examples/canned/
make real-agent    # record a fresh run (examples/real-agent/run.sh)
```

`examples/real-agent/run.sh` clones NetworkX at a pinned commit
(networkx-3.5), injects a one-line bug in
`networkx/algorithms/shortest_paths/weighted.py` (`<` → `<=` in
Dijkstra's relaxation, so equal-length paths stop being recorded as
predecessors: 4 tests fail), installs the hook in the clone's
`.claude/settings.json`, and runs `claude -p` under the loader
(`--catalog-only claude-code`, syscall summary, io accounting, net
send/recv events) with a prompt to set up a venv, fix the bug without
touching tests, and run the full suite.

Credentials come in two kinds that the demo keeps apart. **Coding-agent
credentials** (`AGENT_*`) decide what the observed Claude Code run bills
to: the default `claude` login, other logged-in profiles (`~/.claude-<name>`,
a second subscription), `claude setup-token` tokens, or API keys
(`~/.config/agentloupe/agent-credentials/<name>.{key,oauth,profile}`,
`AGENT_API_KEY_FILE`, `AGENT_API_KEY`). `AGENT_AUTH=list` shows what is
available, `AGENT_AUTH=<id>` picks one, and with several available and
no choice the script shows a menu. The model is then chosen from what
those credentials can use: for an API key, the list its own service
returns (`/v1/models`); subscription logins cannot be listed, so the menu
offers the account default or a typed id (`AGENT_MODEL=<id>` skips it).
`scripts/agent-session pick` saves a credentials + model choice ahead of
time (ids only), `show` checks it, and `run -- [args]` starts your own
`claude` with it for runs under the loader.

Before anything is built, the demo shows the credentials and model and
asks whether they are right; answering no prints how to set the ones you
want (without a terminal it needs `AGENT_CONFIRM=1`). The credentials are
checked with `claude auth status` then and again right before the agent
starts, and the choice is recorded in `out/agent-session.txt` (no secret).
The **analysis-model key** (`META_MODEL_API_KEY`, AgentCutter) is only used
by `SAVE_CANNED=1` and is never passed to the agent. Run it from a plain terminal:
sudo needs the TTY, and a `claude` started from inside another tracked
Claude Code session would be folded into that session. `SAVE_CANNED=1`
also refreshes `examples/canned/` through `scripts/make_canned.py`,
which keeps only the demo session, sanitizes paths and the user name,
and renders `report.json` and `analysis.md` (AgentCutter; a real model
call when `META_MODEL_API_KEY` is set, otherwise its dry run).

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

### Tool spans: which tool call used what

`loupe-timeline` (text, `--json`, and the `--tool-spans` table) breaks
each session into **tool spans** — "tool call #12 (pytest) used 40s CPU,
300 MB of reads, 3 round trips" rather than "the session made 62 opens".

```sh
./loupe-timeline --tool-spans capture.jsonl            # span table per session
./loupe-timeline --json capture.jsonl | jq '.sessions[].tool_spans'
./loupe-timeline --agent-process claude capture.jsonl  # agent wrapped by a launcher
```

**Layer 1 — process tree (no harness cooperation).** Most harnesses run
each tool as a child process (Claude Code's Bash tool spawns
`bash -c ...`), so each direct child subtree of the agent process is one
span (`source: "process_tree"`). The agent process is the session root
unless `--agent-process NAME` picks an earlier-matching comm / exec
basename / argv[0] (for harnesses that wrap the agent; processes outside
the chosen agent's tree are counted in `agent_self` and reported as
`agent_process.outside_agent_tree`). A span carries `span_id`, root pid,
the first exec's argv (truncated: 16 args, 200 B each, 800 B total) and,
for `sh/bash -c`, the `command` payload; start/end, `wall_ms`, the root's
`exit_code`; and resources aggregated over the whole subtree:

| `resources` field | Source |
|---|---|
| `cpu_user_ms`, `cpu_sys_ms`, `max_rss_kb` | `exit` events (ABI v4), summed (RSS: max) over the subtree. `cpu_incomplete` = some processes had not exited by capture end. |
| `file_opens`, `file_open_failures`, `files_mutated` | `file_open`, unlink/rename/chmod events. |
| `file_reads`, `file_writes`, `read_bytes`, `write_bytes` | per-call `file_read`/`file_write` events when collected, else `file_close` totals (`--enable-io-accounting`); the session's `io_bytes_source` says which. |
| `net_connects`, `dns_connects`, `net_sends`, `net_recvs`, `net_sent_bytes`, `net_recv_bytes` | net events; `top_destinations` per span. |
| `syscalls_by_category`, `syscalls_total` | `syscall_summary` `per_process_counts` (interval-granular). |

A field is **null** when the capture did not collect that signal (probe
off, per the `capture_meta` record or, for older captures, inferred from
which event types appear) — a 0 is always a measured zero.

- **Nested shells**: `bash -c "pytest"` and everything it starts is one
  span, whatever the depth.
- **Daemonized / orphaned children** are attributed to the span that
  forked them (parentage is fixed at fork time, so a reparent to init or
  a subreaper does not move them) and the span is flagged
  `outlived_span` with `subtree_end_ms`.
- **Parallel tools**: overlapping spans list each other in `parallel_with`.
- **`agent_self`**: events of the agent process itself (in-process tools,
  model calls, interpreter startup, sleeps) are an explicit bucket, never
  dropped. Every session reports independent `resource_totals` and
  `tool_span_reconciliation`: `sum(tool_spans) + agent_self == totals` on
  every additive field; a failure is also written to the report notes.

**Layer 2 — harness spans via Claude Code hooks.** `hooks/agentloupe_hook.py`
(Python standard library only) is a `PreToolUse` / `PostToolUse` /
`PostToolUseFailure` command hook that appends one JSONL line per event —
`event` (`pre`/`post`/`post_failure`), `tool_name`, `tool_use_id`,
`session_id`, `ts_ns` (CLOCK_REALTIME), `mono_ns` (CLOCK_MONOTONIC), `pid`,
`ppid`, `ancestors`, an `input` summary, and on post `duration_ms`
(Claude Code's own tool time). The input summary keeps only known short
keys (`command`, `file_path`, `pattern`, `url`, ...) truncated to 300
chars; anything else (file `content`, `old_string`/`new_string`, ...) is
reduced to its length under `_sizes`, so file contents are never
recorded. It prints nothing and always exits 0: it cannot block or alter
a tool call.

Install it in `.claude/settings.json` (project) or `~/.claude/settings.json`
(user) — `hooks/claude-settings.example.json`:

```json
{
  "hooks": {
    "PreToolUse":         [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /path/to/AgentLoupe/hooks/agentloupe_hook.py" }] }],
    "PostToolUse":        [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /path/to/AgentLoupe/hooks/agentloupe_hook.py" }] }],
    "PostToolUseFailure": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /path/to/AgentLoupe/hooks/agentloupe_hook.py" }] }]
  }
}
```

The spans file is `$AGENTLOUPE_SPANS`, else
`$AGENTLOUPE_CAPTURE_DIR/spans.jsonl`, else `/tmp/agentloupe/spans.jsonl`.
Name it `<capture>.spans.jsonl` (e.g. `AGENTLOUPE_SPANS=run.spans.jsonl`
next to `run.jsonl`) and `loupe-timeline` picks it up automatically;
otherwise pass `--spans FILE`.

Correlation (report `harness` section): a harness call is the pre→post
interval of one `tool_use_id`, placed in the session whose agent process
is an ancestor of the hook (or that contains the hook's own process).
Child-process spans starting inside that interval are matched to it —
first by the Bash `command` appearing in the subtree's argv, then for
process-spawning tools (Bash, Grep, Glob) by time containment, innermost
call first — and merged into one span, `source: "harness+process_tree"`,
carrying `tool_name`, `tool_use_id`, `input`, `status`
(`ok`/`error`/`interrupted`/`no_post`), `harness_duration_ms` and
`process_wall_ms`. Calls with no child process (Read, Edit, Write, Glob
when in-process, ...) become `source: "harness"` spans with
`attribution: "time_window"`: the agent process's own file and network
events inside the window move from `agent_self` into the span.
**This is approximate** — any concurrent in-process work in that window
(model streaming, a parallel tool) is included; overlapping windows give
each event to the innermost (latest-starting) call and say so in the
span's `notes`; CPU and syscall counts are whole-process / per-interval
numbers and stay in `agent_self` (null on the span). Child processes the
agent starts on its own (e.g. `git status`) during a Read window stay
plain `process_tree` spans. The hook's own processes are spans tagged
`role: "hook"` (observation overhead) linked to their `tool_use_id`.

**Clocks.** BPF timestamps are `bpf_ktime_get_ns()` — CLOCK_MONOTONIC
(no suspend time, NTP-slewed). The loader renders `ts` as
`wall_base + ktime`, where `wall_base` (CLOCK_REALTIME − CLOCK_MONOTONIC
at loader start) is written once to the capture's first line, a
`capture_meta` record (`session_id` 0; readers skip it; it also carries
the probe set). The hook records CLOCK_MONOTONIC too, so hook time maps to
capture time exactly: `wall_base_unix_ns + mono_ns`
(`harness.clock.method: "monotonic"`). CLOCK_REALTIME would be wrong by
any suspend or NTP step since loader start; it is used only for captures
without `capture_meta`, shifted by an offset estimated from the hook's own
processes in the capture (`realtime_pid_anchored`, biased by the fastest
hook startup) or as-is when none are found (`realtime_assumed`). Every
method reports anchor residuals — hook timestamp minus its own process's
start, which must be ≥ 0 and a few ms of interpreter startup.

Not covered: harnesses without hooks get process-tree spans only, and
in-process work (model calls, in-process file tools) stays in
`agent_self`; naming it needs harness cooperation or, for model calls,
user-space TLS uprobes (future work).

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

#### `file_read` / `file_write` events

With `--enable-file-rw-events`, the loader emits one discrete event per
`vfs_read`/`vfs_write` (and `readv`/`writev`) call on a tracked file —
the per-call attribution that `file_close` totals and
`--enable-io-accounting` counters cannot give. `bytes` is **this call's**
byte count (the call's return value), not a cumulative total; pairing
calls into per-open totals is done on `(file_ptr, open_ts_ns)`, the same
key `file_close` uses. These are the fexit probes, so they work in both
LSM and tracepoint-fallback modes, and they do not require
`--enable-io-accounting`.

Latency comes from four companion fentry probes on the same
`vfs_read`/`vfs_write`/`vfs_readv`/`vfs_writev` symbols: each entry
stamps `bpf_ktime_get_ns()` into an LRU map keyed on (thread, file),
and the fexit side consumes it into `duration_us`. The fentry probes
attach under the same flag but degrade independently — if they fail to
load, the events still flow with `duration_us` 0, and the loader logs
`file_rw_latency=false`. A zero duration on an individual event likewise
means unknown (entry missed or evicted) or sub-microsecond, never a
dropped event.

Volume warning: this fires on every read/write a tracked process makes,
including interpreter startup (hundreds of small reads). Prefer it for
bounded captures, or pair it with `--drop-path-prefix` for trees you do
not care about. The events land in the timeline as per-path markers and
in the scorecard as `file_reads`/`file_writes` call counts (byte totals
still come from `file_close`, so nothing double-counts).

| Field | Meaning |
|---|---|
| `type` | `"file_read"` or `"file_write"`. |
| `path`, `path_src` | File path and how it was resolved (same semantics as `file_open`). |
| `file_ptr`, `open_ts_ns` | Correlation key for one open (same as `file_close`). |
| `bytes` | This call's byte count. |
| `duration_us` | Per-call latency in microseconds, paired by the fentry probes. **0 means unknown** (entry missed, fentry degraded/unattached) **or sub-microsecond** — never a dropped event. |

#### `net_send` events

With `--enable-net-send-events`, the loader emits one discrete event per
`tcp_sendmsg`/`udp_sendmsg` call on a tracked socket — the network-side
equivalent of the file `file_read`/`file_write` events. `bytes` is
**this call's** byte count (the call's return value; failed calls emit
nothing), with the destination (`daddr`, `dport`) and source port from
the socket. TCP destinations always come from the sock; unconnected UDP
sends carry a per-call destination parsed from the message (connected
UDP falls back to the sock). Same volume warning as the rw events: this
fires on every send a tracked process makes. The events land in the
timeline as per-destination markers (with byte counts and hostnames) and
in the scorecard as `net_sends`/`net_sent_bytes` totals plus a sorted
unique `hostnames` list (per-destination send volume and per-dest
hostnames stay in the timeline's net entries). Each send also stamps a
per-(thread, socket) last-send record consumed by the recv path below,
so enabling sends is what arms recv latency.

#### `net_recv` events (ABI v8)

The same flag emits one event per `tcp_recvmsg`/`udp_recvmsg` call on a
tracked socket (failed calls emit nothing). `bytes` is this call's byte
count; the address fields are the **remote peer** — the sock's peer for
TCP, the datagram's source address for UDP. `latency_us` is the
microseconds from the last send on the same thread and socket to this
recv: the call's time-to-first-byte. It is 0 when no send was seen
(recv before any send, a cross-thread send/recv pair, an evicted
record) — unknown, never wrong. The send's `hostname` rides along onto
the recv, so responses inherit the name of the request that caused
them. Recvs land in the timeline as per-destination markers (with byte
counts, latencies, and hostnames) and in the scorecard as
`net_recvs`/`net_recv_bytes` totals plus `first_response_us`, the
session's first paired send→recv latency.

`hostname` (ABI v7) is the DNS query name for UDP sends and the TLS
ClientHello SNI for TCP sends, parsed from **this call's** send buffer at
`sys_enter` (where the buffer pointers are stable) and paired with the
send at its `fexit`. Parsing is strict: single-question queries with
plain labels only, well-formed ClientHellos walked to `server_name`, the
whole name fitting in 63 characters. Anything else — raw TCP/UDP
payloads, over-long names, a missed enter probe — yields an **empty**
hostname, never a dropped event. A name learned from an earlier send to
the same destination (e.g. DNS-before-connect) also annotates that
destination's `net_connect` markers in the timeline; SNI arrives after
its connect, so it is never backfilled there. Two known gaps: `sendmmsg`
batches share the first datagram's parse, and only `iov[0]` of a
`sendmsg` is inspected.

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
`/proc` and say nothing about child tools. `loupe-scorecard` reports the
`session_end` figure when there is one; when there is not (e.g. the
capture stopped before the session closed) it falls back to the sum of
every exited process's exit CPU (a `root_exit` counts only if the root's
`exit` was missed), and `cpu_source` (`session_end` / `exits`) says
which. With neither, the CPU column shows `-`.

Useful loader flags: `--drop-path-prefix /proc/` (repeatable) suppresses
file-event noise (e.g. agents polling their own `/proc/<pid>/stat`);
`session_end` events carry `cpu_user_ms`/`cpu_sys_ms` (session root
process CPU, sampled from `/proc`). Network events cover TCP and UDP;
connects to port 53 are flagged `"dns": true`, and with
`--enable-net-send-events` the send's `hostname` carries the parsed DNS
query name (UDP) or TLS SNI (TCP) — empty when the buffer holds no name.
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
- **Opt-in probe sets** (`--enable-io-accounting`,
  `--enable-syscall-summary`, `--enable-file-rw-events`). Not attached in the tested configuration
  unless noted. (Unlink/rename/chmod events are core since slice 1 and
  always attached.)
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
cmd/loupe-timeline/  per-session timeline + breakdown + tool spans (text / JSON / HTML)
hooks/          Claude Code tool-call hook (harness spans) + settings example
internal/app/   loader: feature probe, attach, maps, events, housekeeping
internal/config/ agents.yaml parsing
configs/        example configuration
scripts/        build-time safety checks, one-command demo (demo.sh),
                canned-run export (make_canned.py)
examples/       demo workload, real-agent run script, canned real-agent run
```
