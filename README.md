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
--enable-syscall-summary   # per-(session, syscall) counts
```

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
  candidate and confirmed from argv, a child exec, a file open, and a
  TCP connect to a local listener. It asserts the expected events with
  correct PID/comm/path/address, zero ring-buffer drops and zero
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

Not yet tested on a live kernel:

- **Tracepoint fallback mode** (no `bpf` in `lsm=`). The loader selects
  it automatically; it has never been loaded live — treat as unverified.
- **Opt-in probe sets** (`--enable-file-mutations`,
  `--enable-io-accounting`, `--enable-syscall-summary`). Not attached
  in the tested configuration.
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
internal/app/   loader: feature probe, attach, maps, events, housekeeping
internal/config/ agents.yaml parsing
configs/        example configuration
scripts/        build-time safety checks
```
