# AgentLoupe

An agent observability tool: eBPF-based, observe-only visibility into what
AI agents do on a Linux host — process execution, file activity, and
network connections, scoped to agent processes only. No enforcement, no
kernel modules, nothing pinned.

## Status

MVP in development. The eBPF programs and dev-mode Go loader are written;
they have not yet been load-tested on a live kernel. See "Safety" before
running anywhere that matters.

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

## Dev-mode quickstart (kernel 5.11+, BTF required)

On a host without `bpf` in `lsm=` (check `/sys/kernel/security/lsm`) the
loader automatically runs in tracepoint-fallback mode.

```sh
sudo apt-get install -y clang libbpf-dev bpftool golang
make check            # header ABI asserts + LSM return-0 safety check
make vmlinux.h        # from THIS host's /sys/kernel/btf/vmlinux
make bpf              # bpf/agentloupe.bpf.o (also runs check-lsm-returns)
go mod tidy
go build -o agentloupe ./cmd/agentloupe

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
