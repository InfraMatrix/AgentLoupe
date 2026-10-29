/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * agentloupe.h — shared contract between the eBPF programs and the Go loader.
 *
 * Included by every .bpf.c after vmlinux.h and <bpf/bpf_helpers.h>.
 * If you change any struct here you change the ABI: bump
 * AGENTLOUPE_ABI_VERSION so the loader refuses a stale object instead of
 * silently mis-decoding events.
 *
 * MINIMUM KERNEL — stated explicitly, enforced by the loader's startup
 * feature probe (which reports every item and which fallback is active):
 *   - Absolute floor: 5.8 (BPF ring buffer; CO-RE/BTF). Below this the
 *     loader refuses to run.
 *   - Full mode: 5.11+ with CONFIG_BPF_SYSCALL=y, CONFIG_DEBUG_INFO_BTF=y,
 *     CONFIG_BPF_LSM=y and "bpf" in the lsm= boot parameter.
 *     Rationale per feature: ring buffer 5.8; fentry/fexit 5.5;
 *     BPF LSM 5.7; bpf_d_path and sleepable programs 5.10;
 *     bpf_get_current_task_btf 5.11 (required by sleepable LSM hooks to
 *     reach the current task). The binding constraint is 5.11.
 *   - Between 5.8 and 5.11 (or without BPF LSM): tracepoint fallback mode.
 *     The loader probes — per hook, not globally — whether each LSM
 *     program loads, whether vfs_read/vfs_write/vfs_readv/vfs_writev are
 *     fentry-attachable in this kernel's BTF, and whether bpf_d_path is
 *     allowlisted for the hooks in use, and activates fallbacks per
 *     missing piece with a startup warning per fallback.
 *
 * Design rules baked into this header:
 *  - All tracking is keyed on host TGID (upper 32 bits of
 *    bpf_get_current_pid_tgid()), never on thread ID.
 *  - Lookup budget: an untracked process costs at most two lookups in any
 *    probe — tracked_sessions[tgid], then agent_cgroups[cgroup_id]. A
 *    tracked process costs tracked_sessions + sessions (state check).
 *  - Events are variable-length ring-buffer records: a fixed
 *    struct event_hdr followed by ONE fixed-size payload struct per event
 *    type, reserved with that type's own constant size via
 *    bpf_ringbuf_reserve(&events, EVLEN_<TYPE>, 0).
 *  - Drops are counted per event type in a percpu array (no atomics on the
 *    hot path); failed map updates (map full) are counted separately in
 *    struct agentloupe_counters and surfaced alongside ring drops.
 *  - Session state lives in the KERNEL (sessions map), not in userspace
 *    scans. Rejecting or timing out a provisional session is one userspace
 *    map write (state = SESSION_REJECTED): the fork hook refuses to
 *    propagate REJECTED sessions and in_scope() treats REJECTED as out of
 *    scope, so there is no fork-during-purge race. Stale tracked_sessions
 *    entries of a rejected subtree are removed by the exit hook and the
 *    userspace /proc sweeper, and stop emitting immediately because every
 *    probe re-checks state. The REJECTED tombstone in sessions is deleted
 *    by userspace once no tracked_sessions entry references it.
 *  - Paths are resolved in the kernel, never trusted from syscall args:
 *    with BPF LSM, bpf_d_path in its allowlisted hooks, plus a sleepable
 *    bprm hook for exec/cwd; on the tracepoint fallback, a bounded
 *    in-kernel dentry walk (see scope.h: fixed depth, mount crossings
 *    marked partial). Each path-bearing payload records HOW its path was
 *    obtained (enum path_source) and truncation sets EVENT_F_PATH_PARTIAL.
 */
#ifndef AGENTLOUPE_H
#define AGENTLOUPE_H

#define AGENTLOUPE_ABI_VERSION 2

/* Minimum kernel for full (LSM) mode; the loader enforces this, the
 * header only documents it. Fallback floor is 5.8. */
#define AGENTLOUPE_MIN_FULL_MAJOR 5
#define AGENTLOUPE_MIN_FULL_MINOR 11

/* ---- Bounds (compile-time, so memory use is known before load) --------- */
#define MAX_TRACKED_SESSIONS 8192   /* entries in tracked_sessions        */
#define MAX_SESSIONS         8192   /* entries in sessions (incl. tombs.) */
#define MAX_AGENT_BINARIES   1024   /* configured tool binaries           */
#define MAX_CANDIDATES       256    /* interpreter binaries (node, ...)   */
#define MAX_AGENT_CGROUPS    2048   /* resolved cgroup IDs (v2 only)      */
#define MAX_FILE_INFOS       16384  /* struct file * -> fd_info (LRU)     */
#define MAX_SYSCALL_COUNTS   16384  /* (session, nr) counters (LRU)       */
#define RINGBUF_BYTES        (8 * 1024 * 1024)

/* ---- Fixed string sizes (truncation is flagged, never silent) ---------- */
#define TASK_COMM_LEN_AL     16     /* matches kernel TASK_COMM_LEN       */
#define AGENT_NAME_LEN       32
#define MAX_PATH_LEN         512    /* file paths, exec filename, cwd     */
#define MAX_ARGV_LEN         512    /* NUL-joined argv, exec events only  */
#define MAX_ARGV_ARGS        16     /* argv entries copied at most        */

/* Bounded dentry walk for the tracepoint fallback (scope.h). At the cap,
 * the path is emitted partial (leading components dropped) with
 * EVENT_F_PATH_PARTIAL | path_source = PATH_SRC_DENTRY_WALK. */
#define DENTRY_WALK_MAX_DEPTH 16
#define DENTRY_WALK_MAX_NAME  64    /* per-component copy bound           */

#define INVALID_UID          4294967295U /* kernel "unset" uid/loginuid    */

/* ---- Event types (stable numbering: JSONL "type" maps from this) ------- */
enum event_type {
	EVENT_UNSPEC        = 0,
	EVENT_EXEC          = 1,  /* sched_process_exec / bprm_committed_creds  */
	EVENT_FORK          = 2,  /* sched_process_fork (new process only)      */
	EVENT_EXIT          = 3,  /* sched_process_exit (thread-group leader)   */
	EVENT_FILE_OPEN     = 4,  /* LSM file_open / tp sys_exit_openat         */
	EVENT_FILE_UNLINK   = 5,  /* LSM path_unlink / tp unlinkat              */
	EVENT_FILE_RENAME   = 6,  /* LSM path_rename / tp renameat              */
	EVENT_FILE_CHMOD    = 7,  /* LSM path_chmod / tp chmod/fchmodat         */
	EVENT_FILE_CLOSE    = 8,  /* last release of a struct file (see fd_info)*/
	EVENT_FILE_IO       = 9,  /* userspace-synthesised periodic flush of a
	                             * long-lived fd_info; payload = ev_file_close
	                             * with EVENT_F_PARTIAL set                   */
	EVENT_NET_CONNECT   = 10, /* connect() to AF_INET/AF_INET6              */
	EVENT_SESSION_START = 11, /* userspace-synthesised on confirm/attach    */
	EVENT_SESSION_END   = 12, /* userspace-synthesised on leader exit       */
	EVENT_MAX           = 13,
};

/* How a path string in a payload was obtained. Recorded per path (rename
 * has two), because the mode (LSM vs fallback) can differ per hook. */
enum path_source {
	PATH_SRC_NONE        = 0, /* path unavailable (payload path is empty) */
	PATH_SRC_D_PATH      = 1, /* bpf_d_path() — authoritative, mount-aware */
	PATH_SRC_DENTRY_WALK = 2, /* bounded dentry walk — may miss mounts    */
	PATH_SRC_RAW_ARG     = 3, /* userspace pointer arg, verbatim (last
	                           * resort; relative, possibly misleading)   */
};

/* session_info.state */
enum session_state {
	SESSION_STATE_UNKNOWN     = 0,
	SESSION_STATE_PROVISIONAL = 1, /* interpreter candidate, undecided     */
	SESSION_STATE_CONFIRMED   = 2,
	SESSION_STATE_REJECTED    = 3, /* tombstone: out of scope, no inherit  */
};

/* session_info.flags (origin; state is separate, above) */
#define SESSION_F_PROVISIONAL  (1U << 0) /* created as interpreter candidate */
#define SESSION_F_FROM_BINARY  (1U << 1) /* matched agent_binaries at exec   */
#define SESSION_F_FROM_CGROUP  (1U << 2) /* matched agent_cgroups            */
#define SESSION_F_FROM_PROC    (1U << 3) /* adopted by startup /proc scan    */
#define SESSION_F_INTERPRETER  (1U << 4) /* confirmed interpreter session    */

/* event_hdr.flags */
#define EVENT_F_TRUNCATED      (1U << 0) /* a string field hit its bound    */
#define EVENT_F_PROVISIONAL    (1U << 1) /* session not yet confirmed       */
#define EVENT_F_ERROR          (1U << 2) /* payload result/exit indicates err */
#define EVENT_F_PARTIAL        (1U << 3) /* FILE_IO flush, not a final close */
#define EVENT_F_PATH_PARTIAL   (1U << 4) /* a path was truncated/incomplete */

/* ---- Map key/value types ------------------------------------------------ */

/*
 * Binary identity as seen from the kernel. Userspace fills this from stat():
 *   dev = makedev(major(st_dev), minor(st_dev))   (kernel dev_t encoding)
 *   ino = st_ino
 * st_dev as returned by glibc is NOT directly comparable to
 * inode->i_sb->s_dev — the loader must convert with makedev(), and a
 * startup self-test (resolve the loader's own binary, look it up with the
 * key the kernel computes for a known exec) verifies the conversion.
 * Caveats: this matches every hard link to the binary and survives rename,
 * but replacing the binary creates a new inode. Package managers install
 * by writing a temp file and renaming it over the old path, so the loader
 * watches the PARENT DIRECTORY of each configured path with inotify
 * (IN_MOVED_TO | IN_CREATE | IN_DELETE) and re-resolves on change — an
 * inotify watch on the file itself follows the old, unlinked inode.
 */
struct binary_id {
	__u32 dev;
	__u32 _pad;
	__u64 ino;
};                                        /* 16 bytes                          */

/* What a matched binary/cgroup resolves to. agent_name is copied into the
 * session_info at creation so probes never need a second lookup to stamp
 * events. */
struct agent_ref {
	__u32 rule_id;                    /* index into userspace config       */
	char  agent_name[AGENT_NAME_LEN];
};                                        /* 36 bytes                          */

/* Kernel-side session state: session_id -> metadata + lifecycle state.
 * Parent linkage and agent metadata live HERE, not in tracked_sessions.
 * Userspace transitions state (PROVISIONAL -> CONFIRMED | REJECTED) with a
 * single map update; the kernel enforces REJECTED in the fork hook and in
 * in_scope(). */
struct session_info {
	__u32 state;                      /* enum session_state                */
	__u32 agent_id;                   /* agent_ref.rule_id                 */
	__u64 parent_session_id;          /* 0 for a root session              */
	__u64 cgroup_id;                  /* cgroup v2 ID at session start     */
	__u64 start_ts_ns;                /* bpf_ktime_get_ns() at creation    */
	__u32 flags;                      /* SESSION_F_*                       */
	__u32 root_tgid;                  /* host TGID that started the session */
	char  agent_name[AGENT_NAME_LEN];
	char  root_comm[TASK_COMM_LEN_AL];
};                                        /* 88 bytes                          */

/* tracked_sessions value: deliberately just the session pointer. All
 * metadata comes from `sessions`; a TGID is in scope iff it maps here AND
 * its session is not REJECTED. */
struct tracked_session {
	__u64 session_id;
};                                        /* 8 bytes                           */

/*
 * Open-file state, keyed by `struct file *` (as a __u64 key), NOT by
 * (tgid, fd). Children after fork, threads, and dup'd descriptors all share
 * one struct file, so byte counts stay attributed across fork with no
 * fd-table walk, and an fd number being reused by a different file can
 * never alias two opens.
 *
 * Which files get an entry — pseudo-filesystems are SKIPPED at creation
 * (inode->i_sb->s_magic checked against proc, sysfs, cgroup/cgroup2,
 * debugfs, tracefs, devpts, bpf, pstore, securityfs, configfs,
 * anon_inode/pipe/socket inodes): an agent's /proc and /sys reads would
 * otherwise evict real-file entries and swamp attribution. Sizing
 * assumption for MAX_FILE_INFOS: regular files and directories on real
 * filesystems (ext4/xfs/btrfs/overlayfs/tmpfs) opened by tracked agents.
 *
 * Lifecycle:
 *  - Created on LSM file_open (or lazily by the vfs_read/vfs_write probes
 *    for files inherited/opened before tracking started, if the file
 *    pointer is unknown but current is in scope).
 *  - Byte counts accumulated by fentry/fexit on vfs_read, vfs_write,
 *    vfs_readv and vfs_writev (fexit sees both the file argument and the
 *    return value, so no in-flight map is needed; *v variants return the
 *    same byte total). NOTE: io_uring reads/writes go through the file's
 *    read_iter/write_iter directly and may bypass all four vfs_* entry
 *    points — those bytes are undercounted or missed. Known, documented
 *    gap, symmetric to io_uring bypassing syscall tracepoints.
 *  - Deleted on final release: LSM file_free_security (fallback __fput),
 *    which fires exactly once per struct file and therefore covers
 *    close(2), process exit, dup2 overwrite, and close-on-exec alike.
 *  - Release may run in a deferred/kworker or unrelated task context, so
 *    the opener's session_id and tgid are STORED here at open time;
 *    EVENT_FILE_CLOSE takes its attribution from this struct, never from
 *    `current`.
 *  - Userspace periodically iterates the map and synthesises EVENT_FILE_IO
 *    (EVENT_F_PARTIAL) for long-lived entries; it tracks last-reported
 *    counters itself, keyed by (file_ptr, open_ts_ns), and emits deltas.
 */
struct fd_info {
	char  path[MAX_PATH_LEN];
	__u64 session_id;                 /* opener's session (close attribution) */
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 open_ts_ns;
	__u64 ino;                        /* (dev, ino) disambiguate pointer reuse */
	__u32 opener_tgid;                /* host TGID that opened the file    */
	__u32 flags;                      /* open(2) flags                     */
	__u32 dev;                        /* kernel dev_t encoding, as binary_id */
	__u8  path_src;                   /* enum path_source                  */
	__u8  _pad[3];
};                                        /* 568 bytes                         */

/* Syscall summary (optional probe): counts only, never events. */
struct syscall_key {
	__u64 session_id;
	__u32 syscall_nr;
	__u32 _pad;
};

/* Per-CPU scratch for the dentry walk: component staging cannot fit on the
 * 512-byte BPF stack alongside a 256-byte path buffer. Single entry per
 * CPU; BPF programs run non-preemptibly per invocation, and the walk
 * completes within one invocation, so no locking is needed. */
struct path_scratch {
	char buf[MAX_PATH_LEN];           /* assembled path (built backwards) */
	char comp[DENTRY_WALK_MAX_NAME];  /* one component being copied       */
};

/* Pending syscall-fallback file operation, keyed by full pid_tgid
 * (thread-scoped: enter/exit pair on the same thread). Only created for
 * in-scope processes. The tracepoint fallback captures path args at
 * sys_enter (marked PATH_SRC_RAW_ARG) and result/fd at sys_exit. */
#define MAX_PENDING_OPS 1024
struct pending_file_op {
	__u32 op;                         /* enum event_type                   */
	__u32 flags;                      /* open flags, or chmod mode         */
	char  path[MAX_PATH_LEN];
	char  path2[MAX_PATH_LEN];        /* rename only                       */
	__u8  path_src;                   /* enum path_source                  */
	__u8  _pad[3];
};

/* Per-event-type counters. Percpu: each CPU bumps its own copy, userspace
 * sums. ringbuf_drops counts reservation failures only — out-of-scope
 * processes are the normal case and are not "drops". */
struct event_counters {
	__u64 emitted;
	__u64 ringbuf_drops;
};

/* Failures that are NOT ring-buffer drops, kept separate so "we are losing
 * visibility" is distinguishable from "the ring is undersized". Percpu,
 * single entry; userspace sums and exposes every field. */
struct agentloupe_counters {
	__u64 tracked_updates_failed;     /* tracked_sessions full: a process
	                                   * (possibly a whole subtree) is now
	                                   * silently untracked — alert on this */
	__u64 sessions_updates_failed;    /* sessions full: session not created */
	__u64 file_info_updates_failed;   /* file_infos full: lost attribution */
	__u64 syscall_updates_failed;     /* syscall_counts full               */
	__u64 session_allocs_failed;      /* session_counter unreadable (bug)  */
	__u64 exec_hook_runs;             /* exec hooks entered (both modes)   */
	__u64 exec_out_of_scope;          /* exec hooks that matched nothing:
	                                   * hook_runs == out_of_scope while
	                                   * known agents exec => key mismatch */
	__u64 exec_no_file;               /* exec hooks with no bprm/exe file:
	                                   * raw-tp argument parsing suspect  */
	__u64 exec_binary_miss;           /* exec hooks whose (dev,ino) key hit
	                                   * neither agent_binaries nor
	                                   * candidates                       */
	__u64 exec_last_dev;              /* last binary key the kernel built */
	__u64 exec_last_ino;
	__u64 file_pending_stored;        /* sys_enter file-op handlers entered
	                                   * (any process, before scope check) */
	__u64 file_pending_matched;       /* sys_exit found its pending op     */
};

/* Runtime toggles, written by the loader; index 0 of the config map. */
struct agentloupe_config {
	__u64 run_id;                     /* echoed in every userspace record  */
	__u32 enable_syscall_summary;     /* gates raw_syscalls:sys_enter body */
	__u32 enable_file_io_accounting;  /* gates vfs_read/write(v) probes    */
	__u32 enable_file_mutations;      /* gates unlink/rename/chmod fallback */
	__u32 net_udp_only;               /* enter_connect emits SOCK_DGRAM only
	                                   * (set when TCP fexit probes attached) */
};

/* ---- Event records -------------------------------------------------------
 *
 * Wire format per record:
 *     struct event_hdr | one payload struct, chosen by hdr.type
 * hdr.size is the TOTAL record size (header + payload) and must equal the
 * constant EVLEN_<TYPE> for the type; the Go decoder validates
 * version, size >= sizeof(hdr), and size == expected-for-type before
 * touching the payload, and skips (counting) malformed records.
 *
 * Every payload is itself fixed-size: all variability across types is in
 * WHICH payload follows the header, never in a payload's own length.
 * Strings are fixed arrays, NUL-terminated when they fit, with
 * EVENT_F_TRUNCATED / EVENT_F_PATH_PARTIAL set when they do not.
 *
 * ts_ns is monotonic (bpf_ktime_get_ns). Userspace converts to wall clock
 * once, using boot time sampled at startup.
 *
 * Field naming: `tgid` is the host thread-group ID (what userspace on the
 * host calls the PID). `pid` is the same thread-group's ID inside its own
 * PID namespace (what the process itself sees from getpid()). The JSONL
 * schema emits both as "pid" (host) and "pid_in_ns". parent_session_id is
 * copied from `sessions` at emit time (one extra lookup, tracked path only).
 */
struct event_hdr {
	__u16 type;                       /* enum event_type                   */
	__u16 size;                       /* total record size, incl. header   */
	__u16 version;                    /* AGENTLOUPE_ABI_VERSION            */
	__u16 flags;                      /* EVENT_F_*                         */
	__u64 ts_ns;
	__u64 session_id;
	__u64 parent_session_id;          /* 0 for root sessions               */
	__u64 cgroup_id;                  /* cgroup v2 ID                      */
	__u32 tgid;                       /* host thread-group ID              */
	__u32 pid;                        /* thread-group ID in its PID ns     */
	__u32 ppid;                       /* host TGID of real_parent          */
	__u32 uid;                        /* fallback identity: when
	                                   * audit_loginuid is INVALID_UID the
	                                   * loader reports this uid instead   */
	char  comm[TASK_COMM_LEN_AL];
};                                        /* 72 bytes                          */

struct ev_exec {
	char  filename[MAX_PATH_LEN];
	char  cwd[MAX_PATH_LEN];
	char  argv[MAX_ARGV_LEN];         /* NUL-separated, double-NUL end     */
	__u32 argc;                       /* entries copied (<= MAX_ARGV_ARGS) */
	__u32 audit_loginuid;             /* INVALID_UID if unset/no CONFIG_AUDIT */
	__u32 audit_sessionid;            /* audit session, NOT our session_id */
	__s32 result;                     /* 0 (exec success has no retval)    */
	__u8  filename_src;               /* enum path_source                  */
	__u8  cwd_src;                    /* enum path_source                  */
	__u16 _pad;
	__u32 _pad2;
};                                        /* 1560 bytes                        */

struct ev_fork {
	__u32 child_tgid;                 /* host TGID of the new process      */
	__u32 child_pid;                  /* child's PID in its PID namespace  */
};                                        /* 8 bytes                           */

struct ev_exit {
	__s32 exit_code;                  /* raw exit status; decoded in Go    */
	__s32 _pad;
};                                        /* 8 bytes                           */

/* file_ptr is the struct file * as an opaque correlation cookie. It is
 * meaningful only within one boot and one loader run; userspace must not
 * persist it or expose it as a stable identifier in output. */
struct ev_file_open {
	char  path[MAX_PATH_LEN];
	__u64 file_ptr;
	__u32 flags;                      /* open(2) flags                     */
	__s32 result;                     /* 0 or negative errno               */
	__u8  path_src;                   /* enum path_source                  */
	__u8  _pad[3];
	__u32 _pad2;
};                                        /* 536 bytes                         */

struct ev_file_unlink {
	char  path[MAX_PATH_LEN];
	__s32 result;
	__u8  path_src;
	__u8  _pad[3];
};                                        /* 520 bytes                         */

struct ev_file_rename {
	char  old_path[MAX_PATH_LEN];
	char  new_path[MAX_PATH_LEN];
	__s32 result;
	__u8  old_path_src;
	__u8  new_path_src;
	__u16 _pad;
};                                        /* 1032 bytes                        */

struct ev_file_chmod {
	char  path[MAX_PATH_LEN];
	__u32 mode;
	__s32 result;
	__u8  path_src;
	__u8  _pad[3];
	__u32 _pad2;
};                                        /* 528 bytes                         */

struct ev_file_close {
	char  path[MAX_PATH_LEN];
	__u64 file_ptr;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 open_ts_ns;                 /* pairs with file_ptr to identify
	                                   * one open across flush + close     */
	__u8  path_src;
	__u8  _pad[7];
};                                        /* 552 bytes                         */

struct ev_net_connect {
	__u8  daddr[16];                  /* IPv4 in first 4 bytes if family=2 */
	__u8  saddr[16];
	__u16 dport;                      /* host byte order                   */
	__u16 sport;                      /* 0 if not yet bound/unknown        */
	__u16 family;                     /* AF_INET / AF_INET6                */
	__u8  protocol;                   /* IPPROTO_TCP / UDP                 */
	__u8  flags;                      /* bit0: DNS (dport 53)              */
	__s32 result;                     /* connect() result where available  */
	__s32 _pad2;
};                                        /* 48 bytes                          */

/* Total ring-buffer record size per type: the constant passed to
 * bpf_ringbuf_reserve() and checked against hdr.size by the decoder. */
#define EVLEN_EXEC       (sizeof(struct event_hdr) + sizeof(struct ev_exec))
#define EVLEN_FORK       (sizeof(struct event_hdr) + sizeof(struct ev_fork))
#define EVLEN_EXIT       (sizeof(struct event_hdr) + sizeof(struct ev_exit))
#define EVLEN_FILE_OPEN  (sizeof(struct event_hdr) + sizeof(struct ev_file_open))
#define EVLEN_FILE_UNLINK (sizeof(struct event_hdr) + sizeof(struct ev_file_unlink))
#define EVLEN_FILE_RENAME (sizeof(struct event_hdr) + sizeof(struct ev_file_rename))
#define EVLEN_FILE_CHMOD (sizeof(struct event_hdr) + sizeof(struct ev_file_chmod))
#define EVLEN_FILE_CLOSE (sizeof(struct event_hdr) + sizeof(struct ev_file_close))
#define EVLEN_NET_CONNECT (sizeof(struct event_hdr) + sizeof(struct ev_net_connect))

/* Compile-time ABI guards: if any of these fire, bump AGENTLOUPE_ABI_VERSION
 * and update the Go decoder in the same commit. `make check-header` verifies
 * them with a host compiler, no kernel or libbpf needed. */
_Static_assert(sizeof(struct event_hdr) == 72, "event_hdr ABI changed");
_Static_assert(sizeof(struct ev_exec) == 1560, "ev_exec ABI changed");
_Static_assert(sizeof(struct ev_file_open) == 536, "ev_file_open ABI changed");
_Static_assert(sizeof(struct ev_file_chmod) == 528, "ev_file_chmod ABI changed");
_Static_assert(sizeof(struct ev_file_close) == 552, "ev_file_close ABI changed");
_Static_assert(sizeof(struct session_info) == 88, "session_info ABI changed");
_Static_assert(sizeof(struct tracked_session) == 8, "tracked_session ABI changed");
_Static_assert(sizeof(struct fd_info) == 568, "fd_info ABI changed");

/* ---- Maps ----------------------------------------------------------------
 * All maps are defined here (not per-program) so every program sees
 * identical definitions. The MVP links all probes into ONE object
 * (single translation unit) so these maps are shared without pinning.
 */

/* TGID -> tracked_session ("tracked"). Plain HASH, not LRU:
 * sched_process_exit removes the entry, and the loader sweeps stale
 * entries against /proc. LRU would silently evict a live long-running
 * agent under fork pressure, which is worse than a bounded leak the
 * sweeper can see and count. A failed update (map full) increments
 * agentloupe_counters.tracked_updates_failed — that is a visibility loss,
 * not a drop, and must page like one. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TRACKED_SESSIONS);
	__type(key, __u32);
	__type(value, struct tracked_session);
} tracked_sessions SEC(".maps");

/* session_id -> session_info: lifecycle state + metadata. Written by the
 * kernel at session creation; state transitions (CONFIRMED/REJECTED) are
 * single userspace updates. Not LRU for the same reason as above: evicting
 * a live session's state would resurrect the fork-during-purge class of
 * bugs. Userspace deletes entries (incl. REJECTED tombstones) once no
 * tracked_sessions entry references them and any provisional decision
 * window has closed. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, __u64);
	__type(value, struct session_info);
} sessions SEC(".maps");

/* (dev,ino) -> agent, for directly-executed agent binaries. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_AGENT_BINARIES);
	__type(key, struct binary_id);
	__type(value, struct agent_ref);
} agent_binaries SEC(".maps");

/* (dev,ino) -> agent, for interpreters needing argv confirmation. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CANDIDATES);
	__type(key, struct binary_id);
	__type(value, struct agent_ref);
} candidates SEC(".maps");

/* cgroup v2 ID -> agent, for deployed services. cgroup v2 is REQUIRED:
 * bpf_get_current_cgroup_id() identifies tasks in the v2 hierarchy, and
 * the loader refuses (or loudly warns and disables service matching) on a
 * v1 or hybrid host rather than silently matching nothing. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_AGENT_CGROUPS);
	__type(key, __u64);
	__type(value, struct agent_ref);
} agent_cgroups SEC(".maps");

/* struct file * -> open-file state. LRU is correct here: an eviction only
 * loses byte attribution for one file, never session membership (the
 * evicted file's release then finds nothing and is skipped, which the
 * file_info counters make visible). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_FILE_INFOS);
	__type(key, __u64);               /* struct file *                     */
	__type(value, struct fd_info);
} file_infos SEC(".maps");

/* Optional per-(session, syscall) counts. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_SYSCALL_COUNTS);
	__type(key, struct syscall_key);
	__type(value, __u64);
} syscall_counts SEC(".maps");

/* Index 0: next session counter, seeded by userspace (see session_id note
 * at struct session_info: (random_run_id << 32) | counter). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} session_counter SEC(".maps");

/* Index 0: struct agentloupe_config. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct agentloupe_config);
} config_map SEC(".maps");

/* Per-event-type emitted/drop counters, summed by userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EVENT_MAX);
	__type(key, __u32);
	__type(value, struct event_counters);
} stats SEC(".maps");

/* Map-full / lost-visibility counters (struct agentloupe_counters). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct agentloupe_counters);
} counters SEC(".maps");

/* Per-CPU dentry-walk scratch (struct path_scratch). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct path_scratch);
} path_scratch_map SEC(".maps");

/* Pending tracepoint-fallback file ops (struct pending_file_op). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PENDING_OPS);
	__type(key, __u64);               /* bpf_get_current_pid_tgid()        */
	__type(value, struct pending_file_op);
} pending_file_ops SEC(".maps");

/* The single output channel. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} events SEC(".maps");

#endif /* AGENTLOUPE_H */
