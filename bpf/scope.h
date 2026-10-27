/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * scope.h — scoping, session lifecycle, event emission and path resolution.
 * Included once by agentloupe.bpf.c (single translation unit).
 *
 * Requires: vmlinux.h, <bpf/bpf_helpers.h>, <bpf/bpf_core_read.h>,
 *           <bpf/bpf_tracing.h>, agentloupe.h.
 *
 * Path resolution strategy (see agentloupe.h):
 *   - path_via_dpath():  bpf_d_path, LSM programs ONLY. The helper is
 *     allowlisted per program type/function; calling it from a tracepoint
 *     program would make that program fail to load, so the two variants are
 *     kept strictly separate and the exec logic is split so no shared
 *     subprogram ever references bpf_d_path.
 *   - path_via_walk():   bounded dentry walk for tracepoint/fentry use.
 *     Mount crossings are NOT followed (struct mount is not exposed in
 *     vmlinux BTF, so mountpoint translation is impossible with CO-RE);
 *     the walk stops at the mount root and the path may be missing its
 *     mount prefix. That is why PATH_SRC_DENTRY_WALK exists: downstream
 *     consumers can see the path is best-effort, never silently exact.
 */
#ifndef AGENTLOUPE_SCOPE_H
#define AGENTLOUPE_SCOPE_H

/* Pseudo-filesystem superblock magics skipped for file_infos creation. */
#define AL_PROC_SUPER_MAGIC    0x9fa0ULL
#define AL_SYSFS_MAGIC         0x62656572ULL
#define AL_CGROUP2_MAGIC       0x63677270ULL
#define AL_CGROUP_MAGIC        0x27e0ebULL
#define AL_DEBUG_MAGIC         0x64626720ULL
#define AL_TRACEFS_MAGIC       0x74726163ULL
#define AL_DEVPTS_MAGIC        0x1cd1ULL
#define AL_BPF_FS_MAGIC        0xcafe4a11ULL
#define AL_SECURITYFS_MAGIC    0x73636673ULL
#define AL_PSTORE_MAGIC        0x6165676cULL
#define AL_CONFIGFS_MAGIC      0x62656570ULL
#define AL_FUSE_MAGIC          0x65735546ULL /* /run/user doc portals etc.  */

static __always_inline __u32 cur_tgid(void)
{
	return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

/* Non-sleepable programs: legacy helper returns the task as a u64. */
static __always_inline struct task_struct *cur_task(void)
{
	return (struct task_struct *)(unsigned long)bpf_get_current_task();
}

static __always_inline void bump_stat(__u32 type, bool dropped)
{
	struct event_counters *c;
	__u32 key = type;

	if (type >= EVENT_MAX)
		return;
	c = bpf_map_lookup_elem(&stats, &key);
	if (!c)
		return;
	if (dropped)
		__sync_fetch_and_add(&c->ringbuf_drops, 1);
	else
		__sync_fetch_and_add(&c->emitted, 1);
}

static __always_inline struct agentloupe_counters *counters_ptr(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&counters, &zero);
}

static __always_inline bool cfg_enabled(__u32 which)
{
	struct agentloupe_config *cfg;
	__u32 zero = 0;

	cfg = bpf_map_lookup_elem(&config_map, &zero);
	if (!cfg)
		return false;
	if (which == 1)
		return cfg->enable_syscall_summary != 0;
	if (which == 2)
		return cfg->enable_file_io_accounting != 0;
	if (which == 3)
		return cfg->enable_file_mutations != 0;
	return false;
}

/* PID of the thread group as seen inside its own PID namespace.
 * pid->numbers[pid->level].nr; level is clamped to the architectural max
 * (MAX_PID_NS_LEVEL == 4). Falls back to the host TGID on any read error. */
static __always_inline __u32 task_pid_in_ns(struct task_struct *task, __u32 fallback)
{
	struct pid *pid;
	unsigned int level;
	__s32 nr = 0;

	if (!task)
		return fallback;
	pid = BPF_CORE_READ(task, thread_pid);
	if (!pid)
		return fallback;
	level = BPF_CORE_READ(pid, level);
	if (level > 3)
		return fallback;
	/* Variable-index CO-RE array read: address arithmetic + probe read. */
	if (bpf_probe_read_kernel(&nr, sizeof(nr),
				  (const void *)&pid->numbers[level].nr) < 0)
		return fallback;
	return nr > 0 ? (__u32)nr : fallback;
}

static __always_inline __u32 task_ppid(struct task_struct *task)
{
	if (!task)
		return 0;
	return BPF_CORE_READ(task, real_parent, tgid);
}

/* ---- Sessions ------------------------------------------------------------ */

static __always_inline __u64 alloc_session_id(void)
{
	__u32 zero = 0;
	__u64 *next = bpf_map_lookup_elem(&session_counter, &zero);

	if (!next) {
		struct agentloupe_counters *c = counters_ptr();
		if (c)
			__sync_fetch_and_add(&c->session_allocs_failed, 1);
		return 0;
	}
	/* Counter is seeded (run_id << 32); pre-increment keeps 0 invalid. */
	return __sync_fetch_and_add(next, 1) + 1;
}

static __always_inline bool load_session_info(__u64 sid, struct session_info *out)
{
	struct session_info *info = bpf_map_lookup_elem(&sessions, &sid);

	if (!info)
		return false;
	*out = *info;
	return true;
}

/*
 * Core scope check on an already-known TGID.
 * Returns the session state (SESSION_STATE_*) and fills sid/info when a
 * session exists, or SESSION_STATE_UNKNOWN when out of scope. REJECTED is
 * returned as out of scope by in_scope() below but visible to callers that
 * need to distinguish (fork must not propagate it).
 */
static __always_inline __u32 scope_lookup(__u32 tgid, __u64 *sid_out,
					  struct session_info *info_out)
{
	struct tracked_session *tr;
	__u64 sid;

	tr = bpf_map_lookup_elem(&tracked_sessions, &tgid);
	if (!tr)
		return SESSION_STATE_UNKNOWN;
	sid = tr->session_id;
	if (!load_session_info(sid, info_out))
		return SESSION_STATE_UNKNOWN; /* inconsistent: treat as out */
	if (sid_out)
		*sid_out = sid;
	return info_out->state;
}

/* In-scope iff tracked and state is PROVISIONAL or CONFIRMED. */
static __always_inline bool in_scope(__u32 tgid, __u64 *sid_out,
				     struct session_info *info_out)
{
	__u32 st = scope_lookup(tgid, sid_out, info_out);

	return st == SESSION_STATE_PROVISIONAL || st == SESSION_STATE_CONFIRMED;
}

/* Lightweight variant for hot paths that need only the session_id:
 * reads the state field in place, never copies session_info (an 88-byte
 * stack copy the byte-accounting path cannot afford). */
static __always_inline bool tracked_sid(__u32 tgid, __u64 *sid_out)
{
	struct tracked_session *tr;
	struct session_info *info;
	__u32 state;

	tr = bpf_map_lookup_elem(&tracked_sessions, &tgid);
	if (!tr)
		return false;
	info = bpf_map_lookup_elem(&sessions, &tr->session_id);
	if (!info)
		return false;
	state = info->state;
	if (state != SESSION_STATE_PROVISIONAL && state != SESSION_STATE_CONFIRMED)
		return false;
	if (sid_out)
		*sid_out = tr->session_id;
	return true;
}

/* Packed so create_session stays within the 5-argument BPF-to-BPF call
 * limit and can be a real subprogram (__noinline) instead of being
 * inlined — and its verifier cost paid — at every call site. */
struct create_session_args {
	struct task_struct *task;
	const struct agent_ref *ref;
	__u64 parent_sid;
	__u64 cgroup_id;
	__u32 state;
	__u32 flags;
};

/*
 * Create a session for tgid. Writes sessions first, then tracked_sessions;
 * on tracked failure the sessions entry is rolled back so no orphan state
 * remains. Returns the new session_id, or 0 on failure (counter bumped).
 */
static __noinline __u64
create_session(__u32 tgid, const struct create_session_args *a)
{
	struct session_info info = {};
	struct tracked_session tr = {};
	struct agentloupe_counters *c;
	/* Hoist a->task into a task_struct-typed local BEFORE any CO-RE
	 * access: a CO-RE relocation rooted at `a` would reference our
	 * program-local create_session_args type, which does not exist in
	 * kernel BTF and fails relocation (poisoned instruction). Plain
	 * loads from `a` (our own stack struct) need no relocation. */
	struct task_struct *task = a->task;
	const struct agent_ref *ref = a->ref;
	__u64 sid = alloc_session_id();

	if (!sid)
		return 0;
	info.state = a->state;
	info.agent_id = ref ? ref->rule_id : 0;
	info.parent_session_id = a->parent_sid;
	info.cgroup_id = a->cgroup_id;
	info.start_ts_ns = bpf_ktime_get_ns();
	info.flags = a->flags;
	info.root_tgid = tgid;
	if (ref)
		__builtin_memcpy(info.agent_name, ref->agent_name, AGENT_NAME_LEN);
	if (task)
		BPF_CORE_READ_STR_INTO(&info.root_comm, task, comm);
	else
		bpf_get_current_comm(&info.root_comm, sizeof(info.root_comm));

	if (bpf_map_update_elem(&sessions, &sid, &info, BPF_ANY) < 0) {
		c = counters_ptr();
		if (c)
			__sync_fetch_and_add(&c->sessions_updates_failed, 1);
		return 0;
	}
	tr.session_id = sid;
	if (bpf_map_update_elem(&tracked_sessions, &tgid, &tr, BPF_ANY) < 0) {
		bpf_map_delete_elem(&sessions, &sid);
		c = counters_ptr();
		if (c)
			__sync_fetch_and_add(&c->tracked_updates_failed, 1);
		return 0;
	}
	return sid;
}

/*
 * Full scope resolution for event probes: tracked first; on a miss, one
 * agent_cgroups lookup, creating a CONFIRMED service session on a match.
 * An untracked, unmatched process costs exactly two lookups here.
 * cgroup_id is returned either way (needed for event headers).
 */
static __always_inline bool
resolve_scope(__u32 tgid, struct task_struct *task, __u64 *sid_out,
	      struct session_info *info_out, __u64 *cgroup_out)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	struct agent_ref *ref;

	if (cgroup_out)
		*cgroup_out = cgid;
	if (in_scope(tgid, sid_out, info_out))
		return true;
	ref = bpf_map_lookup_elem(&agent_cgroups, &cgid);
	if (!ref)
		return false;
	{
		struct create_session_args a = {
			.task = task, .ref = ref,
			.parent_sid = 0, .cgroup_id = cgid,
			.state = SESSION_STATE_CONFIRMED,
			.flags = SESSION_F_FROM_CGROUP,
		};

		*sid_out = create_session(tgid, &a);
	}
	if (!*sid_out)
		return false;
	return load_session_info(*sid_out, info_out);
}

/* ---- Event emission ------------------------------------------------------ */

static __always_inline void
fill_hdr(struct event_hdr *hdr, __u32 type, __u32 total_len, __u64 sid,
	 const struct session_info *info, struct task_struct *task, __u32 tgid)
{
	__builtin_memset(hdr, 0, sizeof(*hdr));
	hdr->type = (__u16)type;
	hdr->size = (__u16)total_len;
	hdr->version = AGENTLOUPE_ABI_VERSION;
	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->session_id = sid;
	if (info) {
		hdr->parent_session_id = info->parent_session_id;
		hdr->cgroup_id = info->cgroup_id;
		if (info->state == SESSION_STATE_PROVISIONAL)
			hdr->flags |= EVENT_F_PROVISIONAL;
	} else {
		hdr->cgroup_id = bpf_get_current_cgroup_id();
	}
	hdr->tgid = tgid;
	hdr->pid = tgid;
	hdr->uid = (__u32)bpf_get_current_uid_gid();
	if (task) {
		hdr->pid = task_pid_in_ns(task, tgid);
		hdr->ppid = task_ppid(task);
		BPF_CORE_READ_STR_INTO(&hdr->comm, task, comm);
	} else {
		bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
	}
}

/* Reserve a record. Caller fills the payload at (hdr + 1), then submits
 * with bpf_ringbuf_submit(hdr, 0). NULL => drop already counted. */
static __always_inline struct event_hdr *
reserve_event(__u32 type, __u32 total_len, __u64 sid,
	      const struct session_info *info, struct task_struct *task, __u32 tgid)
{
	struct event_hdr *hdr = bpf_ringbuf_reserve(&events, total_len, 0);

	if (!hdr) {
		bump_stat(type, true);
		return NULL;
	}
	__builtin_memset(hdr, 0, total_len);
	fill_hdr(hdr, type, total_len, sid, info, task, tgid);
	return hdr;
}

static __always_inline void submit_event(struct event_hdr *hdr, __u32 type)
{
	bump_stat(type, false);
	bpf_ringbuf_submit(hdr, 0);
}

/* ---- Path resolution ----------------------------------------------------- */

static __always_inline bool is_pseudo_magic(__u64 magic)
{
	switch (magic) {
	case AL_PROC_SUPER_MAGIC:
	case AL_SYSFS_MAGIC:
	case AL_CGROUP2_MAGIC:
	case AL_CGROUP_MAGIC:
	case AL_DEBUG_MAGIC:
	case AL_TRACEFS_MAGIC:
	case AL_DEVPTS_MAGIC:
	case AL_BPF_FS_MAGIC:
	case AL_SECURITYFS_MAGIC:
	case AL_PSTORE_MAGIC:
	case AL_CONFIGFS_MAGIC:
	case AL_FUSE_MAGIC:
		return true;
	default:
		return false;
	}
}

static __always_inline bool file_is_pseudo(struct file *f)
{
	struct inode *inode;
	__u64 magic;

	if (!f)
		return true; /* unknown file: do not create attribution state */
	inode = BPF_CORE_READ(f, f_inode);
	if (!inode)
		return true;
	magic = BPF_CORE_READ(inode, i_sb, s_magic);
	return is_pseudo_magic(magic);
}

/* bpf_d_path variant — LSM programs ONLY (see header note). Returns the
 * path_source for the payload; sets *partial on truncation/failure. */
static __always_inline __u8 path_via_dpath(struct path *p, char *out, bool *partial)
{
	long n = bpf_d_path(p, out, MAX_PATH_LEN);

	if (n < 0) {
		out[0] = '\0';
		*partial = true;
		return PATH_SRC_NONE;
	}
	if (n >= MAX_PATH_LEN)
		*partial = true;
	return PATH_SRC_D_PATH;
}

/*
 * Bounded dentry walk into out[MAX_PATH_LEN]. Components are staged
 * backwards in per-CPU scratch, then copied out. Returns PATH_SRC_DENTRY_WALK
 * (or PATH_SRC_NONE when there is nothing to walk); *partial is set on
 * depth/name/length overflow. Mount roots terminate the walk (see header).
 *
 * Deliberately __noinline with plain bounded loops: inlining this twice
 * into the exec program (filename + cwd) with unrolled loops blew the
 * verifier's 1M processed-instruction limit. As a subprogram it is
 * verified once; masked indices keep every access provably in range
 * inside loop bodies.
 */
static __noinline __u8 path_via_walk(struct dentry *dentry, char *out, bool *partial)
{
	struct path_scratch *s;
	struct dentry *cur = dentry;
	__u32 zero = 0;
	int pos = MAX_PATH_LEN;
	int i;

	out[0] = '\0';
	if (!cur)
		return PATH_SRC_NONE;
	s = bpf_map_lookup_elem(&path_scratch_map, &zero);
	if (!s)
		return PATH_SRC_NONE;
	__builtin_memset(s->buf, 0, sizeof(s->buf));

	for (i = 0; i < DENTRY_WALK_MAX_DEPTH; i++) {
		struct dentry *parent;
		const unsigned char *name;
		long len, n;
		int j, start;

		if (!cur)
			break;
		parent = BPF_CORE_READ(cur, d_parent);
		if (!parent || parent == cur)
			break; /* filesystem root */
		name = BPF_CORE_READ(cur, d_name.name);
		len = BPF_CORE_READ(cur, d_name.len);
		if (!name || len <= 0)
			break;
		if (len >= DENTRY_WALK_MAX_NAME) {
			*partial = true;
			len = DENTRY_WALK_MAX_NAME - 1;
		}
		n = bpf_probe_read_kernel_str(s->comp, DENTRY_WALK_MAX_NAME, name);
		if (n <= 0)
			break;
		if (n - 1 < len)
			len = n - 1;
		if (pos < (int)len + 1) {
			*partial = true;
			break;
		}
		pos -= (int)len;
		start = pos;
		for (j = 0; j < DENTRY_WALK_MAX_NAME && j < len; j++)
			s->buf[(start + j) & (MAX_PATH_LEN - 1)] =
				s->comp[j & (DENTRY_WALK_MAX_NAME - 1)];
		pos -= 1;
		if (pos < 0) {
			*partial = true;
			pos = 0;
			break;
		}
		s->buf[pos & (MAX_PATH_LEN - 1)] = '/';
		cur = parent;
	}
	if (i >= DENTRY_WALK_MAX_DEPTH && cur) {
		struct dentry *parent = BPF_CORE_READ(cur, d_parent);
		if (parent && parent != cur)
			*partial = true; /* stopped by depth, not by root */
	}

	if (pos >= MAX_PATH_LEN) { /* nothing walked: root itself */
		out[0] = '/';
		out[1] = '\0';
		return PATH_SRC_DENTRY_WALK;
	}
	for (i = 0; i < MAX_PATH_LEN; i++) {
		int src = pos + i;

		if (src >= MAX_PATH_LEN)
			break;
		out[i & (MAX_PATH_LEN - 1)] = s->buf[src & (MAX_PATH_LEN - 1)];
	}
	if (pos == 0)
		*partial = true; /* leading components were dropped */
	out[MAX_PATH_LEN - 1] = '\0';
	return PATH_SRC_DENTRY_WALK;
}

static __always_inline __u8 file_path_via_walk(struct file *f, char *out, bool *partial)
{
	struct dentry *dentry;

	if (!f)
		return PATH_SRC_NONE;
	dentry = BPF_CORE_READ(f, f_path.dentry);
	return path_via_walk(dentry, out, partial);
}

/* Read the linear argv area (mm->arg_start..arg_end holds NUL-separated
 * strings) into dst[MAX_ARGV_LEN]. argc is NOT counted in-kernel: the
 * 256-byte NUL scan cost verifier budget in the exec programs and
 * userspace recovers argc exactly from the parsed argv it already
 * builds (argc field in the payload is left 0). argc_out is kept only
 * so the payload layout/call site stay stable.
 * __noinline: keeps its copy loop out of the exec programs' inline body. */
static __noinline void read_argv(struct task_struct *task, char *dst, __u32 *argc_out)
{
	struct mm_struct *mm;
	unsigned long start, end, len;

	*argc_out = 0;
	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return;
	start = BPF_CORE_READ(mm, arg_start);
	end = BPF_CORE_READ(mm, arg_end);
	if (!start || end <= start)
		return;
	len = end - start;
	if (len > MAX_ARGV_LEN - 2)
		len = MAX_ARGV_LEN - 2;
	bpf_probe_read_user(dst, (__u32)len, (const void *)(unsigned long)start);
}

#endif /* AGENTLOUPE_SCOPE_H */
