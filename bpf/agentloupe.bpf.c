/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * agentloupe.bpf.c — AgentLoupe MVP probes (single translation unit).
 *
 * OBSERVE ONLY. Every LSM hook in this file returns 0 unconditionally on
 * every path: a non-zero return from a BPF LSM hook DENIES the operation.
 * There must never be a code path here that returns anything else.
 *
 * Attach model (loader chooses per feature probe, never both of a pair):
 *   exec:    lsm.s/bprm_committed_creds  (preferred; sleepable, bpf_d_path)
 *            raw_tp/sched_process_exec   (fallback; dentry-walk paths)
 *   file:    lsm/file_open, lsm/path_*, lsm/file_free_security (preferred)
 *            raw_tp/sys_{enter,exit}     (fallback; RAW_ARG paths)
 *   io acct: fexit/vfs_read, vfs_write, vfs_readv, vfs_writev
 *   net:     kprobe/tcp_v4_connect + tcp_v6_connect (default), or
 *            tp/syscalls/sys_enter_connect (adds UDP, loses result)
 *   syscall summary (optional): raw_tp/sys_enter
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "agentloupe.h"
#include "scope.h"

/* AF_* are macros in kernel headers, not BTF, so vmlinux.h does not
 * provide them in BPF compilation units. Values are ABI-stable. */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Zero templates in .bss: large value structs must not be initialised on
 * the 512-byte BPF stack. Passed by pointer to bpf_map_update_elem. */
static struct fd_info zero_fd_info;
static struct pending_file_op zero_pending;

/* ======================================================================
 * Process lifecycle: fork / exec / exit
 * ==================================================================== */

/*
 * Shared exec core used by both exec hooks. Decides session membership,
 * reserves the EXEC record and fills everything except filename/cwd
 * (which differ per hook: bpf_d_path vs dentry walk). Returns the payload
 * for the caller to complete and submit, plus the exe file pointer.
 * Keeping path code OUT of this function is what allows it to be shared:
 * bpf_d_path in a subprogram would poison the tracepoint caller.
 *
 * __noinline: inlining this into both exec hooks (each with its own
 * session-creation branches and 88-byte session_info copies) blew the
 * verifier's 1M processed-instruction limit on handle_exec_tp. As a
 * subprogram it is verified once. Four arguments — within the 5-arg
 * BPF-to-BPF call limit.
 */
static __noinline struct ev_exec *
exec_core(struct task_struct *task, struct linux_binprm *bprm,
	  struct file **file_out, struct event_hdr **hdr_out)
{
	struct session_info info = {};
	struct ev_exec *ev;
	struct event_hdr *hdr;
	struct file *file = NULL;
	struct inode *inode = NULL;
	__u64 sid = 0, parent_sid = 0, cgid = 0;
	__u64 parent_cgid;
	__u32 tgid = cur_tgid();
	bool provisional = false, have_session;

	*file_out = NULL;
	*hdr_out = NULL;

	if (bprm)
		file = BPF_CORE_READ(bprm, file);
	if (!file) {
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		if (mm)
			file = BPF_CORE_READ(mm, exe_file);
	}
	*file_out = file;
	if (file)
		inode = BPF_CORE_READ(file, f_inode);

	have_session = in_scope(tgid, &sid, &info);
	if (have_session)
		parent_sid = sid;

	/* Binary identity match. */
	if (inode) {
		struct binary_id key = {};
		struct agent_ref *bin_ref;
		struct agentloupe_counters *dc;

		key.ino = BPF_CORE_READ(inode, i_ino);
		key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
		dc = counters_ptr();
		if (dc) {
			dc->exec_last_dev = key.dev;
			dc->exec_last_ino = key.ino;
		}
		bin_ref = bpf_map_lookup_elem(&agent_binaries, &key);
		if (bin_ref) {
			/* A matched tool exec always starts a child session,
			 * even inside an existing (e.g. cgroup) session. */
			struct create_session_args a = {
				.task = task, .ref = bin_ref,
				.parent_sid = have_session ? parent_sid : 0,
				.cgroup_id = bpf_get_current_cgroup_id(),
				.state = SESSION_STATE_CONFIRMED,
				.flags = SESSION_F_FROM_BINARY,
			};

			sid = create_session(tgid, &a);
			if (!sid)
				return NULL;
			goto emit;
		}
		bin_ref = bpf_map_lookup_elem(&candidates, &key);
		if (bin_ref && !have_session) {
			/* Interpreter: provisional until userspace confirms
			 * from argv. Flag cgroup origin if the interpreter
			 * was exec'd from inside a tracked cgroup. */
			bool cg = false;

			parent_cgid = bpf_get_current_cgroup_id();
			if (bpf_map_lookup_elem(&agent_cgroups, &parent_cgid))
				cg = true;
			{
				struct create_session_args a = {
					.task = task, .ref = bin_ref,
					.parent_sid = 0, .cgroup_id = parent_cgid,
					.state = SESSION_STATE_PROVISIONAL,
					.flags = SESSION_F_PROVISIONAL | SESSION_F_INTERPRETER |
						 (cg ? SESSION_F_FROM_CGROUP : 0),
				};

				sid = create_session(tgid, &a);
			}
			if (!sid)
				return NULL;
			provisional = true;
			goto emit;
		}
		if (dc)
			__sync_fetch_and_add(&dc->exec_binary_miss, 1);
	} else {
		struct agentloupe_counters *dc = counters_ptr();

		if (dc)
			__sync_fetch_and_add(&dc->exec_no_file, 1);
	}

	if (!have_session) {
		/* Last chance: cgroup-matched service exec'ing something. */
		if (!resolve_scope(tgid, task, &sid, &info, &cgid)) {
			struct agentloupe_counters *c = counters_ptr();

			if (c)
				__sync_fetch_and_add(&c->exec_out_of_scope, 1);
			return NULL; /* not an agent action */
		}
	} else if (info.state == SESSION_STATE_PROVISIONAL) {
		provisional = true;
	}

emit:
	if (!load_session_info(sid, &info))
		return NULL;
	hdr = reserve_event(EVENT_EXEC, EVLEN_EXEC, sid, &info, task, tgid);
	if (!hdr)
		return NULL;
	ev = (struct ev_exec *)(void *)(hdr + 1);
	read_argv(task, bprm, ev->argv, &ev->argc);
	/* Audit identity: fields exist only under CONFIG_AUDIT; CO-RE field
	 * existence keeps this portable. INVALID_UID => loader falls back
	 * to hdr.uid. */
	ev->audit_loginuid = INVALID_UID;
	ev->audit_sessionid = 0;
	if (bpf_core_field_exists(((struct task_struct *)0)->loginuid))
		ev->audit_loginuid = BPF_CORE_READ(task, loginuid.val);
	if (bpf_core_field_exists(((struct task_struct *)0)->sessionid))
		ev->audit_sessionid = BPF_CORE_READ(task, sessionid);
	if (provisional)
		hdr->flags |= EVENT_F_PROVISIONAL;
	*hdr_out = hdr;
	return ev;
	(void)cgid;
}

/* Preferred exec hook: sleepable LSM, runs after creds are committed, so
 * bprm->file is the NEW image's. Note the hook fires (via
 * install_exec_creds in begin_new_exec) BEFORE setup_arg_pages, so
 * mm->arg_start/arg_end are not set yet — read_argv uses bprm->p.
 * bpf_d_path is allowlisted here. */
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(handle_bprm_committed_creds, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct event_hdr *hdr = NULL;
	struct ev_exec *ev;
	struct file *file = NULL;
	bool partial = false;
	struct agentloupe_counters *c = counters_ptr();

	if (c)
		__sync_fetch_and_add(&c->exec_hook_runs, 1);
	ev = exec_core(task, bprm, &file, &hdr);
	if (!ev)
		return 0;
	{
		/* bpf_d_path needs a pointer to a live kernel struct path
		 * reached via a trusted pointer: re-derive it from the hook
		 * argument. A BPF_CORE_READ stack copy is type=fp and newer
		 * verifiers reject it as the bpf_d_path argument.
		 * task->mm->exe_file and task->fs are __rcu fields, so a
		 * direct read of them yields untrusted_ptr_ and is rejected
		 * the same way; when bprm->file is unavailable, and for the
		 * cwd, fall back to the dentry walk used by the tracepoint
		 * hook (cwd is then PATH_SRC_DENTRY_WALK: best-effort). */
		struct file *f = bprm->file;

		if (f)
			ev->filename_src = path_via_dpath((struct path *)&f->f_path, ev->filename, &partial);
		else if (file)
			ev->filename_src = file_path_via_walk(file, ev->filename, &partial);
	}
	{
		struct dentry *pwd_dentry = BPF_CORE_READ(task, fs, pwd.dentry);

		ev->cwd_src = path_via_walk(pwd_dentry, ev->cwd, &partial);
	}
	if (partial)
		hdr->flags |= EVENT_F_PATH_PARTIAL;
	submit_event(hdr, EVENT_EXEC);
	return 0; /* observe only */
}

/* Fallback exec hook. sched_process_exec raw args: (task_struct *p,
 * u32 old_pid, linux_binprm *bprm) — args[0] is the first argument. */
struct exec_raw_args {
	__u64 args[3];
};

SEC("raw_tp/sched_process_exec")
int handle_exec_tp(struct exec_raw_args *ctx)
{
	struct task_struct *task = (struct task_struct *)(unsigned long)ctx->args[0];
	struct linux_binprm *bprm = (struct linux_binprm *)(unsigned long)ctx->args[2];
	struct event_hdr *hdr = NULL;
	struct ev_exec *ev;
	struct file *file = NULL;
	struct dentry *pwd_dentry;
	bool partial = false;
	struct agentloupe_counters *c = counters_ptr();

	if (c)
		__sync_fetch_and_add(&c->exec_hook_runs, 1);
	ev = exec_core(task, bprm, &file, &hdr);
	if (!ev)
		return 0;
	if (file)
		ev->filename_src = file_path_via_walk(file, ev->filename, &partial);
	pwd_dentry = BPF_CORE_READ(task, fs, pwd.dentry);
	ev->cwd_src = path_via_walk(pwd_dentry, ev->cwd, &partial);
	if (partial)
		hdr->flags |= EVENT_F_PATH_PARTIAL;
	submit_event(hdr, EVENT_EXEC);
	return 0;
}

struct fork_raw_args {
	__u64 args[2]; /* (task_struct *parent, task_struct *child) */
};

SEC("raw_tp/sched_process_fork")
int handle_fork(struct fork_raw_args *ctx)
{
	struct task_struct *parent = (struct task_struct *)(unsigned long)ctx->args[0];
	struct task_struct *child = (struct task_struct *)(unsigned long)ctx->args[1];
	struct session_info info = {};
	struct tracked_session tr = {};
	struct event_hdr *hdr;
	struct ev_fork *ev;
	__u32 ptgid, ctgid;
	__u64 sid = 0;

	ptgid = BPF_CORE_READ(parent, tgid);
	ctgid = BPF_CORE_READ(child, tgid);
	if (!ptgid || !ctgid || ptgid == ctgid)
		return 0; /* new thread, or unreadable: nothing to propagate */

	if (!in_scope(ptgid, &sid, &info)) {
		/* Parent may be an undiscovered cgroup service member. */
		__u64 cgid = 0;

		if (!resolve_scope(ptgid, parent, &sid, &info, &cgid))
			return 0;
		/* resolve_scope created the session on the PARENT; fall through */
	}
	/* REJECTED never reaches here: in_scope() excludes it, so a rejected
	 * provisional subtree stops growing at this hook. */
	tr.session_id = sid;
	if (bpf_map_update_elem(&tracked_sessions, &ctgid, &tr, BPF_ANY) < 0) {
		struct agentloupe_counters *c = counters_ptr();
		if (c)
			__sync_fetch_and_add(&c->tracked_updates_failed, 1);
		return 0;
	}
	hdr = reserve_event(EVENT_FORK, EVLEN_FORK, sid, &info, parent, ptgid);
	if (!hdr)
		return 0;
	ev = (struct ev_fork *)(void *)(hdr + 1);
	ev->child_tgid = ctgid;
	ev->child_pid = task_pid_in_ns(child, ctgid);
	submit_event(hdr, EVENT_FORK);
	return 0;
}

struct exit_raw_args {
	__u64 args[1]; /* (task_struct *p) */
};

SEC("raw_tp/sched_process_exit")
int handle_exit(struct exit_raw_args *ctx)
{
	struct task_struct *task = (struct task_struct *)(unsigned long)ctx->args[0];
	struct session_info info = {};
	struct event_hdr *hdr;
	struct ev_exit *ev;
	__u32 tgid, pid;
	__u64 sid = 0;

	/* sched_process_exit fires per thread; only the leader's exit ends
	 * the tracked entry. */
	pid = BPF_CORE_READ(task, pid);
	tgid = BPF_CORE_READ(task, tgid);
	if (!tgid || pid != tgid)
		return 0;
	if (in_scope(tgid, &sid, &info)) {
		hdr = reserve_event(EVENT_EXIT, EVLEN_EXIT, sid, &info, task, tgid);
		if (hdr) {
			struct signal_struct *signal;

			ev = (struct ev_exit *)(void *)(hdr + 1);
			ev->exit_code = BPF_CORE_READ(task, exit_code);
			if (ev->exit_code != 0)
				hdr->flags |= EVENT_F_ERROR;
			/*
			 * Per-process CPU + peak RSS for the exiting thread
			 * group. This is the short-lived-tool counterpart of
			 * the /proc-sampled session-root CPU on session_end:
			 * sampled here, in-kernel, the process cannot outrun
			 * it, and every tracked TGID gets numbers, not just
			 * session roots.
			 *
			 * CPU: signal->utime/stime hold the cputime of group
			 * threads that have ALREADY exited (a dead thread's
			 * task cputime is folded into its signal_struct during
			 * teardown); the exiting leader's own has not been
			 * folded in yet at this tracepoint, so add
			 * task->utime/stime. signal->cutime/cstime are
			 * deliberately NOT added: those are reaped CHILDREN
			 * (wait4 rusage), and every child tool emits its own
			 * exit event with its own numbers — adding them here
			 * would double-count and make the parent's number
			 * "inclusive" instead of "self". Caveats: threads of
			 * the group still alive when the leader exits are not
			 * summed (that would need a thread-list walk; their
			 * later exits emit no exit event, pid != tgid), so for
			 * multithreaded processes this is leader + already-dead
			 * threads — exact for the single-threaded tools that
			 * dominate agent process trees.
			 *
			 * Units: task/signal utime+stime are __u64 NANOSECONDS
			 * on every supported kernel (the cputime-to-nsecs
			 * conversion predates the 5.8 floor) — unlike
			 * /proc/<pid>/stat fields 14/15, which are USER_HZ
			 * ticks and must NOT be used to rescale these.
			 *
			 * Peak RSS: signal->maxrss, not mm->hiwater_rss. By
			 * the time sched_process_exit fires, do_exit() has
			 * already run exit_mm(): task->mm may be NULL and the
			 * mm may be gone, but exit_mm() folds the mm's
			 * hiwater into signal->maxrss (setmax_mm_hiwater_rss)
			 * and signal_struct lives until the group is reaped,
			 * so it is the source that is valid at this hook. It
			 * is already stored in KiB (the kernel does the
			 * pages->KiB conversion), so no PAGE_SHIFT assumption
			 * (4K/16K/64K arm64) is needed here. Like the CPU
			 * fields it is a thread-GROUP figure (threads share
			 * one mm), in KiB; 0 if the task never had an mm.
			 *
			 * Cost: one pointer chase + five scalar CO-RE reads,
			 * no loops, no extra stack — handle_exit is shared by
			 * the LSM and tracepoint-fallback probe sets and must
			 * stay well inside the fallback's verifier budget.
			 */
			signal = BPF_CORE_READ(task, signal);
			if (signal) {
				ev->cpu_user_ns = BPF_CORE_READ(signal, utime) +
						  BPF_CORE_READ(task, utime);
				ev->cpu_sys_ns = BPF_CORE_READ(signal, stime) +
						 BPF_CORE_READ(task, stime);
				ev->max_rss_kb = BPF_CORE_READ(signal, maxrss);
			}
			submit_event(hdr, EVENT_EXIT);
		}
	}
	/* Delete even when the session was REJECTED mid-flight (in_scope is
	 * false then): stale entries must not survive their process. The
	 * sessions entry itself is userspace's to retire (children may
	 * still reference it). */
	bpf_map_delete_elem(&tracked_sessions, &tgid);
	return 0;
}

/* ======================================================================
 * Files: LSM hooks (preferred)
 * ==================================================================== */

static __always_inline struct fd_info *
file_info_create(__u64 file_ptr, struct file *f, __u64 sid, __u32 tgid,
		 __u32 open_flags, const char *path, __u8 path_src)
{
	struct fd_info *info;
	struct inode *inode;
	int i;

	if (bpf_map_update_elem(&file_infos, &file_ptr, &zero_fd_info, BPF_NOEXIST) < 0) {
		/* Already known (e.g. created lazily by vfs hooks): reuse. */
		return bpf_map_lookup_elem(&file_infos, &file_ptr);
	}
	info = bpf_map_lookup_elem(&file_infos, &file_ptr);
	if (!info) {
		struct agentloupe_counters *c = counters_ptr();
		if (c)
			__sync_fetch_and_add(&c->file_info_updates_failed, 1);
		return NULL;
	}
#pragma unroll
	for (i = 0; i < MAX_PATH_LEN; i++)
		info->path[i] = path[i];
	info->session_id = sid;
	info->open_ts_ns = bpf_ktime_get_ns();
	info->opener_tgid = tgid;
	info->flags = open_flags;
	info->path_src = path_src;
	inode = BPF_CORE_READ(f, f_inode);
	if (inode) {
		info->ino = BPF_CORE_READ(inode, i_ino);
		info->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	}
	return info;
}

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
	struct session_info info = {};
	struct event_hdr *hdr;
	struct ev_file_open *ev;
	__u64 sid = 0, cgid = 0;
	__u32 tgid = cur_tgid();
	bool partial = false;

	if (!resolve_scope(tgid, cur_task(), &sid, &info, &cgid))
		return 0;
	hdr = reserve_event(EVENT_FILE_OPEN, EVLEN_FILE_OPEN, sid, &info,
			    cur_task(), tgid);
	if (!hdr)
		return 0;
	ev = (struct ev_file_open *)(void *)(hdr + 1);
	ev->file_ptr = (unsigned long)file;
	ev->flags = BPF_CORE_READ(file, f_flags);
	ev->path_src = path_via_dpath((struct path *)&file->f_path, ev->path, &partial);
	if (partial)
		hdr->flags |= EVENT_F_PATH_PARTIAL;
	/* Create fd attribution BEFORE submit_event: submitting hands the
	 * ring-buffer record to the kernel, after which ev must not be
	 * dereferenced (the verifier invalidates the pointer on submit —
	 * and rightly so: userspace may already be reading the record). */
	if (!file_is_pseudo(file))
		file_info_create((unsigned long)file, file, sid, tgid,
				 ev->flags, ev->path, ev->path_src);
	submit_event(hdr, EVENT_FILE_OPEN);
	return 0; /* observe only */
}

SEC("lsm/path_unlink")
int BPF_PROG(handle_path_unlink, const struct path *path, struct dentry *dentry)
{
	struct session_info info = {};
	struct event_hdr *hdr;
	struct ev_file_unlink *ev;
	__u64 sid = 0, cgid = 0;
	__u32 tgid = cur_tgid();
	bool partial = false;

	if (!resolve_scope(tgid, cur_task(), &sid, &info, &cgid))
		return 0;
	hdr = reserve_event(EVENT_FILE_UNLINK, EVLEN_FILE_UNLINK, sid, &info,
			    cur_task(), tgid);
	if (!hdr)
		return 0;
	ev = (struct ev_file_unlink *)(void *)(hdr + 1);
	/* No live struct path names the victim (the hook's path is the
	 * parent directory), and a fabricated stack copy cannot be given
	 * to bpf_d_path — walk the victim dentry instead. */
	ev->path_src = path_via_walk(dentry, ev->path, &partial);
	if (partial)
		hdr->flags |= EVENT_F_PATH_PARTIAL;
	submit_event(hdr, EVENT_FILE_UNLINK);
	return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(handle_path_rename, const struct path *old_path, struct dentry *old_dentry,
	     const struct path *new_path, struct dentry *new_dentry, unsigned int flags)
{
	struct session_info info = {};
	struct event_hdr *hdr;
	struct ev_file_rename *ev;
	__u64 sid = 0, cgid = 0;
	__u32 tgid = cur_tgid();
	bool partial = false;

	if (!resolve_scope(tgid, cur_task(), &sid, &info, &cgid))
		return 0;
	hdr = reserve_event(EVENT_FILE_RENAME, EVLEN_FILE_RENAME, sid, &info,
			    cur_task(), tgid);
	if (!hdr)
		return 0;
	ev = (struct ev_file_rename *)(void *)(hdr + 1);
	/* As in path_unlink: walk the dentries; no fabricated struct path. */
	ev->old_path_src = path_via_walk(old_dentry, ev->old_path, &partial);
	ev->new_path_src = path_via_walk(new_dentry, ev->new_path, &partial);
	if (partial)
		hdr->flags |= EVENT_F_PATH_PARTIAL;
	submit_event(hdr, EVENT_FILE_RENAME);
	return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(handle_path_chmod, const struct path *path, umode_t mode)
{
	struct session_info info = {};
	struct event_hdr *hdr;
	struct ev_file_chmod *ev;
	__u64 sid = 0, cgid = 0;
	__u32 tgid = cur_tgid();
	bool partial = false;

	if (!resolve_scope(tgid, cur_task(), &sid, &info, &cgid))
		return 0;
	hdr = reserve_event(EVENT_FILE_CHMOD, EVLEN_FILE_CHMOD, sid, &info,
			    cur_task(), tgid);
	if (!hdr)
		return 0;
	ev = (struct ev_file_chmod *)(void *)(hdr + 1);
	ev->mode = mode;
	ev->path_src = path_via_dpath((struct path *)path, ev->path, &partial);
	if (partial)
		hdr->flags |= EVENT_F_PATH_PARTIAL;
	submit_event(hdr, EVENT_FILE_CHMOD);
	return 0;
}

/* Final release of a struct file. Attribution comes from fd_info, never
 * from `current`: __fput may run deferred in a kworker, and
 * file_free_security inherits that context. */
SEC("lsm/file_free_security")
int BPF_PROG(handle_file_free_security, struct file *file)
{
	struct session_info info = {};
	struct fd_info *fi;
	struct event_hdr *hdr;
	struct ev_file_close *ev;
	__u64 key = (unsigned long)file;
	int i;

	fi = bpf_map_lookup_elem(&file_infos, &key);
	if (!fi)
		return 0;
	/* Skip emission for rejected sessions: userspace already discarded
	 * their buffered events; a lone CLOSE would be an orphan. */
	if (load_session_info(fi->session_id, &info) &&
	    info.state != SESSION_STATE_REJECTED) {
		hdr = reserve_event(EVENT_FILE_CLOSE, EVLEN_FILE_CLOSE,
				    fi->session_id, &info, NULL, fi->opener_tgid);
		if (hdr) {
			ev = (struct ev_file_close *)(void *)(hdr + 1);
#pragma unroll
			for (i = 0; i < MAX_PATH_LEN; i++)
				ev->path[i] = fi->path[i];
			ev->file_ptr = key;
			ev->read_bytes = fi->read_bytes;
			ev->write_bytes = fi->write_bytes;
			ev->open_ts_ns = fi->open_ts_ns;
			ev->path_src = fi->path_src;
			submit_event(hdr, EVENT_FILE_CLOSE);
		}
	}
	bpf_map_delete_elem(&file_infos, &key);
	return 0;
}

/* ======================================================================
 * Files: syscall tracepoint fallback (no BPF LSM)
 *
 * sys_enter records the op + raw user path for in-scope processes only;
 * sys_exit emits with the real result and, for openat, creates file_infos
 * keyed by the struct file * recovered from the task's fd table.
 * ==================================================================== */

struct sys_enter_ctx {
	__u64 unused;
	long id;
	unsigned long args[6];
};

struct sys_exit_ctx {
	__u64 unused;
	long id;
	long ret;
};

static __always_inline int
pending_begin(__u32 op, const char *user_path, const char *user_path2, __u32 flags)
{
	struct pending_file_op *p;
	struct session_info info = {};
	__u64 key = bpf_get_current_pid_tgid();
	__u64 sid = 0, cgid = 0;
	struct agentloupe_counters *ec = counters_ptr();

	if (ec)
		__sync_fetch_and_add(&ec->file_pending_stored, 1);
	if (!resolve_scope(cur_tgid(), cur_task(), &sid, &info, &cgid))
		return 0;
	if (bpf_map_update_elem(&pending_file_ops, &key, &zero_pending, BPF_ANY) < 0)
		return 0;
	p = bpf_map_lookup_elem(&pending_file_ops, &key);
	if (!p)
		return 0;
	p->op = op;
	p->flags = flags;
	p->path_src = PATH_SRC_RAW_ARG;
	if (user_path)
		bpf_probe_read_user_str(p->path, sizeof(p->path), user_path);
	if (user_path2)
		bpf_probe_read_user_str(p->path2, sizeof(p->path2), user_path2);
	return 0;
}

static __always_inline struct file *task_file_from_fd(struct task_struct *task, int fd)
{
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fds, *f = NULL;
	unsigned int max_fds;

	if (fd < 0)
		return NULL;
	files = BPF_CORE_READ(task, files);
	if (!files)
		return NULL;
	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return NULL;
	max_fds = BPF_CORE_READ(fdt, max_fds);
	if ((unsigned int)fd >= max_fds || fd > 4096)
		return NULL;
	fds = BPF_CORE_READ(fdt, fd);
	if (!fds)
		return NULL;
	bpf_probe_read_kernel(&f, sizeof(f), (const void *)&fds[fd]);
	return f;
}

/* Socket type (SOCK_STREAM/SOCK_DGRAM/...) for an fd of the current task,
 * or -1 if the fd is not a socket. Used to keep UDP connects visible when
 * TCP is already covered by the tcp_* fexit probes. */
static __always_inline int socket_type_from_fd(int fd)
{
	struct file *f = task_file_from_fd(cur_task(), fd);
	struct inode *inode;
	void *priv;
	short type = -1;

	if (!f)
		return -1;
	inode = BPF_CORE_READ(f, f_inode);
	if (!inode)
		return -1;
	if ((BPF_CORE_READ(inode, i_mode) & 0170000) != 0140000) /* S_IFSOCK */
		return -1;
	priv = BPF_CORE_READ(f, private_data);
	if (!priv)
		return -1;
	if (bpf_core_read(&type, sizeof(type),
			  &((struct socket *)priv)->type) < 0)
		return -1;
	return (int)type;
}

static __always_inline int pending_finish(long ret, __u32 op)
{
	struct session_info info = {};
	struct pending_file_op *p;
	__u64 key = bpf_get_current_pid_tgid();
	__u64 sid = 0;
	__u32 tgid = cur_tgid();

	p = bpf_map_lookup_elem(&pending_file_ops, &key);
	if (!p || (op && p->op != op))
		return 0;
	op = p->op; /* raw_tp sys_exit does not say which syscall: use stored */
	{
		struct agentloupe_counters *c = counters_ptr();

		if (c)
			__sync_fetch_and_add(&c->file_pending_matched, 1);
	}
	if (!in_scope(tgid, &sid, &info)) {
		bpf_map_delete_elem(&pending_file_ops, &key);
		return 0;
	}

	if (op == EVENT_FILE_OPEN) {
		struct event_hdr *hdr = reserve_event(EVENT_FILE_OPEN, EVLEN_FILE_OPEN,
						      sid, &info, cur_task(), tgid);
		struct file *f = NULL;

		if (ret >= 0)
			f = task_file_from_fd(cur_task(), (int)ret);
		if (hdr) {
			struct ev_file_open *ev = (struct ev_file_open *)(void *)(hdr + 1);
			int i;

#pragma unroll
			for (i = 0; i < MAX_PATH_LEN; i++)
				ev->path[i] = p->path[i];
			ev->flags = p->flags;
			ev->result = ret < 0 ? (__s32)ret : 0;
			ev->file_ptr = (unsigned long)f;
			ev->path_src = PATH_SRC_RAW_ARG;
			if (p->path[0] != '/') /* relative: resolution unknown */
				hdr->flags |= EVENT_F_PATH_PARTIAL;
			if (ret < 0)
				hdr->flags |= EVENT_F_ERROR;
			submit_event(hdr, EVENT_FILE_OPEN);
		}
		if (f && !file_is_pseudo(f))
			file_info_create((unsigned long)f, f, sid, tgid,
					 p->flags, p->path, PATH_SRC_RAW_ARG);
	} else if (op == EVENT_FILE_UNLINK) {
		struct event_hdr *hdr = reserve_event(EVENT_FILE_UNLINK, EVLEN_FILE_UNLINK,
						      sid, &info, cur_task(), tgid);
		if (hdr) {
			struct ev_file_unlink *ev = (struct ev_file_unlink *)(void *)(hdr + 1);
			int i;
#pragma unroll
			for (i = 0; i < MAX_PATH_LEN; i++)
				ev->path[i] = p->path[i];
			ev->result = (__s32)ret;
			ev->path_src = PATH_SRC_RAW_ARG;
			if (p->path[0] != '/')
				hdr->flags |= EVENT_F_PATH_PARTIAL;
			if (ret < 0)
				hdr->flags |= EVENT_F_ERROR;
			submit_event(hdr, EVENT_FILE_UNLINK);
		}
	} else if (op == EVENT_FILE_RENAME) {
		struct event_hdr *hdr = reserve_event(EVENT_FILE_RENAME, EVLEN_FILE_RENAME,
						      sid, &info, cur_task(), tgid);
		if (hdr) {
			struct ev_file_rename *ev = (struct ev_file_rename *)(void *)(hdr + 1);
			int i;
#pragma unroll
			for (i = 0; i < MAX_PATH_LEN; i++) {
				ev->old_path[i] = p->path[i];
				ev->new_path[i] = p->path2[i];
			}
			ev->result = (__s32)ret;
			ev->old_path_src = PATH_SRC_RAW_ARG;
			ev->new_path_src = PATH_SRC_RAW_ARG;
			if (p->path[0] != '/' || p->path2[0] != '/')
				hdr->flags |= EVENT_F_PATH_PARTIAL;
			if (ret < 0)
				hdr->flags |= EVENT_F_ERROR;
			submit_event(hdr, EVENT_FILE_RENAME);
		}
	} else if (op == EVENT_FILE_CHMOD) {
		struct event_hdr *hdr = reserve_event(EVENT_FILE_CHMOD, EVLEN_FILE_CHMOD,
						      sid, &info, cur_task(), tgid);
		if (hdr) {
			struct ev_file_chmod *ev = (struct ev_file_chmod *)(void *)(hdr + 1);
			int i;
#pragma unroll
			for (i = 0; i < MAX_PATH_LEN; i++)
				ev->path[i] = p->path[i];
			ev->mode = p->flags;
			ev->result = (__s32)ret;
			ev->path_src = PATH_SRC_RAW_ARG;
			if (p->path[0] != '/')
				hdr->flags |= EVENT_F_PATH_PARTIAL;
			if (ret < 0)
				hdr->flags |= EVENT_F_ERROR;
			submit_event(hdr, EVENT_FILE_CHMOD);
		}
	}
	bpf_map_delete_elem(&pending_file_ops, &key);
	return 0;
}

/*
 * File-op fallback hooks: raw tracepoints, NOT tp/syscalls. The classic
 * syscall tracepoints are attached via per-CPU perf events, which proved
 * unreliable here (events silently delivered on a subset of CPUs); raw
 * tracepoints fire on every CPU. sys_enter/sys_exit raw tracepoint args
 * are (pt_regs *, long id_or_ret) — only two arguments; syscall arguments
 * are read from pt_regs (x86_64: di, si, dx, r10).
 */
#ifndef NR_openat
#define NR_openat 257
#define NR_unlinkat 263
#define NR_renameat 264
#define NR_fchmodat 268
#define NR_renameat2 316
#define NR_openat2 437
#endif

struct sys_raw_args {
	__u64 args[2]; /* (struct pt_regs *regs, long id_or_ret) */
};

SEC("raw_tp/sys_enter")
int handle_file_sys_enter(struct sys_raw_args *ctx)
{
	struct pt_regs *regs = (struct pt_regs *)(unsigned long)ctx->args[0];
	long nr = (long)ctx->args[1];
	const char *path, *path2;
	__u64 si, dx, r10;

	if (!regs)
		return 0;
	switch (nr) {
	case NR_openat:
	case NR_openat2:
	case NR_unlinkat:
	case NR_renameat:
	case NR_renameat2:
	case NR_fchmodat:
		break;
	default:
		return 0;
	}
	if (nr != NR_openat && nr != NR_openat2 && !cfg_enabled(3))
		return 0; /* file mutations are opt-in */
	si = BPF_CORE_READ(regs, si);
	dx = BPF_CORE_READ(regs, dx);
	path = (const char *)(unsigned long)si;
	switch (nr) {
	case NR_openat:
		return pending_begin(EVENT_FILE_OPEN, path, NULL, (__u32)dx);
	case NR_openat2:
		/* flags live in struct open_how (user ptr at dx), not a scalar */
		return pending_begin(EVENT_FILE_OPEN, path, NULL, 0);
	case NR_unlinkat:
		return pending_begin(EVENT_FILE_UNLINK, path, NULL, 0);
	case NR_renameat:
	case NR_renameat2:
		r10 = BPF_CORE_READ(regs, r10);
		path2 = (const char *)(unsigned long)r10;
		return pending_begin(EVENT_FILE_RENAME, path, path2, 0);
	case NR_fchmodat:
		return pending_begin(EVENT_FILE_CHMOD, path, NULL, (__u32)dx);
	}
	return 0;
}

SEC("raw_tp/sys_exit")
int handle_file_sys_exit(struct sys_raw_args *ctx)
{
	return pending_finish((long)ctx->args[1], 0);
}

/* ======================================================================
 * File I/O byte accounting: fexit on vfs_read/vfs_write{,v}
 *
 * fexit sees the file argument AND the return value, so no in-flight map
 * is needed. Hot path (fires for ALL host I/O): one file_infos lookup;
 * on a miss, one tracked_sessions lookup via scope check, then out.
 * The Stage 3 gate for enabling this by default is `make bench-io`.
 * ==================================================================== */

static __always_inline void account_io(struct file *file, long ret, bool is_write)
{
	struct fd_info *info;
	__u64 key = (unsigned long)file;

	if (ret <= 0)
		return;
	/* Hot path: exactly one lookup for an already-attributed file, and
	 * one lookup + one scope check for everything else on the host. */
	info = bpf_map_lookup_elem(&file_infos, &key);
	if (!info) {
		/* Lazy creation for files opened before tracking/inherited:
		 * in scope, on a real filesystem, path via dentry walk.
		 * The path is staged in the per-CPU scratch buffer, NOT on
		 * the stack: a 256-byte array here blew the 512-byte BPF
		 * stack limit for the fexit programs. path_via_walk uses
		 * the same scratch as its assembly buffer; copying the
		 * result onto itself is safe (destination offset < source
		 * offset throughout the copy). */
		struct path_scratch *scratch;
		struct fd_info *created;
		__u64 sid = 0;
		__u32 zero = 0;
		bool partial = false;
		__u8 src;

		if (!cfg_enabled(2))
			return;
		if (!tracked_sid(cur_tgid(), &sid) || file_is_pseudo(file))
			return;
		scratch = bpf_map_lookup_elem(&path_scratch_map, &zero);
		if (!scratch)
			return;
		src = file_path_via_walk(file, scratch->buf, &partial);
		created = file_info_create(key, file, sid, cur_tgid(), 0,
					   scratch->buf, src);
		if (!created)
			return;
		info = created;
	}
	if (!cfg_enabled(2))
		return;
	if (is_write)
		__sync_fetch_and_add(&info->write_bytes, (__u64)ret);
	else
		__sync_fetch_and_add(&info->read_bytes, (__u64)ret);
}

SEC("fexit/vfs_read")
int BPF_PROG(handle_vfs_read, struct file *file, char *buf, size_t count,
	     loff_t *pos, ssize_t ret)
{
	account_io(file, (long)ret, false);
	return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(handle_vfs_write, struct file *file, const char *buf, size_t count,
	     loff_t *pos, ssize_t ret)
{
	account_io(file, (long)ret, true);
	return 0;
}

SEC("fexit/vfs_readv")
int BPF_PROG(handle_vfs_readv, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, rwf_t flags, ssize_t ret)
{
	account_io(file, (long)ret, false);
	return 0;
}

SEC("fexit/vfs_writev")
int BPF_PROG(handle_vfs_writev, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, rwf_t flags, ssize_t ret)
{
	account_io(file, (long)ret, true);
	return 0;
}

/* ======================================================================
 * Network
 * ==================================================================== */

static __always_inline void
emit_net_connect(struct sock *sk, __u32 result, bool have_result)
{
	struct session_info info = {};
	struct event_hdr *hdr;
	struct ev_net_connect *ev;
	__u64 sid = 0, cgid = 0;
	__u32 tgid = cur_tgid();
	__u16 family;

	if (!resolve_scope(tgid, cur_task(), &sid, &info, &cgid))
		return;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return;
	hdr = reserve_event(EVENT_NET_CONNECT, EVLEN_NET_CONNECT, sid, &info,
			    cur_task(), tgid);
	if (!hdr)
		return;
	ev = (struct ev_net_connect *)(void *)(hdr + 1);
	ev->family = family;
	ev->protocol = IPPROTO_TCP;
	ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (family == AF_INET) {
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

		__builtin_memcpy(ev->daddr, &daddr, 4);
		__builtin_memcpy(ev->saddr, &saddr, 4);
	} else {
		struct in6_addr daddr6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
		struct in6_addr saddr6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);

		__builtin_memcpy(ev->daddr, &daddr6, 16);
		__builtin_memcpy(ev->saddr, &saddr6, 16);
	}
	ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (ev->dport == 53)
		ev->flags |= 1; /* DNS */
	ev->result = have_result ? (__s32)result : 0;
	submit_event(hdr, EVENT_NET_CONNECT);
}

/* fexit, not an entry kprobe: at exit the sock's destination fields are
 * populated and the real result is available. An entry probe sees
 * skc_daddr/skc_dport still zeroed. */
SEC("fexit/tcp_v4_connect")
int BPF_PROG(handle_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr,
	     int addr_len, int ret)
{
	(void)uaddr;
	(void)addr_len;
	emit_net_connect(sk, (__u32)ret, true);
	return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(handle_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr,
	     int addr_len, int ret)
{
	(void)uaddr;
	(void)addr_len;
	emit_net_connect(sk, (__u32)ret, true);
	return 0;
}

/* Syscall network probe: parses the userspace sockaddr at enter.
 * Always attached by the loader. When the tcp_* fexit probes are live
 * the loader sets config net_udp_only and this emits SOCK_DGRAM only
 * (no TCP double-report); otherwise it emits every connect. */
SEC("tp/syscalls/sys_enter_connect")
int handle_enter_connect(struct sys_enter_ctx *ctx)
{
	struct session_info info = {};
	struct event_hdr *hdr;
	struct ev_net_connect *ev;
	unsigned char sa[28] = {};
	__u64 sid = 0, cgid = 0;
	__u32 tgid = cur_tgid();
	__u16 family;

	if (!resolve_scope(tgid, cur_task(), &sid, &info, &cgid))
		return 0;
	/* When the TCP fexit probes are attached the loader sets net_udp_only:
	 * emit SOCK_DGRAM only, so TCP is not double-reported. Otherwise
	 * (fallback) emit every connect, tagged with its protocol. */
	{
		int stype = socket_type_from_fd((int)ctx->args[0]);

		if (cfg_enabled(4)) {
			if (stype != 2) /* SOCK_DGRAM */
				return 0;
		}
		if (bpf_probe_read_user(sa, sizeof(sa), (const void *)ctx->args[1]) < 0)
			return 0;
		family = (__u16)sa[0] | ((__u16)sa[1] << 8);
		if (family != AF_INET && family != AF_INET6)
			return 0;
		hdr = reserve_event(EVENT_NET_CONNECT, EVLEN_NET_CONNECT, sid, &info,
				    cur_task(), tgid);
		if (!hdr)
			return 0;
		ev = (struct ev_net_connect *)(void *)(hdr + 1);
		ev->family = family;
		ev->protocol = (stype == 2) ? 17 : 6; /* IPPROTO_UDP / TCP */
		if (family == AF_INET) {
			/* sockaddr_in: port at 2 (BE), addr at 4 */
			ev->dport = ((__u16)sa[2] << 8) | sa[3];
			__builtin_memcpy(ev->daddr, &sa[4], 4);
		} else {
			/* sockaddr_in6: port at 2 (BE), addr at 8 */
			ev->dport = ((__u16)sa[2] << 8) | sa[3];
			__builtin_memcpy(ev->daddr, &sa[8], 16);
		}
		if (ev->dport == 53)
			ev->flags |= 1; /* DNS */
	}
	submit_event(hdr, EVENT_NET_CONNECT);
	return 0;
}

/* ======================================================================
 * Optional syscall summary: counts only, aggregated per (session, nr).
 * ==================================================================== */

struct sys_enter_raw_args {
	__u64 args[2]; /* (struct pt_regs *regs, long id) */
};

SEC("raw_tp/sys_enter")
int handle_sys_enter_count(struct sys_enter_raw_args *ctx)
{
	struct session_info info = {};
	struct syscall_key key = {};
	__u64 sid = 0;
	__u64 *count;

	if (!cfg_enabled(1))
		return 0;
	if (!in_scope(cur_tgid(), &sid, &info))
		return 0;
	key.session_id = sid;
	key.tgid = cur_tgid();
	key.syscall_nr = (__u32)ctx->args[1];
	count = bpf_map_lookup_elem(&syscall_counts, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 one = 1;

		if (bpf_map_update_elem(&syscall_counts, &key, &one, BPF_NOEXIST) < 0) {
			struct agentloupe_counters *c = counters_ptr();
			if (c)
				__sync_fetch_and_add(&c->syscall_updates_failed, 1);
		}
	}
	return 0;
}
