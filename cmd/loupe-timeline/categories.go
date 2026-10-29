package main

import "strings"

// Syscall categorisation: ONE name-based table, applied to the syscall
// names the loader emits. Because it keys on names (not numbers), the
// same table serves amd64 and arm64 captures. Anything unlisted —
// including unknown "sys_<nr>" names — is "other".

// CategoryNames in display order.
var CategoryNames = []string{"process", "file", "network", "memory", "sync/wait", "signals", "time", "other"}

// HiddenCategories are excluded from the rate chart by default (runtime
// background noise); the page has a toggle to show them.
var HiddenCategories = map[string]bool{"memory": true, "sync/wait": true}

var categoryBySyscall = map[string]string{}

func reg(cat string, names ...string) {
	for _, n := range names {
		categoryBySyscall[n] = cat
	}
}

func init() {
	reg("process",
		"execve", "execveat", "clone", "clone3", "fork", "vfork",
		"exit", "exit_group", "kill", "tkill", "tgkill", "pidfd_send_signal",
		"wait4", "waitid", "ptrace", "unshare", "setns",
		"getpid", "gettid", "getppid", "getpgrp", "getpgid", "getsid",
		"setpgid", "setsid", "set_tid_address", "set_thread_area", "get_thread_area",
		// credentials / privilege (identity of the process)
		"getuid", "geteuid", "getgid", "getegid", "setuid", "setgid",
		"setreuid", "setregid", "setresuid", "getresuid", "setresgid", "getresgid",
		"setfsuid", "setfsgid", "getgroups", "setgroups", "capget", "capset",
		"personality", "prctl", "arch_prctl", "seccomp", "landlock_create_ruleset",
		"landlock_add_rule", "landlock_restrict_self", "set_robust_list", "get_robust_list")
	reg("file",
		"open", "openat", "openat2", "creat", "close", "close_range",
		"read", "write", "pread64", "pwrite64", "readv", "writev",
		"preadv", "pwritev", "preadv2", "pwritev2", "lseek", "sendfile",
		"splice", "tee", "vmsplice", "copy_file_range", "readahead", "fadvise64",
		"stat", "fstat", "lstat", "newfstatat", "statx", "statfs", "fstatfs",
		"access", "faccessat", "faccessat2", "ioctl", "fcntl", "flock",
		"unlink", "unlinkat", "rename", "renameat", "renameat2",
		"chmod", "fchmod", "fchmodat", "fchmodat2",
		"chown", "fchown", "lchown", "fchownat", "umask",
		"getdents", "getdents64", "getcwd", "chdir", "fchdir",
		"readlink", "readlinkat", "mkdir", "mkdirat", "rmdir",
		"link", "linkat", "symlink", "symlinkat",
		"truncate", "ftruncate", "fallocate", "fsync", "fdatasync", "sync", "syncfs",
		"dup", "dup2", "dup3", "pipe", "pipe2",
		"getxattr", "lgetxattr", "fgetxattr", "setxattr", "lsetxattr", "fsetxattr",
		"listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr",
		"setxattrat", "getxattrat", "listxattrat", "removexattrat",
		"utime", "utimes", "futimesat", "utimensat",
		"mknod", "mknodat", "inotify_init", "inotify_init1", "inotify_add_watch", "inotify_rm_watch",
		"fanotify_init", "fanotify_mark", "name_to_handle_at", "open_by_handle_at",
		// filesystem administration
		"mount", "umount", "umount2", "move_mount", "open_tree", "open_tree_attr",
		"fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
		"pivot_root", "chroot", "swapon", "swapoff", "ustat", "statmount", "listmount",
		"file_getattr", "file_setattr")
	reg("network",
		"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
		"sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
		"shutdown", "getsockname", "getpeername", "setsockopt", "getsockopt")
	reg("memory",
		"mmap", "munmap", "mprotect", "pkey_mprotect", "pkey_alloc", "pkey_free",
		"madvise", "process_madvise", "brk", "mremap", "msync", "mincore",
		"mlock", "munlock", "mlockall", "munlockall", "mlock2",
		"remap_file_pages", "mbind", "set_mempolicy", "get_mempolicy",
		"set_mempolicy_home_node", "move_pages", "migrate_pages",
		"shmget", "shmat", "shmctl", "shmdt", "memfd_create", "memfd_secret",
		"userfaultfd", "map_shadow_stack", "mseal", "cachestat")
	reg("sync/wait",
		"futex", "futex_wait", "futex_wake", "futex_requeue", "futex_waitv",
		"epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
		"epoll_wait", "epoll_wait_old", "epoll_pwait", "epoll_pwait2",
		"poll", "ppoll", "select", "pselect6", "nanosleep", "pause",
		"sched_yield", "restart_syscall", "eventfd", "eventfd2",
		"timerfd_create", "timerfd_settime", "timerfd_gettime",
		"io_uring_setup", "io_uring_enter", "io_uring_register",
		"io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "io_pgetevents",
		"semget", "semop", "semctl", "semtimedop",
		"msgget", "msgsnd", "msgrcv", "msgctl",
		"mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr")
	reg("signals",
		"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending",
		"rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "rt_tgsigqueueinfo",
		"sigaltstack", "signalfd", "signalfd4", "pidfd_open", "pidfd_getfd")
	reg("time",
		"time", "gettimeofday", "settimeofday", "times",
		"clock_gettime", "clock_settime", "clock_getres", "clock_nanosleep", "clock_adjtime",
		"adjtimex", "getitimer", "setitimer", "alarm",
		"timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete",
		"sched_rr_get_interval")
}

// SyscallCategory returns the display category for a syscall name.
func SyscallCategory(name string) string {
	if c, ok := categoryBySyscall[name]; ok {
		return c
	}
	// 32-bit time64 variants on arm64 share the base name's category.
	if b, ok := strings.CutSuffix(name, "_time64"); ok {
		if c, ok2 := categoryBySyscall[b]; ok2 {
			return c
		}
	}
	return "other"
}

// NotableSyscalls are always listed per session regardless of volume:
// process creation, network listeners, destructive/privileged operations.
var NotableSyscalls = map[string]bool{
	"execve": true, "execveat": true,
	"connect": true, "bind": true, "listen": true, "accept": true, "accept4": true,
	"unlink": true, "unlinkat": true,
	"rename": true, "renameat": true, "renameat2": true,
	"chmod": true, "fchmod": true, "fchmodat": true, "fchmodat2": true,
	"chown": true, "fchown": true, "lchown": true, "fchownat": true,
	"ptrace": true,
	"setuid": true, "setgid": true, "setreuid": true, "setregid": true,
	"setresuid": true, "setresgid": true, "setfsuid": true, "setfsgid": true,
	"capset": true,
	"mount":  true, "umount": true, "umount2": true,
	"bpf": true, "kill": true, "tkill": true, "tgkill": true,
	"init_module": true, "finit_module": true, "delete_module": true,
}

func isNotable(name string) bool { return NotableSyscalls[name] }
