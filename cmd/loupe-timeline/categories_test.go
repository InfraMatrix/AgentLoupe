package main

import "testing"

func TestSyscallCategory(t *testing.T) {
	cases := map[string]string{
		"openat":         "file",
		"open":           "file", // amd64-only name, same table
		"read":           "file",
		"unlinkat":       "file",
		"renameat2":      "file",
		"execve":         "process",
		"clone3":         "process",
		"setresuid":      "process",
		"connect":        "network",
		"accept4":        "network",
		"mmap":           "memory",
		"madvise":        "memory",
		"futex":          "sync/wait",
		"epoll_pwait":    "sync/wait",
		"futex_time64":   "sync/wait", // arm64 32-bit time variant
		"rt_sigaction":   "signals",
		"clock_gettime":  "time",
		"timer_create":   "time",
		"bpf":            "other",
		"getrandom":      "other",
		"sys_9999":       "other",
		"never_heard_of": "other",
	}
	for name, want := range cases {
		if got := SyscallCategory(name); got != want {
			t.Errorf("SyscallCategory(%q) = %q, want %q", name, got, want)
		}
	}
	if !HiddenCategories["memory"] || !HiddenCategories["sync/wait"] || HiddenCategories["file"] {
		t.Errorf("hidden-by-default categories = %v", HiddenCategories)
	}
}

func TestNotableSyscalls(t *testing.T) {
	for _, n := range []string{"execve", "connect", "bind", "listen", "accept", "unlink", "unlinkat",
		"rename", "renameat", "renameat2", "chmod", "fchmodat2", "chown", "fchownat",
		"ptrace", "setuid", "setgid", "capset", "mount", "umount2", "bpf", "kill", "tgkill",
		"init_module", "finit_module"} {
		if !isNotable(n) {
			t.Errorf("%q should be notable", n)
		}
	}
	for _, n := range []string{"read", "mmap", "futex", "openat"} {
		if isNotable(n) {
			t.Errorf("%q should not be notable", n)
		}
	}
}
