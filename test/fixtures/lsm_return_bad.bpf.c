/* Self-test fixture for scripts/check_lsm_returns.py — DO NOT COMPILE OR LOAD.
 *
 * This file intentionally contains an LSM program that can return -EPERM.
 * The checker MUST reject this file. If it ever passes, the checker is
 * broken and `make check-lsm-returns-selftest` fails.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("lsm/file_open")
int BPF_PROG(bad_file_open, struct file *file)
{
	if (!file)
		return -EPERM; /* violation: an LSM hook must never deny */
	return 0;
}

SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(bad_bprm, struct linux_binprm *bprm)
{
	return -1; /* violation */
}
