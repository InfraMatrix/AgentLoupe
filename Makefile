# AgentLoupe — build orchestration.
#
# Targets:
#   make check-header  Compile-check bpf/agentloupe.h (incl. _Static_asserts)
#                      with a host compiler. No kernel, libbpf, or root needed.
#   make vmlinux.h     Regenerate bpf/vmlinux.h from the RUNNING kernel's BTF.
#                      Run this on the target/VM kernel, not blindly on a dev host.
#   make bpf           Compile bpf/agentloupe.bpf.c -> bpf/agentloupe.bpf.o (CO-RE).
#   make generate      Run bpf2go to regenerate the Go bindings (Stage 3).
#   make loader        Build the Go loader (Stage 3).
#   make bench-io      Plan/target stub: fexit vfs_* overhead benchmark (Stage 3 gate).

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -Wall -Werror -Wno-missing-declarations -target bpf -D__TARGET_ARCH_$(ARCH) -I bpf -I /usr/include/$(shell uname -m)-linux-gnu
CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: check-header
check-header:
	@printf '%s\n' \
	  'typedef unsigned char __u8; typedef unsigned short __u16;' \
	  'typedef unsigned int __u32; typedef unsigned long long __u64;' \
	  'typedef signed char __s8; typedef short __s16; typedef int __s32; typedef long long __s64;' \
	  '#define __uint(n, v) int _u_##n' \
	  '#define __type(n, v) int _t_##n' \
	  '#define SEC(x)' \
	  '#define BPF_MAP_TYPE_HASH 1' '#define BPF_MAP_TYPE_LRU_HASH 2' \
	  '#define BPF_MAP_TYPE_ARRAY 3' '#define BPF_MAP_TYPE_PERCPU_ARRAY 4' \
	  '#define BPF_MAP_TYPE_RINGBUF 5' \
	  '#include "agentloupe.h"' \
	  'int main(void) { return 0; }' > /tmp/agentloupe_header_check.c
	$(CLANG) -std=c11 -Wall -Wextra -Werror -I bpf -fsyntax-only /tmp/agentloupe_header_check.c
	@echo "check-header: OK (all _Static_asserts hold)"

.PHONY: check-lsm-returns
check-lsm-returns:
	python3 scripts/check_lsm_returns.py bpf/agentloupe.bpf.c

# Proof the checker catches the bad case, not just that it runs: it must
# REJECT the -EPERM fixture and ACCEPT the real source.
.PHONY: check-lsm-returns-selftest
check-lsm-returns-selftest:
	@echo "selftest: checker must reject test/fixtures/lsm_return_bad.bpf.c ..."
	@if python3 scripts/check_lsm_returns.py test/fixtures/lsm_return_bad.bpf.c; then \
		echo "selftest: FAIL — checker accepted an LSM program returning -EPERM"; exit 1; \
	else \
		echo "selftest: OK — bad fixture rejected as expected"; \
	fi
	@echo "selftest: checker must accept bpf/agentloupe.bpf.c ..."
	python3 scripts/check_lsm_returns.py bpf/agentloupe.bpf.c
	@echo "check-lsm-returns-selftest: OK"

.PHONY: check
check: check-header check-lsm-returns check-lsm-returns-selftest

.PHONY: vmlinux.h
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

bpf/agentloupe.bpf.o: bpf/agentloupe.bpf.c bpf/agentloupe.h bpf/scope.h bpf/vmlinux.h check-lsm-returns
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

.PHONY: bpf
bpf: bpf/agentloupe.bpf.o

.PHONY: generate
generate:
	cd internal/loader && go generate ./...

.PHONY: loader
loader: bpf generate
	go build -o agentloupe ./cmd/agentloupe

# Stage 3 gate: measure fexit/vfs_read{,v} + vfs_write{,v} overhead host-wide
# under a fio-style I/O load with the hooks attached but no tracked agents,
# to prove the in_scope() early-exit keeps untracked I/O overhead negligible.
.PHONY: bench-io
bench-io:
	@echo "bench-io: implemented in Stage 3 (test/bench/io_overhead.sh) — required before enabling enable_file_io_accounting by default"
