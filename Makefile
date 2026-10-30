# AgentLoupe — build orchestration.
#
# Canonical targets:
#   make build        Compile the BPF object, then build ./agentloupe.
#   make bpf          Compile bpf/agentloupe.bpf.c -> bpf/agentloupe.bpf.o (CO-RE).
#   make test         Unit tests only: no kernel, no root (go test ./...).
#   make integration  Real-kernel integration test. Run as: sudo make integration
#   make demo         One-command live demo (scripts/demo.sh): builds, runs
#                     the loader with configs/loupe-demo.yaml, runs the demo
#                     workload, renders scorecard/timeline/HTML. Prompts for
#                     sudo once.
#
# Supporting targets:
#   make check        Header ABI asserts + LSM return-0 safety checks +
#                     tracked-files hygiene (no home paths / captures).
#   make vmlinux.h    Regenerate bpf/vmlinux.h from the RUNNING kernel's BTF.
#                     Run this on the target kernel, not blindly on a dev host.
#   make vet          go vet ./...
#   make bench-io     Plan/target stub: fexit vfs_* overhead benchmark.
#   make clean        Remove build artifacts.
#
# There is intentionally no code-generation target: the loader consumes the
# compiled BPF object directly via cilium/ebpf (ebpf.LoadCollectionSpec), so
# no bpf2go bindings are generated or committed.

GO      ?= go
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -Wall -Werror -Wno-missing-declarations -target bpf -D__TARGET_ARCH_$(ARCH) -I bpf -I /usr/include/$(shell uname -m)-linux-gnu
CLANG   ?= clang
BPFTOOL ?= bpftool

.PHONY: build
build: bpf
	$(GO) build -o agentloupe ./cmd/agentloupe

bpf/agentloupe.bpf.o: bpf/agentloupe.bpf.c bpf/agentloupe.h bpf/scope.h bpf/vmlinux.h check-lsm-returns
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

.PHONY: bpf
bpf: bpf/agentloupe.bpf.o

.PHONY: test
test:
	$(GO) test ./...

# Integration runs the real-kernel test as root. It deliberately does
# NOT depend on `build`: run `make build` as your normal user first, so
# no build artifact (bpf object, binary) is ever created root-owned.
# The test itself fails with that instruction if the object is missing.
.PHONY: integration
integration:
	$(GO) test -tags integration -count=1 -v -run TestIntegration ./internal/app/

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: demo
demo:
	bash scripts/demo.sh

.PHONY: clean
clean:
	rm -f agentloupe bpf/agentloupe.bpf.o

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

.PHONY: check-tracked-files
check-tracked-files:
	python3 scripts/check_tracked_files.py

.PHONY: check
check: check-header check-lsm-returns check-lsm-returns-selftest check-tracked-files

.PHONY: vmlinux.h
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Stage 3 gate: measure fexit/vfs_read{,v} + vfs_write{,v} overhead host-wide
# under a fio-style I/O load with the hooks attached but no tracked agents,
# to prove the in_scope() early-exit keeps untracked I/O overhead negligible.
.PHONY: bench-io
bench-io:
	@echo "bench-io: implemented in Stage 3 (test/bench/io_overhead.sh) — required before enabling enable_file_io_accounting by default"
