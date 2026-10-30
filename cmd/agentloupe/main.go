// AgentLoupe dev-mode loader. Observe-only eBPF agent observability.
//
// Dev-mode guarantees:
//   - Nothing is ever pinned in bpffs; programs and links exist only as
//     file descriptors in this process, so exit, SIGINT/SIGTERM, or even
//     SIGKILL detaches everything (the kernel closes the fds).
//   - Clean shutdown on SIGINT/SIGTERM; --max-runtime bounds a run.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/InfraMatrix/AgentLoupe/internal/app"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

type multiInt []int

func (m *multiInt) String() string { return fmt.Sprint([]int(*m)) }
func (m *multiInt) Set(v string) error {
	var n int
	if _, err := fmt.Sscan(v, &n); err != nil {
		return err
	}
	*m = append(*m, n)
	return nil
}

func main() {
	var o app.Options
	var maxRuntime time.Duration
	flag.StringVar(&o.BPFObject, "bpf-object", "bpf/agentloupe.bpf.o", "compiled CO-RE object")
	flag.StringVar(&o.ConfigPath, "config", "/etc/agentloupe/agents.yaml", "agents.yaml path")
	flag.StringVar(&o.Output, "output", "-", "JSONL output: file path or - for stdout")
	flag.DurationVar(&maxRuntime, "max-runtime", 0, "stop automatically after this duration (0 = run until signal)")
	flag.BoolVar(&o.EnableIOAccounting, "enable-io-accounting", false, "opt-in: fexit vfs_read/vfs_write{,v} byte accounting + file_close events (benchmark first: make bench-io)")
	flag.BoolVar(&o.EnableSyscallSummary, "enable-syscall-summary", false, "opt-in: per-(session, syscall) counts via raw_tp/sys_enter")
	flag.BoolVar(&o.EnableFileMutations, "enable-file-mutations", false, "opt-in: unlink/rename/chmod events (default probes are process, file-open, network only)")
	flag.DurationVar(&o.StatsInterval, "stats-interval", 10*time.Second, "how often to print drop/map-full counters (0 = only on shutdown)")
	flag.DurationVar(&o.SyscallInterval, "syscall-interval", time.Second, "how often to emit syscall_summary JSONL events (deltas; requires --enable-syscall-summary; 0 = only final flush on session end/shutdown)")
	flag.DurationVar(&o.OrphanTimeout, "orphan-timeout", 3*time.Minute, "how long a session stays open after its root exits while tracked child processes remain alive; on expiry session_end is emitted with reason orphan_timeout (0 = wait indefinitely)")
	flag.BoolVar(&o.ForceTracepointMode, "force-tracepoint-mode", false, "force the tracepoint-fallback probe set even when BPF LSM is available (for rehearsing/testing the fallback path)")
	var dropPrefixes, attachComms, attachExes, catalogOnly multiFlag
	var attachPIDs multiInt
	flag.Var(&dropPrefixes, "drop-path-prefix", "drop file events whose path has this prefix (repeatable; e.g. /proc/)")
	flag.Var(&attachPIDs, "attach-pid", "adopt this already-running PID and its children (repeatable)")
	flag.Var(&attachComms, "attach-comm", "adopt running processes with this comm/exe basename (repeatable)")
	flag.Var(&attachExes, "attach-exe", "adopt running processes whose /proc/<pid>/exe matches this path or glob (repeatable)")
	flag.BoolVar(&o.UseCatalog, "catalog", false, "enable the built-in catalog of known agent harnesses")
	flag.Var(&catalogOnly, "catalog-only", "enable only this catalog entry (repeatable; implies --catalog)")
	flag.Parse()
	o.DropPathPrefixes = dropPrefixes
	o.AttachPIDs = attachPIDs
	o.AttachComms = attachComms
	o.AttachExes = attachExes
	o.CatalogOnly = catalogOnly

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if maxRuntime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxRuntime)
		defer cancel()
	}

	if err := app.Run(ctx, o); err != nil {
		fmt.Fprintf(os.Stderr, "agentloupe: fatal: %v\n", err)
		os.Exit(1)
	}
}
