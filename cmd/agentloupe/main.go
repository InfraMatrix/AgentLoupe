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
	"syscall"
	"time"

	"github.com/inframatrix/agentloupe/internal/app"
)

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
	flag.Parse()

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
