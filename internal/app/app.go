package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/InfraMatrix/AgentLoupe/internal/config"
)

type Options struct {
	BPFObject            string
	ConfigPath           string
	Output               string
	EnableIOAccounting   bool
	EnableSyscallSummary bool
	EnableFileMutations  bool
	StatsInterval        time.Duration
	SyscallInterval      time.Duration
	// OrphanTimeout bounds how long a session stays open after its
	// root exits while tracked processes remain (0 = wait
	// indefinitely). See Processor.OrphanTimeout.
	OrphanTimeout    time.Duration
	DropPathPrefixes []string
	AttachPIDs       []int
	AttachComms      []string
	AttachExes       []string
	UseCatalog       bool
	CatalogOnly      []string
}

type progReq struct {
	Name   string // Go-visible program (function) name in the object
	Kind   string // raw_tp | tracepoint | kprobe | lsm | fexit
	Group  string // tracepoint group, when Kind == tracepoint
	Target string // symbol / tracepoint name
	Tag    string // core | mutation | io | syscall | netkprobe
}

func buildRequests(lsmMode bool, o Options) []progReq {
	reqs := []progReq{
		{Name: "handle_fork", Kind: "raw_tp", Target: "sched_process_fork", Tag: "core"},
		{Name: "handle_exit", Kind: "raw_tp", Target: "sched_process_exit", Tag: "core"},
	}
	if lsmMode {
		reqs = append(reqs,
			progReq{Name: "handle_bprm_committed_creds", Kind: "lsm", Tag: "core"},
			progReq{Name: "handle_file_open", Kind: "lsm", Tag: "core"},
			// Always: emits file_close with duration even when byte
			// accounting is off (counts stay zero).
			progReq{Name: "handle_file_free_security", Kind: "lsm", Tag: "core"})
	} else {
		reqs = append(reqs,
			progReq{Name: "handle_exec_tp", Kind: "raw_tp", Target: "sched_process_exec", Tag: "core"},
			progReq{Name: "handle_file_sys_enter", Kind: "raw_tp", Target: "sys_enter", Tag: "core"},
			progReq{Name: "handle_file_sys_exit", Kind: "raw_tp", Target: "sys_exit", Tag: "core"})
	}
	// Network: fexit on tcp_v4/v6_connect by default (destination fields
	// are populated and the result known at exit); sys_enter_connect is
	// loaded but left unattached as the fallback if fexit cannot attach.
	reqs = append(reqs,
		progReq{Name: "handle_tcp_v4_connect", Kind: "fexit", Target: "tcp_v4_connect", Tag: "netkprobe"},
		progReq{Name: "handle_tcp_v6_connect", Kind: "fexit", Target: "tcp_v6_connect", Tag: "netkprobe"})

	if o.EnableFileMutations {
		if lsmMode {
			reqs = append(reqs,
				progReq{Name: "handle_path_unlink", Kind: "lsm", Tag: "mutation"},
				progReq{Name: "handle_path_rename", Kind: "lsm", Tag: "mutation"},
				progReq{Name: "handle_path_chmod", Kind: "lsm", Tag: "mutation"})
		} else {
			// Tracepoint mode handles mutations inside
			// handle_file_sys_enter/exit (raw_tp sys_enter/exit,
			// already in core), gated by the enable_file_mutations
			// config flag — no extra programs to attach.
		}
	}
	if o.EnableIOAccounting {
		reqs = append(reqs,
			progReq{Name: "handle_vfs_read", Kind: "fexit", Target: "vfs_read", Tag: "io"},
			progReq{Name: "handle_vfs_write", Kind: "fexit", Target: "vfs_write", Tag: "io"},
			progReq{Name: "handle_vfs_readv", Kind: "fexit", Target: "vfs_readv", Tag: "io"},
			progReq{Name: "handle_vfs_writev", Kind: "fexit", Target: "vfs_writev", Tag: "io"})
	}
	if o.EnableSyscallSummary {
		reqs = append(reqs, progReq{Name: "handle_sys_enter_count", Kind: "raw_tp", Target: "sys_enter", Tag: "syscall"})
	}
	return reqs
}

func attachOne(coll *ebpf.Collection, r progReq) (link.Link, error) {
	prog := coll.Programs[r.Name]
	if prog == nil {
		return nil, fmt.Errorf("program %s not in object", r.Name)
	}
	switch r.Kind {
	case "raw_tp":
		return link.AttachRawTracepoint(link.RawTracepointOptions{Name: r.Target, Program: prog})
	case "tracepoint":
		return link.Tracepoint(r.Group, r.Target, prog, nil)
	case "kprobe":
		return link.Kprobe(r.Target, prog, nil)
	case "lsm":
		return link.AttachLSM(link.LSMOptions{Program: prog})
	case "fexit":
		return link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceFExit})
	}
	return nil, fmt.Errorf("unknown attach kind %q", r.Kind)
}

type loadAttempt struct {
	label     string
	keepTag   map[string]bool
	tpNetwork bool
}

// loadCollection tries progressively smaller program sets so one bad
// optional probe (e.g. a vfs_readv prototype mismatch) cannot take down
// the core pipeline. Maps are never pinned (PinPath is never set):
// closing the collection — on exit, crash or SIGKILL — detaches
// everything, because links and programs live only as file descriptors
// in this process.
func loadCollection(object string, reqs []progReq, logf func(string, ...any)) (*ebpf.Collection, []progReq, string, error) {
	attempts := []loadAttempt{
		{"full requested set", nil, false},
		{"without syscall summary", map[string]bool{"core": true, "mutation": true, "io": true, "netkprobe": true}, false},
		{"without io accounting or syscall summary", map[string]bool{"core": true, "mutation": true, "netkprobe": true}, false},
		{"core + network kprobes only", map[string]bool{"core": true, "netkprobe": true}, false},
		{"core only, tracepoint network", map[string]bool{"core": true}, true},
	}
	for _, att := range attempts {
		var use []progReq
		loadNames := map[string]bool{}
		for _, r := range reqs {
			if att.keepTag != nil && !att.keepTag[r.Tag] {
				continue
			}
			use = append(use, r)
			loadNames[r.Name] = true
		}
		if att.tpNetwork {
			use = append(use, progReq{Name: "handle_enter_connect", Kind: "tracepoint", Group: "syscalls", Target: "sys_enter_connect", Tag: "core"})
			loadNames["handle_enter_connect"] = true
		} else {
			loadNames["handle_enter_connect"] = true // standby
		}
		spec, err := ebpf.LoadCollectionSpec(object)
		if err != nil {
			return nil, nil, "", fmt.Errorf("load spec %s: %w", object, err)
		}
		for name := range spec.Programs {
			if !loadNames[name] {
				delete(spec.Programs, name)
			}
		}
		coll, err := ebpf.NewCollection(spec) // no pinning, ever
		if err != nil {
			logf("feature probe: collection load with %q failed: %v", att.label, err)
			// Dump the tail of the kernel verifier log: the %v form
			// truncates it to a line count, which hides the exact
			// instruction the kernel rejected.
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) && len(ve.Log) > 0 {
				start := 0
				if len(ve.Log) > 60 {
					start = len(ve.Log) - 60
				}
				for _, line := range ve.Log[start:] {
					logf("  vlog: %s", line)
				}
			}
			continue
		}
		return coll, use, att.label, nil
	}
	return nil, nil, "", fmt.Errorf("could not load BPF collection with any program set")
}

func featureProbe(logf func(string, ...any)) (lsmMode bool) {
	rel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	lsmList := ""
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsmList = strings.TrimSpace(string(data))
	}
	btf := false
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		btf = true
	}
	lsmActive := false
	for _, tok := range strings.Split(lsmList, ",") {
		if strings.TrimSpace(tok) == "bpf" {
			lsmActive = true
		}
	}
	logf("feature probe: kernel=%s btf=%v cgroup_v2=%v euid=%d",
		strings.TrimSpace(string(rel)), btf, cgroupV2Available(), os.Geteuid())
	logf("feature probe: lsm_list=%q bpf_lsm_active=%v", lsmList, lsmActive)
	if ok, detail := selfTestBinaryKey(); ok {
		logf("feature probe: binary-identity self-test OK (%s)", detail)
	} else {
		logf("feature probe: WARNING binary-identity self-test FAILED: %s — exec_path matching may not work", detail)
	}
	if !btf {
		logf("feature probe: WARNING no kernel BTF — CO-RE object will fail to load")
	}
	if !cgroupV2Available() {
		logf("feature probe: WARNING cgroup v2 not found — service (cgroup/k8s) matching disabled in practice")
	}
	if !lsmActive {
		logf("feature probe: BPF LSM inactive → tracepoint fallback mode (paths via dentry walk / raw args, io_uring syscall blind spots apply)")
		return false
	}
	logf("feature probe: BPF LSM active → LSM mode (bpf_d_path paths)")
	return true
}

func Run(ctx context.Context, o Options) error {
	if o.OrphanTimeout < 0 {
		return fmt.Errorf("orphan timeout must be >= 0 (0 = wait indefinitely), got %s", o.OrphanTimeout)
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "agentloupe: "+format+"\n", args...)
	}
	lsmMode := featureProbe(logf)

	cfg, existed, err := config.Load(o.ConfigPath)
	if err != nil {
		return err
	}
	if !existed {
		logf("config %s not found — running with no agent rules (scope will be empty)", o.ConfigPath)
	}
	mergeExtras := func(base *config.File) *config.File {
		var extra []config.Agent
		if o.UseCatalog || len(o.CatalogOnly) > 0 {
			extra = append(extra, config.Catalog(o.CatalogOnly)...)
		}
		extra = append(extra, config.AttachRules(o.AttachPIDs, o.AttachComms, o.AttachExes)...)
		if len(extra) == 0 {
			return base
		}
		return config.Merge(base, extra)
	}
	cfg = mergeExtras(cfg)
	logf("agents: %d rules after catalog/attach merge", len(cfg.Agents))

	out := os.Stdout
	var outFile *os.File
	if o.Output != "" && o.Output != "-" {
		outFile, err = os.Create(o.Output)
		if err != nil {
			return err
		}
		defer outFile.Close()
		out = outFile
	}
	var writeMu sync.Mutex
	enc := newLineWriter(out)
	writeJSON := func(rec Output) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return enc.Write(rec)
	}

	reqs := buildRequests(lsmMode, o)
	coll, useReqs, attemptLabel, err := loadCollection(o.BPFObject, reqs, logf)
	if err != nil {
		return err
	}
	// Dev-mode guarantee: nothing is pinned; closing the collection and
	// links (here, on signal, or by the kernel if we are SIGKILLed)
	// removes every program from the kernel.
	defer coll.Close()
	logf("loaded BPF collection (%s), no pinned maps or links", attemptLabel)

	loader, err := newLoader(coll)
	if err != nil {
		return err
	}
	loader.SetConfig(cfg)
	if err := loader.setConfig(o.EnableIOAccounting, o.EnableSyscallSummary, o.EnableFileMutations); err != nil {
		return err
	}
	if err := loader.populateRules(cfg, logf); err != nil {
		return err
	}
	loader.adoptRunning(cfg, logf)

	// Attach. Links are held only in this slice; Close detaches.
	var links []link.Link
	var attached, fallbacks []string
	attach := func(r progReq) bool {
		l, err := attachOne(coll, r)
		if err != nil {
			logf("feature probe: attach %s (%s %s) failed: %v", r.Name, r.Kind, r.Target, err)
			fallbacks = append(fallbacks, r.Name)
			return false
		}
		links = append(links, l)
		attached = append(attached, fmt.Sprintf("%s[%s]", r.Name, r.Kind))
		return true
	}
	kprobeFailed := 0
	for _, r := range useReqs {
		if !attach(r) && r.Tag == "netkprobe" {
			kprobeFailed++
		}
	}
	// sys_enter_connect is ALWAYS attached: with TCP fexit live it runs
	// in UDP-only mode (net_udp_only), otherwise it is the full fallback.
	udpOnly := kprobeFailed == 0
	if attach(progReq{Name: "handle_enter_connect", Kind: "tracepoint", Group: "syscalls", Target: "sys_enter_connect", Tag: "core"}) {
		if err := loader.setNetUDPOnly(udpOnly); err != nil {
			logf("warn: set net_udp_only=%v: %v", udpOnly, err)
		}
		if !udpOnly {
			fallbacks = append(fallbacks, "network: sys_enter_connect replaces tcp kprobes")
		}
	}
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			links[i].Close()
		}
	}()
	logf("feature probe: attached %d hooks: %s", len(attached), strings.Join(attached, ", "))
	if !lsmMode {
		logf("fallbacks active: exec=sched_process_exec(raw_tp), file_open=sys_enter/sys_exit(raw_tp, raw args), network=%s", netModeLabel(kprobeFailed))
	}
	if len(fallbacks) > 0 {
		logf("feature probe: failed/fallback hooks: %s", strings.Join(fallbacks, ", "))
	}
	logf("probes enabled: process=yes file_open=yes network=yes file_mutations=%v io_accounting=%v syscall_summary=%v",
		o.EnableFileMutations, o.EnableIOAccounting, o.EnableSyscallSummary)

	if coll.Maps["events"] == nil {
		return fmt.Errorf("events ring buffer map missing from object")
	}
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()
	go func() {
		<-ctx.Done()
		rd.Close() // unblocks Read; kernel detaches everything on exit
	}()

	wallBase := wallBaseTime()
	proc := NewProcessor(loader, wallBase, writeJSON)
	proc.DropPrefixes = o.DropPathPrefixes
	proc.OrphanTimeout = o.OrphanTimeout

	// syscall_summary JSONL emission (userspace-synthesised; no kernel
	// change). Final flush runs from the session_end hook in the
	// Processor and, for sessions still live, on shutdown below.
	var summarizer *SyscallSummarizer
	if o.EnableSyscallSummary {
		summarizer = newLoaderSyscallSummarizer(loader, proc, writeJSON)
		proc.BeforeSessionEnd = summarizer.FlushSession
		proc.ForgetHook = summarizer.ForgetSession
	}

	// Config watching: inotify on the config directory and each watched
	// binary's parent directory (package managers rename over the path).
	reloadDirs := func() []string {
		dirs := map[string]bool{dirOf(o.ConfigPath): true}
		for _, p := range loader.Rules().WatchedPaths() {
			dirs[dirOf(p)] = true
		}
		out := make([]string, 0, len(dirs))
		for d := range dirs {
			out = append(out, d)
		}
		return out
	}
	watcherCtx, stopWatcher := context.WithCancel(ctx)
	defer stopWatcher()
	interesting := func() []string {
		return append([]string{o.ConfigPath}, loader.Rules().WatchedPaths()...)
	}
	go watchDirs(watcherCtx, reloadDirs, interesting, func() {
		newCfg, existed, err := config.Load(o.ConfigPath)
		if err != nil {
			logf("warn: config reload: %v (keeping previous rules)", err)
			return
		}
		if !existed {
			return
		}
		newCfg = mergeExtras(newCfg)
		loader.SetConfig(newCfg)
		if err := loader.populateRules(newCfg, logf); err != nil {
			logf("warn: rule reload: %v", err)
		} else {
			logf("config reloaded from %s", o.ConfigPath)
			loader.adoptRunning(newCfg, logf)
		}
	})

	maintCtx, stopMaint := context.WithCancel(ctx)
	defer stopMaint()
	go maintenance(maintCtx, loader, proc, o, logf, summarizer)

	logf("running (dev mode: detach on exit, nothing pinned)%s", maxRuntimeNote(ctx))
	decodeErrs := 0
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				if summarizer != nil {
					summarizer.EmitAll() // final flush: deltas add up to kernel totals
				}
				logf("shutting down: closing links and collection (all programs detach)")
				return nil
			}
			logf("warn: ring buffer read: %v", err)
			continue
		}
		d, err := Decode(rec.RawSample)
		if err != nil {
			decodeErrs++
			if decodeErrs <= 5 {
				logf("warn: decode record: %v", err)
			}
			continue
		}
		proc.Process(d)
	}
}

func netModeLabel(kprobeFailed int) string {
	if kprobeFailed > 0 {
		return "sys_enter_connect (fexit attach failed)"
	}
	return "tcp_v4/v6_connect fexit"
}

func maxRuntimeNote(ctx context.Context) string {
	if dl, ok := ctx.Deadline(); ok {
		return fmt.Sprintf(" — auto-exit at %s", dl.Format(time.RFC3339))
	}
	return ""
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "."
}

func wallBaseTime() time.Time {
	mono, err := monotonicTimespec()
	if err != nil {
		return time.Now()
	}
	monoDur := time.Duration(mono.Sec)*time.Second + time.Duration(mono.Nsec)
	return time.Now().Add(-monoDur)
}

type lineWriter struct {
	w   *bufio.Writer
	enc interface{ Encode(v any) error }
}

func newLineWriter(out *os.File) *lineWriter {
	bw := bufio.NewWriter(out)
	return &lineWriter{w: bw, enc: jsonEncoder{bw}}
}

func (l *lineWriter) Write(rec Output) error {
	if err := l.enc.Encode(rec); err != nil {
		return err
	}
	return l.w.Flush()
}
