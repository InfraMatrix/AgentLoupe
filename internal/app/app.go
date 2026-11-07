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

	"github.com/InfraMatrix/forkline/internal/config"
)

type Options struct {
	BPFObject            string
	ConfigPath           string
	Output               string
	EnableIOAccounting   bool
	EnableSyscallSummary bool
	// EnableFileRWEvents opts into per-call file_read/file_write
	// events (ABI v5, slices 2a/2b): one discrete event per vfs_read /
	// write{,v} call with this call's byte count and timestamps.
	// Off by default: host-wide vfs traffic makes this very loud.
	// Works without EnableIOAccounting; duration_us is filled by the
	// slice-2b fentry pairing when it attaches (0 = unknown or
	// sub-microsecond).
	EnableFileRWEvents bool
	// EnableNetSendEvents opts into per-call net_send events (ABI v7,
	// slices 3/4): one discrete event per tcp/udp_sendmsg call with this
	// call's byte count and destination. Off by default: per-send
	// traffic on a tracked socket is as loud as per-call rw events.
	// No latency field: slice 3 is attribution first. Slice 4 fills
	// hostname on those events (DNS qname / TLS SNI) via its own
	// sys_enter probe under the same flag; an empty hostname means the
	// send buffer held no parseable name, never a lost event.
	// Slice 5 (ABI v8) adds the other half: per-call net_recv events
	// with this call's bytes plus latency_us pairing each recv with the
	// thread's most recent send on the same socket (time-to-first-byte
	// for the first recv after a request). Same flag, same loudness
	// warning; latency_us = 0 means unknown, never a dropped event.
	EnableNetSendEvents bool
	// EnableFileMutations is accepted for compatibility but ignored:
	// file mutations (unlink/rename/chmod) are core since slice 1
	// and always attached.
	EnableFileMutations bool
	StatsInterval       time.Duration
	SyscallInterval     time.Duration
	// OrphanTimeout bounds how long a session stays open after its
	// root exits while tracked processes remain (0 = wait
	// indefinitely). See Processor.OrphanTimeout.
	OrphanTimeout time.Duration
	// ForceTracepointMode selects the tracepoint-fallback probe set
	// even when BPF LSM is available, so the fallback path can be
	// rehearsed and tested on any host.
	ForceTracepointMode bool
	DropPathPrefixes    []string
	AttachPIDs          []int
	AttachComms         []string
	AttachExes          []string
	UseCatalog          bool
	CatalogOnly         []string
}

type progReq struct {
	Name   string // Go-visible program (function) name in the object
	Kind   string // raw_tp | tracepoint | kprobe | lsm | fexit
	Group  string // tracepoint group, when Kind == tracepoint
	Target string // symbol / tracepoint name
	Tag    string // core | io | syscall | netkprobe | lat | netsend | sndhost | netrecv
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

	// File mutations (unlink/rename/chmod) are core, not opt-in: they
	// ride the same low-volume path as file_open, so they are always
	// attached in LSM mode. Tracepoint mode handles them inside
	// handle_file_sys_enter/exit (raw_tp sys_enter/exit, already in
	// core) with no extra programs to attach.
	if lsmMode {
		reqs = append(reqs,
			progReq{Name: "handle_path_unlink", Kind: "lsm", Tag: "core"},
			progReq{Name: "handle_path_rename", Kind: "lsm", Tag: "core"},
			progReq{Name: "handle_path_chmod", Kind: "lsm", Tag: "core"})
	}
	if o.EnableIOAccounting || o.EnableFileRWEvents {
		reqs = append(reqs,
			progReq{Name: "handle_vfs_read", Kind: "fexit", Target: "vfs_read", Tag: "io"},
			progReq{Name: "handle_vfs_write", Kind: "fexit", Target: "vfs_write", Tag: "io"},
			progReq{Name: "handle_vfs_readv", Kind: "fexit", Target: "vfs_readv", Tag: "io"},
			progReq{Name: "handle_vfs_writev", Kind: "fexit", Target: "vfs_writev", Tag: "io"})
	}
	// Slice 2b: fentry entry-timestamp probes pairing the fexit side
	// above for per-call latency (duration_us). Same flag, own tag:
	// if the fentry probes fail to load, the degradation ladder drops
	// just them and the fexit events keep flowing with duration_us = 0.
	if o.EnableFileRWEvents {
		reqs = append(reqs,
			progReq{Name: "handle_vfs_read_entry", Kind: "fentry", Target: "vfs_read", Tag: "lat"},
			progReq{Name: "handle_vfs_write_entry", Kind: "fentry", Target: "vfs_write", Tag: "lat"},
			progReq{Name: "handle_vfs_readv_entry", Kind: "fentry", Target: "vfs_readv", Tag: "lat"},
			progReq{Name: "handle_vfs_writev_entry", Kind: "fentry", Target: "vfs_writev", Tag: "lat"})
	}
	// Slice 3: fexit on tcp/udp_sendmsg for per-call send events, same
	// flag pattern as the rw probes (opt-in, own tag): a bad sendmsg
	// prototype degrades to no send events instead of losing connects.
	if o.EnableNetSendEvents {
		reqs = append(reqs,
			progReq{Name: "handle_tcp_sendmsg", Kind: "fexit", Target: "tcp_sendmsg", Tag: "netsend"},
			progReq{Name: "handle_udp_sendmsg", Kind: "fexit", Target: "udp_sendmsg", Tag: "netsend"})
	}
	// Slice 5: fexit on tcp/udp_recvmsg for per-call recv events with
	// send->recv latency. Same flag, own tag: a bad recvmsg prototype
	// degrades to sends without recvs (latency stays unknown) instead
	// of losing the send events.
	if o.EnableNetSendEvents {
		reqs = append(reqs,
			progReq{Name: "handle_tcp_recvmsg", Kind: "fexit", Target: "tcp_recvmsg", Tag: "netrecv"},
			progReq{Name: "handle_udp_recvmsg", Kind: "fexit", Target: "udp_recvmsg", Tag: "netrecv"})
	}
	// Slice 4: the sys_enter hostname parser rides the same flag with
	// its own tag, so a verifier rejection of the parsers degrades to
	// empty hostnames instead of losing the send events.
	if o.EnableNetSendEvents {
		reqs = append(reqs,
			progReq{Name: "handle_send_enter", Kind: "raw_tp", Target: "sys_enter", Tag: "sndhost"})
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
	case "fentry":
		return link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceFEntry})
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
		{"without syscall summary", map[string]bool{"core": true, "io": true, "lat": true, "netkprobe": true, "netsend": true, "sndhost": true, "netrecv": true}, false},
		{"without fentry latency (durations stay zero)", map[string]bool{"core": true, "io": true, "netkprobe": true, "netsend": true, "sndhost": true, "netrecv": true}, false},
		{"without send hostnames (hostnames stay empty)", map[string]bool{"core": true, "io": true, "netkprobe": true, "netsend": true, "netrecv": true}, false},
		{"without net recvs (recv latency stays unknown)", map[string]bool{"core": true, "io": true, "netkprobe": true, "netsend": true}, false},
		{"without net sends", map[string]bool{"core": true, "io": true, "netkprobe": true}, false},
		{"without io accounting or syscall summary", map[string]bool{"core": true, "netkprobe": true}, false},
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

func featureProbe(logf func(string, ...any), forceTracepoint bool) (lsmMode bool) {
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
	if forceTracepoint {
		logf("feature probe: tracepoint fallback mode forced (--force-tracepoint-mode) — LSM hooks will not be attached")
		return false
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
		fmt.Fprintf(os.Stderr, "forkline: "+format+"\n", args...)
	}
	lsmMode := featureProbe(logf, o.ForceTracepointMode)

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
	// File mutations are core since slice 1: always enabled in the
	// kernel config (the slot is retained for ABI stability).
	// Per-call read/write events are opt-in (slot 5, ABI v5);
	// per-call send/recv events are opt-in (slot 6, ABI v6/v8;
	// slice 4 send hostnames and slice 5 recv pairing ride the same
	// slot, no new toggle).
	if err := loader.setConfig(o.EnableIOAccounting, o.EnableSyscallSummary, true, o.EnableFileRWEvents, o.EnableNetSendEvents); err != nil {
		return err
	}
	if err := loader.populateRules(cfg, logf); err != nil {
		return err
	}
	// Adoption (the /proc walk) runs AFTER the hooks attach, below. Walking
	// first would leave a window where an agent exec'd, or a child forked
	// by an already-running agent, after the walk but before the hooks
	// exist is seen by neither and missed for good. Rules are populated
	// above, so the exec hook scopes new agents from the moment it attaches.

	// Startup journal on BEFORE the hooks attach, off once adoption is
	// done (finishStartupJournal): see journal.go.
	if err := loader.setJournal(true); err != nil {
		logf("warn: startup journal unavailable: %v", err)
	}

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
	latAttached := 0
	sendAttached := 0
	hostAttached := 0
	recvAttached := 0
	for _, r := range useReqs {
		ok := attach(r)
		if !ok && r.Tag == "netkprobe" {
			kprobeFailed++
		}
		if ok && r.Tag == "lat" {
			latAttached++
		}
		if ok && r.Tag == "netsend" {
			sendAttached++
		}
		if ok && r.Tag == "sndhost" {
			hostAttached++
		}
		if ok && r.Tag == "netrecv" {
			recvAttached++
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
	logf("probes enabled: process=yes file_open=yes file_mutations=yes network=yes io_accounting=%v file_rw_events=%v file_rw_latency=%v net_send_events=%v net_send_hostnames=%v net_recv_events=%v syscall_summary=%v",
		o.EnableIOAccounting, o.EnableFileRWEvents, o.EnableFileRWEvents && latAttached == 4, o.EnableNetSendEvents && sendAttached == 2, o.EnableNetSendEvents && hostAttached == 1, o.EnableNetSendEvents && recvAttached == 2, o.EnableSyscallSummary)

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

	// Now that exec/fork are hooked: adopt what was already running. A
	// process the kernel scoped in the meantime is already in
	// tracked_sessions and is skipped; children forked during the walk are
	// picked up by adoptRunning's re-scan (adoptLateChildren), and ones
	// linked only through a process that has since exited by the startup
	// journal. The pump drains the ring meanwhile so it cannot fill.
	pump := startJournalPump(rd, logf)
	newSIDs := loader.adoptRunning(cfg, logf)
	startupRecords, err := loader.finishStartupJournal(rd, pump, newSIDs, logf)
	if err != nil && (errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil) {
		logf("shutting down during startup: closing links and collection (all programs detach)")
		return nil
	}

	wallBase := wallBaseTime()
	// One capture-level record first: the clock anchor (so harness hook
	// timestamps map into capture time exactly) and the probe set (so
	// reducers can tell measured-zero from not-collected).
	if err := writeJSON(newCaptureMeta(wallBase, map[string]bool{
		"lsm_mode":          lsmMode,
		"io_accounting":     o.EnableIOAccounting,
		"file_rw_events":    o.EnableFileRWEvents,
		"file_rw_latency":   o.EnableFileRWEvents && latAttached == 4,
		"net_send_events":   o.EnableNetSendEvents && sendAttached == 2,
		"net_recv_events":   o.EnableNetSendEvents && recvAttached == 2,
		"net_send_hostname": o.EnableNetSendEvents && hostAttached == 1,
		"syscall_summary":   o.EnableSyscallSummary,
	})); err != nil {
		return fmt.Errorf("write capture_meta: %w", err)
	}
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
	configSeen := existed // a config file has been loaded at some point
	go watchDirs(watcherCtx, reloadDirs, interesting, func() {
		newCfg, existed, err := config.Load(o.ConfigPath)
		if err != nil {
			logf("warn: config reload: %v (keeping previous rules)", err)
			return
		}
		if !reloadWithConfig(existed, &configSeen) {
			logf("config %s disappeared — keeping previous rules", o.ConfigPath)
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
	// Records from the startup window first, in ring order (journal
	// records already relabeled or removed by finishStartupJournal).
	for _, raw := range startupRecords {
		d, err := Decode(raw)
		if err != nil {
			decodeErrs++
			if decodeErrs <= 5 {
				logf("warn: decode record: %v", err)
			}
			continue
		}
		proc.Process(d)
	}
	startupRecords = nil
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

// reloadWithConfig decides whether a watcher-triggered reload proceeds.
// Without any config file the rules come only from --attach-*/--catalog,
// and those must still be re-applied (e.g. an --attach-exe glob gaining a
// binary). Once a config file has been loaded, its disappearing (deleted,
// or mid-replace) keeps the previous rules instead of wiping them.
func reloadWithConfig(existed bool, seen *bool) bool {
	if existed {
		*seen = true
		return true
	}
	return !*seen
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
