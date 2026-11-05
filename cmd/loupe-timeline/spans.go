// Tool spans: attribute a session's kernel events to the individual tool
// calls an agent made.
//
// Layer 1 (always on, no harness cooperation): every direct child
// subtree of the agent process is one span. Most harnesses run each
// tool as a child process (Claude Code's Bash tool spawns `bash -c ...`),
// so "tool call" ~= "child subtree". Events in the agent process itself
// (in-process tools, model calls, runtime startup) land in an explicit
// agent_self bucket, never dropped, so sum(spans) + agent_self equals the
// session totals for every additive resource (checked per session and
// reported in tool_span_reconciliation).
//
// Layer 2 (harness.go): when a harness hook file is supplied, pre/post
// tool-call records are matched to these spans and merged.
package main

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxSpanArgs      = 16  // argv entries kept per span
	maxSpanArgLen    = 200 // bytes per argv entry
	maxSpanArgvTotal = 800 // bytes across all kept entries
	maxSpanCommand   = 300
	maxSpanTopFiles  = 10
	maxSpanTopDests  = 10
	maxSpanPIDs      = 50
	maxSpanParallel  = 10
	maxSpanMutated   = 10
)

// spanRec is one event reduced to what span attribution needs. Records
// are kept for the whole session (the tree is only known at the end).
type spanRec struct {
	t         time.Time
	seq       int
	kind      string
	pid, ppid uint32
	child     uint32
	argv      []string
	filename  string
	comm      string
	path      string
	path2     string
	dest      string
	host      string
	dns       bool
	bytes     uint64
	rb, wb    uint64
	result    int32
	exitCode  int32
	cpuU      uint64
	cpuS      uint64
	rss       uint64
	sys       map[string]uint64 // syscall_summary: category -> count for this pid
	// rootExitCPU marks a root_exit whose resource fields stand in for
	// a missed exit event (counted once, never alongside the exit).
	rootExitCPU bool
	// noCPU: the exit line had no resource fields (pre-ABI-v4 capture).
	noCPU bool
}

// inst is one process instance (a pid between its fork and its exit).
// Parentage is fixed at fork time, so a daemon reparented to init (or a
// subreaper) still belongs to the subtree that spawned it.
type inst struct {
	pid      uint32
	parent   *inst
	start    time.Time
	end      time.Time
	hasEnd   bool
	argv     []string
	filename string
	comm     string
	exitCode *int32
	execs    int
	hasCPU   bool
}

// label prefers argv[0] (what was invoked: "true", not the resolved
// coreutils multicall binary), then the exec'd file, then comm.
func (p *inst) label() string {
	if len(p.argv) > 0 && p.argv[0] != "" {
		return filepath.Base(p.argv[0])
	}
	if p.filename != "" {
		return filepath.Base(p.filename)
	}
	if p.comm != "" {
		return p.comm
	}
	return fmt.Sprintf("pid %d", p.pid)
}

// SpanFile is one file's activity inside a span.
type SpanFile struct {
	Path       string `json:"path"`
	Count      int    `json:"count"`
	ReadBytes  uint64 `json:"read_bytes,omitempty"`
	WriteBytes uint64 `json:"write_bytes,omitempty"`
}

// SpanDest is one network destination's activity inside a span.
type SpanDest struct {
	Dest      string   `json:"dest"`
	Connects  int      `json:"connects"`
	Sends     int      `json:"sends,omitempty"`
	SentBytes uint64   `json:"sent_bytes,omitempty"`
	Recvs     int      `json:"recvs,omitempty"`
	RecvBytes uint64   `json:"recv_bytes,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
}

// SpanResources aggregates kernel-observed resources. Pointer fields are
// null when the capture did not collect that signal (probe off), so a 0
// always means "measured zero", never "unknown".
type SpanResources struct {
	Events    int `json:"events"`
	Processes int `json:"processes"`
	Execs     int `json:"execs"`
	// CPU is the sum of each exited process's own thread-group CPU
	// (exit events, ABI v4). cpu_incomplete: some processes in the
	// bucket had not exited by capture end, so their CPU is missing.
	CPUUserMS        *uint64           `json:"cpu_user_ms"`
	CPUSysMS         *uint64           `json:"cpu_sys_ms"`
	CPUIncomplete    bool              `json:"cpu_incomplete,omitempty"`
	MaxRSSKB         *uint64           `json:"max_rss_kb"`
	FileOpens        int               `json:"file_opens"`
	FileOpenFailures int               `json:"file_open_failures"`
	FileReads        *int              `json:"file_reads"`
	FileWrites       *int              `json:"file_writes"`
	ReadBytes        *uint64           `json:"read_bytes"`
	WriteBytes       *uint64           `json:"write_bytes"`
	FilesMutated     int               `json:"files_mutated"`
	NetConnects      int               `json:"net_connects"`
	DNSConnects      int               `json:"dns_connects"`
	NetSends         *int              `json:"net_sends"`
	NetSentBytes     *uint64           `json:"net_sent_bytes"`
	NetRecvs         *int              `json:"net_recvs"`
	NetRecvBytes     *uint64           `json:"net_recv_bytes"`
	Syscalls         map[string]uint64 `json:"syscalls_by_category"`
	SyscallsTotal    *uint64           `json:"syscalls_total"`
}

// ToolSpan is one tool call (or the agent_self remainder).
type ToolSpan struct {
	SpanID string `json:"span_id"`
	// Source: "process_tree" (child subtree only), "harness+process_tree"
	// (hook record merged with the subtree(s) it spawned), "harness"
	// (hook record, no child process), or "agent_self".
	Source string `json:"source"`
	// Attribution: how resources were assigned. "process_tree" is exact
	// (every event's pid is in the subtree); "time_window" means the
	// agent process's own events inside the pre->post interval — less
	// precise (concurrent in-process work in that window is included);
	// "remainder" is agent_self.
	Attribution string `json:"attribution"`
	// Role "hook" marks the AgentLoupe hook's own processes (overhead of
	// observation, not agent work).
	Role              string         `json:"role,omitempty"`
	ToolName          string         `json:"tool_name,omitempty"`
	ToolUseID         string         `json:"tool_use_id,omitempty"`
	Input             map[string]any `json:"input,omitempty"`
	Status            string         `json:"status,omitempty"`
	HarnessDurationMs *int64         `json:"harness_duration_ms,omitempty"`
	RootPID           uint32         `json:"root_pid,omitempty"`
	PIDs              []uint32       `json:"pids,omitempty"`
	Program           string         `json:"program,omitempty"`
	Argv              []string       `json:"argv,omitempty"`
	ArgvTruncated     bool           `json:"argv_truncated,omitempty"`
	Command           string         `json:"command,omitempty"`
	Start             string         `json:"start"`
	End               string         `json:"end"`
	StartMs           int64          `json:"start_ms"`
	EndMs             int64          `json:"end_ms"`
	WallMs            int64          `json:"wall_ms"`
	ProcessWallMs     *int64         `json:"process_wall_ms,omitempty"`
	OpenEnded         bool           `json:"open_ended,omitempty"`
	OutlivedSpan      bool           `json:"outlived_span"`
	SubtreeEndMs      int64          `json:"subtree_end_ms,omitempty"`
	ExitCode          *int32         `json:"exit_code"`
	ParallelWith      []string       `json:"parallel_with,omitempty"`
	MergedRootPIDs    []uint32       `json:"merged_root_pids,omitempty"`
	// ContinuedInSession: the span root exec'd a binary that a rule
	// tracks as its own agent (e.g. Claude Code re-executing itself as
	// its bundled rg), so the loader opened a nested session for it.
	// Timing/argv/exit come from that session's root; its resources are
	// reported under that session (decimal string: IDs exceed 2^53).
	ContinuedInSession string         `json:"continued_in_session,omitempty"`
	Resources          *SpanResources `json:"resources"`
	TopFiles           []*SpanFile    `json:"top_files,omitempty"`
	TopDestinations    []*SpanDest    `json:"top_destinations,omitempty"`
	MutatedPaths       []string       `json:"mutated_paths,omitempty"`
	Notes              []string       `json:"notes,omitempty"`

	startT, endT time.Time
	acc          *acc
	roots        []*inst
	members      []*inst
	mergedInto   *ToolSpan
}

// AgentProcess says which process the spans hang off.
type AgentProcess struct {
	PID     uint32 `json:"pid"`
	Program string `json:"program"`
	// ChosenBy: "session_root" (default) or "--agent-process <name>".
	ChosenBy string `json:"chosen_by"`
	// OutsideAgentTree counts processes not under the agent process
	// (wrapper ancestors and their other children); they are counted
	// in agent_self.
	OutsideAgentTree int `json:"outside_agent_tree,omitempty"`
	// AdditionalRoots: further session_start roots in the same session
	// (adoption, or captures predating exact session IDs). Each is an
	// agent process too: its children are spans, its own events are
	// agent_self.
	AdditionalRoots []uint32 `json:"additional_roots,omitempty"`
}

// SpanReconciliation records the sum(spans)+agent_self == totals check.
type SpanReconciliation struct {
	OK         bool     `json:"ok"`
	Mismatches []string `json:"mismatches,omitempty"`
}

// ---- accumulation ----

type fileAgg struct {
	count  int
	rb, wb uint64
}

type acc struct {
	events            int
	procs, execs      int
	cpuU, cpuS        uint64
	cpuKnown, cpuMiss int
	rss               uint64
	rssKnown          bool
	opens, openFail   int
	reads, writes     int
	rwRB, rwWB        uint64
	closeRB, closeWB  uint64
	mut               int
	connects, dns     int
	sends, recvs      int
	sentB, recvB      uint64
	sys               map[string]uint64
	files             map[string]*fileAgg
	dests             map[string]*SpanDest
	mutPaths          []string
	mutSeen           map[string]bool
}

func newAcc() *acc {
	return &acc{sys: map[string]uint64{}, files: map[string]*fileAgg{},
		dests: map[string]*SpanDest{}, mutSeen: map[string]bool{}}
}

func (a *acc) file(path string) *fileAgg {
	f, ok := a.files[path]
	if !ok {
		f = &fileAgg{}
		a.files[path] = f
	}
	return f
}

func (a *acc) dest(d string) *SpanDest {
	e, ok := a.dests[d]
	if !ok {
		e = &SpanDest{Dest: d}
		a.dests[d] = e
	}
	return e
}

func (a *acc) addHost(e *SpanDest, h string) {
	if h == "" {
		return
	}
	for _, x := range e.Hostnames {
		if x == h {
			return
		}
	}
	if len(e.Hostnames) < 8 {
		e.Hostnames = append(e.Hostnames, h)
	}
}

func (a *acc) mutated(p string) {
	if p == "" || a.mutSeen[p] {
		return
	}
	a.mutSeen[p] = true
	a.mutPaths = append(a.mutPaths, p)
}

// add folds one event record in. Process counts and cpu_incomplete are
// instance properties, added by addInst.
func (a *acc) add(r *spanRec) {
	a.events++
	switch r.kind {
	case "exec":
		a.execs++
	case "exit":
		if r.noCPU {
			break
		}
		a.cpuU += r.cpuU
		a.cpuS += r.cpuS
		a.cpuKnown++
		if r.rss > a.rss {
			a.rss = r.rss
		}
		a.rssKnown = true
	case "root_exit":
		if r.rootExitCPU && !r.noCPU {
			a.cpuU += r.cpuU
			a.cpuS += r.cpuS
			a.cpuKnown++
			if r.rss > a.rss {
				a.rss = r.rss
			}
			a.rssKnown = true
		}
	case "file_open":
		a.opens++
		if r.result < 0 {
			a.openFail++
		}
		if r.path != "" {
			a.file(r.path).count++
		}
	case "file_read":
		a.reads++
		a.rwRB += r.bytes
		if r.path != "" {
			f := a.file(r.path)
			f.count++
			f.rb += r.bytes
		}
	case "file_write":
		a.writes++
		a.rwWB += r.bytes
		if r.path != "" {
			f := a.file(r.path)
			f.count++
			f.wb += r.bytes
		}
	case "file_close":
		a.closeRB += r.rb
		a.closeWB += r.wb
	case "file_unlink", "file_chmod":
		a.mut++
		a.mutated(r.path)
	case "file_rename":
		a.mut++
		a.mutated(r.path)
		a.mutated(r.path2)
	case "net_connect":
		a.connects++
		if r.dns {
			a.dns++
		}
		a.dest(r.dest).Connects++
	case "net_send":
		a.sends++
		a.sentB += r.bytes
		e := a.dest(r.dest)
		e.Sends++
		e.SentBytes += r.bytes
		a.addHost(e, r.host)
	case "net_recv":
		a.recvs++
		a.recvB += r.bytes
		e := a.dest(r.dest)
		e.Recvs++
		e.RecvBytes += r.bytes
		a.addHost(e, r.host)
	case "syscall_summary":
		for c, n := range r.sys {
			a.sys[c] += n
		}
	}
}

func (a *acc) addInst(p *inst) {
	a.procs++
	if !p.hasCPU {
		a.cpuMiss++
	}
}

func (a *acc) merge(b *acc) {
	a.events += b.events
	a.procs += b.procs
	a.execs += b.execs
	a.cpuU += b.cpuU
	a.cpuS += b.cpuS
	a.cpuKnown += b.cpuKnown
	a.cpuMiss += b.cpuMiss
	if b.rssKnown {
		if b.rss > a.rss {
			a.rss = b.rss
		}
		a.rssKnown = true
	}
	a.opens += b.opens
	a.openFail += b.openFail
	a.reads += b.reads
	a.writes += b.writes
	a.rwRB += b.rwRB
	a.rwWB += b.rwWB
	a.closeRB += b.closeRB
	a.closeWB += b.closeWB
	a.mut += b.mut
	a.connects += b.connects
	a.dns += b.dns
	a.sends += b.sends
	a.recvs += b.recvs
	a.sentB += b.sentB
	a.recvB += b.recvB
	for k, v := range b.sys {
		a.sys[k] += v
	}
	for p, f := range b.files {
		g := a.file(p)
		g.count += f.count
		g.rb += f.rb
		g.wb += f.wb
	}
	for d, e := range b.dests {
		g := a.dest(d)
		g.Connects += e.Connects
		g.Sends += e.Sends
		g.SentBytes += e.SentBytes
		g.Recvs += e.Recvs
		g.RecvBytes += e.RecvBytes
		for _, h := range e.Hostnames {
			a.addHost(g, h)
		}
	}
	for _, p := range b.mutPaths {
		a.mutated(p)
	}
}

// spanAvail says which signals the capture collected at all.
type spanAvail struct {
	rw        bool   // per-call file_read/file_write events
	bytesFrom string // "file_rw_events" | "file_close" | "" (none)
	net       bool   // per-call net_send/net_recv events
	sys       bool   // syscall_summary
}

func u64p(v uint64) *uint64 { return &v }
func intp(v int) *int       { return &v }

// resources renders an accumulator under the capture's availability.
// cpuOK=false forces CPU/RSS null (time-window spans: the agent's CPU is
// a whole-lifetime number that cannot be split by window).
func (a *acc) resources(av spanAvail, cpuOK, sysOK bool) *SpanResources {
	r := &SpanResources{
		Events: a.events, Processes: a.procs, Execs: a.execs,
		FileOpens: a.opens, FileOpenFailures: a.openFail,
		FilesMutated: a.mut, NetConnects: a.connects, DNSConnects: a.dns,
	}
	if cpuOK && a.cpuKnown > 0 {
		r.CPUUserMS, r.CPUSysMS = u64p(a.cpuU), u64p(a.cpuS)
		r.CPUIncomplete = a.cpuMiss > 0
	}
	if cpuOK && a.rssKnown {
		r.MaxRSSKB = u64p(a.rss)
	}
	if av.rw {
		r.FileReads, r.FileWrites = intp(a.reads), intp(a.writes)
	}
	switch av.bytesFrom {
	case "file_rw_events":
		r.ReadBytes, r.WriteBytes = u64p(a.rwRB), u64p(a.rwWB)
	case "file_close":
		r.ReadBytes, r.WriteBytes = u64p(a.closeRB), u64p(a.closeWB)
	}
	if av.net {
		r.NetSends, r.NetSentBytes = intp(a.sends), u64p(a.sentB)
		r.NetRecvs, r.NetRecvBytes = intp(a.recvs), u64p(a.recvB)
	}
	if av.sys && sysOK {
		r.Syscalls = map[string]uint64{}
		var tot uint64
		for k, v := range a.sys {
			r.Syscalls[k] = v
			tot += v
		}
		r.SyscallsTotal = u64p(tot)
	}
	return r
}

func (a *acc) topFiles(n int) []*SpanFile {
	out := make([]*SpanFile, 0, len(a.files))
	for p, f := range a.files {
		out = append(out, &SpanFile{Path: p, Count: f.count, ReadBytes: f.rb, WriteBytes: f.wb})
	}
	sort.Slice(out, func(i, j int) bool {
		bi, bj := out[i].ReadBytes+out[i].WriteBytes, out[j].ReadBytes+out[j].WriteBytes
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if bi != bj {
			return bi > bj
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (a *acc) topDests(n int) []*SpanDest {
	out := make([]*SpanDest, 0, len(a.dests))
	for _, d := range a.dests {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		vi := out[i].Connects + out[i].Sends + out[i].Recvs
		vj := out[j].Connects + out[j].Sends + out[j].Recvs
		if vi != vj {
			return vi > vj
		}
		return out[i].Dest < out[j].Dest
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ---- record capture (called from builder.add) ----

func (s *sessionBuilder) record(ev *rawEvent, ts time.Time) {
	base := spanRec{t: ts, seq: len(s.recs), kind: ev.Type, pid: ev.PID, ppid: ev.PPID, comm: ev.Comm}
	switch ev.Type {
	case "session_start", "fork", "exec", "exit", "root_exit":
		base.child = ev.ChildPID
		base.argv = ev.Argv
		base.filename = ev.Filename
		base.exitCode = ev.ExitCode
		base.cpuU, base.cpuS, base.rss = ev.CPUUserMS, ev.CPUSysMS, ev.MaxRSSKB
		base.noCPU = !ev.hasCPU
	case "file_open", "file_unlink", "file_chmod", "file_read", "file_write", "file_close":
		base.path = ev.Path
		base.bytes = ev.Bytes
		base.rb, base.wb = ev.ReadBytes, ev.WriteBytes
		if ev.Result != nil {
			base.result = *ev.Result
		}
	case "file_rename":
		base.path, base.path2 = ev.OldPath, ev.NewPath
	case "net_connect", "net_send", "net_recv":
		base.dest = fmt.Sprintf("%s:%d", ev.Daddr, ev.Dport)
		base.host = ev.Hostname
		base.dns = ev.DNS
		base.bytes = ev.Bytes
	case "syscall_summary":
		if len(ev.PerProcess) == 0 {
			// No per-process split (pre-ABI-v3 capture): unattributable,
			// lands in agent_self via pid 0.
			if len(ev.Counts) == 0 {
				return
			}
			base.pid = 0
			base.sys = categorize(ev.Counts)
			s.recs = append(s.recs, base)
			return
		}
		pids := make([]string, 0, len(ev.PerProcess))
		for p := range ev.PerProcess {
			pids = append(pids, p)
		}
		sort.Strings(pids)
		for _, p := range pids {
			var pid uint32
			if _, err := fmt.Sscanf(p, "%d", &pid); err != nil {
				continue
			}
			r := base
			r.seq = len(s.recs)
			r.pid, r.ppid = pid, 0
			r.sys = categorize(ev.PerProcess[p])
			s.recs = append(s.recs, r)
		}
		return
	case "session_end":
		return // lifecycle bookkeeping only; no resources
	default:
		return
	}
	if base.pid == 0 {
		return
	}
	s.recs = append(s.recs, base)
}

func categorize(counts map[string]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for name, c := range counts {
		if c > 0 {
			out[SyscallCategory(name)] += c
		}
	}
	return out
}

// ---- instance tree ----

type tree struct {
	insts   []*inst
	recInst []*inst // recs[i] -> owning instance (nil for pid 0)
	// rootInsts: one per session_start, in order. A session normally
	// has one; adoption (or captures predating exact session IDs) can
	// yield several, and each is an agent process.
	rootInsts []*inst
}

func buildTree(recs []spanRec) *tree {
	tr := &tree{recInst: make([]*inst, len(recs))}
	current := map[uint32]*inst{}
	last := map[uint32]*inst{}
	newInst := func(pid uint32, parent *inst, t time.Time) *inst {
		p := &inst{pid: pid, parent: parent, start: t}
		tr.insts = append(tr.insts, p)
		current[pid] = p
		last[pid] = p
		return p
	}
	lookup := func(pid uint32) *inst {
		if p, ok := current[pid]; ok {
			return p
		}
		return last[pid] // post-exit teardown events (file_close etc.)
	}
	ensure := func(pid, ppid uint32, t time.Time) *inst {
		if p := lookup(pid); p != nil {
			return p
		}
		var parent *inst
		if ppid != 0 && ppid != pid {
			parent = lookup(ppid)
		}
		return newInst(pid, parent, t)
	}
	exitSeen := map[*inst]bool{}
	for i := range recs {
		r := &recs[i]
		switch r.kind {
		case "session_start":
			p := ensure(r.pid, r.ppid, r.t)
			if len(tr.rootInsts) == 0 || tr.rootInsts[len(tr.rootInsts)-1] != p {
				tr.rootInsts = append(tr.rootInsts, p)
			}
			tr.recInst[i] = p
		case "fork":
			parent := ensure(r.pid, r.ppid, r.t)
			tr.recInst[i] = parent
			if r.child == 0 {
				continue
			}
			if c, ok := current[r.child]; ok && c.parent == nil && !c.start.Before(r.t.Add(-time.Second)) && c != parent {
				// Child's own events arrived first (same timestamp
				// ordering): adopt it rather than splitting it.
				c.parent = parent
				continue
			}
			newInst(r.child, parent, r.t)
		case "exec":
			p := ensure(r.pid, r.ppid, r.t)
			if p.argv == nil {
				p.argv = r.argv
				p.filename = r.filename
				p.comm = r.comm
			}
			p.execs++
			tr.recInst[i] = p
		case "exit":
			p := ensure(r.pid, r.ppid, r.t)
			p.end, p.hasEnd = r.t, true
			ec := r.exitCode
			p.exitCode = &ec
			p.hasCPU = !r.noCPU
			exitSeen[p] = true
			if p.comm == "" {
				p.comm = r.comm
			}
			delete(current, r.pid)
			tr.recInst[i] = p
		case "root_exit":
			p := lookup(r.pid)
			if p == nil {
				p = ensure(r.pid, r.ppid, r.t)
			}
			if !exitSeen[p] {
				// Exit event missed: root_exit mirrors its fields.
				r.rootExitCPU = true
				p.hasCPU = !r.noCPU
				ec := r.exitCode
				p.exitCode = &ec
				if !p.hasEnd {
					p.end, p.hasEnd = r.t, true
				}
				exitSeen[p] = true
			}
			tr.recInst[i] = p
		default:
			if r.pid == 0 {
				continue
			}
			p := ensure(r.pid, r.ppid, r.t)
			if p.comm == "" {
				p.comm = r.comm
			}
			tr.recInst[i] = p
		}
	}
	return tr
}

// subtreeOf returns, for an instance, the span root it belongs to (the
// child of the nearest agent on its ancestor chain), the agent itself
// when p is an agent, or nil when p is under no agent.
func (tr *tree) subtreeOf(isAgent map[*inst]bool) func(p *inst) *inst {
	memo := map[*inst]*inst{}
	return func(p *inst) *inst {
		if isAgent[p] {
			return p
		}
		var chain []*inst
		var res *inst
		cur := p
		for steps := 0; cur != nil && steps < 10000; steps++ {
			if v, ok := memo[cur]; ok {
				res = v
				break
			}
			if isAgent[cur] {
				res = chain[len(chain)-1]
				break
			}
			chain = append(chain, cur)
			cur = cur.parent
		}
		for _, c := range chain {
			memo[c] = res
		}
		return res
	}
}

func matchesAgent(p *inst, name string) bool {
	if name == "" {
		return false
	}
	if p.comm == name || p.label() == name {
		return true
	}
	if len(p.argv) > 0 && filepath.Base(p.argv[0]) == name {
		return true
	}
	return false
}

// ---- span building ----

type spanBuild struct {
	tr        *tree
	recs      []spanRec
	agent     *inst          // primary agent process
	agents    map[*inst]bool // every agent process (session roots)
	agentInfo *AgentProcess
	spans     []*ToolSpan // final span list (process-tree first, by start)
	instSpan  map[*inst]*ToolSpan
	recBucket []*ToolSpan // nil = agent_self; resolved through mergedInto
	self      *acc
	selfPIDs  []uint32
	totals    *acc
	recon     *SpanReconciliation
}

// buildProcessSpans builds the instance tree, picks the agent process,
// and assigns every instance and record to a process-tree span or to
// agent_self. Accumulation happens later (finalizeAccs) so the harness
// layer can still merge spans and move time-window records.
func buildProcessSpans(recs []spanRec, agentName string) *spanBuild {
	tr := buildTree(recs)
	sb := &spanBuild{tr: tr, recs: recs, instSpan: map[*inst]*ToolSpan{},
		recBucket: make([]*ToolSpan, len(recs))}

	chosenBy := "session_root"
	if agentName != "" {
		for _, p := range tr.insts {
			if matchesAgent(p, agentName) && (sb.agent == nil || p.start.Before(sb.agent.start)) {
				sb.agent = p
			}
		}
		if sb.agent != nil {
			chosenBy = "--agent-process " + agentName
		}
	}
	isAgent := map[*inst]bool{}
	if sb.agent == nil && len(tr.rootInsts) > 0 {
		sb.agent = tr.rootInsts[0]
		for _, p := range tr.rootInsts {
			isAgent[p] = true
		}
	}
	if sb.agent == nil {
		for _, p := range tr.insts {
			if p.parent == nil && (sb.agent == nil || p.start.Before(sb.agent.start)) {
				sb.agent = p
			}
		}
	}
	rootOf := func(*inst) *inst { return nil }
	if sb.agent != nil {
		isAgent[sb.agent] = true
		sb.agents = isAgent
		rootOf = tr.subtreeOf(isAgent)
		sb.agentInfo = &AgentProcess{PID: sb.agent.pid, Program: sb.agent.label(), ChosenBy: chosenBy}
		if len(isAgent) > 1 {
			for _, p := range tr.rootInsts {
				sb.agentInfo.AdditionalRoots = append(sb.agentInfo.AdditionalRoots, p.pid)
			}
			sb.agentInfo.AdditionalRoots = sb.agentInfo.AdditionalRoots[1:]
		}
	}

	byRoot := map[*inst]*ToolSpan{}
	for _, p := range tr.insts {
		root := rootOf(p)
		if root == nil || isAgent[root] {
			if root == nil && sb.agentInfo != nil {
				sb.agentInfo.OutsideAgentTree++
			}
			continue
		}
		sp, ok := byRoot[root]
		if !ok {
			sp = &ToolSpan{Source: "process_tree", Attribution: "process_tree", roots: []*inst{root}}
			byRoot[root] = sp
			sb.spans = append(sb.spans, sp)
		}
		sp.members = append(sp.members, p)
		sp.PIDs = appendPID(sp.PIDs, p.pid)
		sb.instSpan[p] = sp
	}
	for i := range recs {
		if owner := tr.recInst[i]; owner != nil {
			sb.recBucket[i] = sb.instSpan[owner]
		}
	}
	sort.SliceStable(sb.spans, func(i, j int) bool {
		a, b := sb.spans[i].roots[0], sb.spans[j].roots[0]
		if !a.start.Equal(b.start) {
			return a.start.Before(b.start)
		}
		return a.pid < b.pid
	})
	return sb
}

func resolveSpan(sp *ToolSpan) *ToolSpan {
	for sp != nil && sp.mergedInto != nil {
		sp = sp.mergedInto
	}
	return sp
}

// finalizeAccs accumulates every record and instance into exactly one
// bucket (a span or agent_self), computes independent session totals,
// and reconciles the two.
func (sb *spanBuild) finalizeAccs() {
	sb.self = newAcc()
	for _, sp := range sb.spans {
		sp.acc = newAcc()
	}
	sb.totals = newAcc()
	selfPIDs := map[uint32]bool{}
	for _, p := range sb.tr.insts {
		sb.totals.addInst(p)
		if sp := resolveSpan(sb.instSpan[p]); sp != nil {
			sp.acc.addInst(p)
		} else {
			sb.self.addInst(p)
			if !selfPIDs[p.pid] {
				selfPIDs[p.pid] = true
				sb.selfPIDs = append(sb.selfPIDs, p.pid)
			}
		}
	}
	for i := range sb.recs {
		r := &sb.recs[i]
		sb.totals.add(r)
		if sp := resolveSpan(sb.recBucket[i]); sp != nil {
			sp.acc.add(r)
		} else {
			sb.self.add(r)
		}
	}
	sb.recon = reconcile(sb.spans, sb.self, sb.totals)
}

func appendPID(ps []uint32, pid uint32) []uint32 {
	for _, p := range ps {
		if p == pid {
			return ps
		}
	}
	return append(ps, pid)
}

// truncArgv keeps argv readable and bounded.
func truncArgv(argv []string) ([]string, bool) {
	var out []string
	total := 0
	cut := false
	for i, a := range argv {
		if i >= maxSpanArgs || total >= maxSpanArgvTotal {
			cut = true
			break
		}
		if len(a) > maxSpanArgLen {
			a = a[:maxSpanArgLen] + "…"
			cut = true
		}
		if total+len(a) > maxSpanArgvTotal {
			a = a[:maxSpanArgvTotal-total] + "…"
			cut = true
		}
		total += len(a)
		out = append(out, a)
	}
	return out, cut
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "fish": true, "ksh": true}

// shellCommand returns the -c payload of a shell invocation.
func shellCommand(argv []string) string {
	if len(argv) < 2 || !shells[filepath.Base(argv[0])] {
		return ""
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "-") && strings.Contains(a, "c") && !strings.HasPrefix(a, "--") {
			// -c, -lc, -ec ...: the next non-flag argument is the command.
			for j := i + 1; j < len(argv); j++ {
				if !strings.HasPrefix(argv[j], "-") {
					return argv[j]
				}
			}
			return ""
		}
		if !strings.HasPrefix(a, "-") {
			return ""
		}
	}
	return ""
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// fillProcessMeta sets identity/timing fields of a process-tree span
// from its root instance(s) and subtree.
func (sp *ToolSpan) fillProcessMeta(globalFirst, globalLast time.Time, members []*inst) {
	root := sp.roots[0]
	sp.RootPID = root.pid
	sp.Program = root.label()
	sp.Argv, sp.ArgvTruncated = truncArgv(root.argv)
	sp.Command = truncStr(shellCommand(root.argv), maxSpanCommand)
	sp.startT = root.start
	if root.hasEnd {
		sp.endT = root.end
	} else {
		sp.endT = globalLast
		sp.OpenEnded = true
	}
	sp.ExitCode = root.exitCode
	// Subtree end: the latest end among members; outlived when any
	// member ended after (or was still running past) the root.
	subEnd := sp.endT
	outlived := false
	for _, m := range members {
		e := globalLast
		if m.hasEnd {
			e = m.end
		}
		if e.After(subEnd) {
			subEnd = e
		}
		if root.hasEnd && (!m.hasEnd || m.end.After(root.end)) {
			outlived = true
		}
	}
	sp.OutlivedSpan = outlived
	if outlived && !globalFirst.IsZero() {
		sp.SubtreeEndMs = subEnd.Sub(globalFirst).Milliseconds()
		sp.Notes = append(sp.Notes, "child processes outlived the span root (daemonized/background); their events stay attributed to this span")
	}
}

func (sp *ToolSpan) finalizeTimes(globalFirst time.Time) {
	sp.Start = sp.startT.UTC().Format(time.RFC3339Nano)
	sp.End = sp.endT.UTC().Format(time.RFC3339Nano)
	if !globalFirst.IsZero() {
		sp.StartMs = sp.startT.Sub(globalFirst).Milliseconds()
		sp.EndMs = sp.endT.Sub(globalFirst).Milliseconds()
	}
	if sp.EndMs < sp.StartMs {
		sp.EndMs = sp.StartMs
	}
	sp.WallMs = sp.EndMs - sp.StartMs
}

func (sp *ToolSpan) finalizeResources(av spanAvail) {
	cpuOK := sp.Attribution != "time_window"
	sysOK := sp.Attribution != "time_window"
	sp.Resources = sp.acc.resources(av, cpuOK, sysOK)
	sp.TopFiles = sp.acc.topFiles(maxSpanTopFiles)
	sp.TopDestinations = sp.acc.topDests(maxSpanTopDests)
	if len(sp.acc.mutPaths) > 0 {
		sp.MutatedPaths = sp.acc.mutPaths
		if len(sp.MutatedPaths) > maxSpanMutated {
			sp.MutatedPaths = sp.MutatedPaths[:maxSpanMutated]
		}
	}
	if len(sp.PIDs) > maxSpanPIDs {
		sp.PIDs = sp.PIDs[:maxSpanPIDs]
	}
}

// reconcile checks sum(spans) + agent_self == totals on every additive
// field (max_rss is a max, checked as such).
func reconcile(spans []*ToolSpan, self, totals *acc) *SpanReconciliation {
	sum := newAcc()
	for _, sp := range spans {
		sum.merge(sp.acc)
	}
	sum.merge(self)
	var mm []string
	chk := func(name string, got, want uint64) {
		if got != want {
			mm = append(mm, fmt.Sprintf("%s: spans+agent_self=%d totals=%d", name, got, want))
		}
	}
	chk("events", uint64(sum.events), uint64(totals.events))
	chk("processes", uint64(sum.procs), uint64(totals.procs))
	chk("execs", uint64(sum.execs), uint64(totals.execs))
	chk("cpu_user_ms", sum.cpuU, totals.cpuU)
	chk("cpu_sys_ms", sum.cpuS, totals.cpuS)
	chk("max_rss_kb", sum.rss, totals.rss)
	chk("file_opens", uint64(sum.opens), uint64(totals.opens))
	chk("file_reads", uint64(sum.reads), uint64(totals.reads))
	chk("file_writes", uint64(sum.writes), uint64(totals.writes))
	chk("rw_read_bytes", sum.rwRB, totals.rwRB)
	chk("rw_write_bytes", sum.rwWB, totals.rwWB)
	chk("close_read_bytes", sum.closeRB, totals.closeRB)
	chk("close_write_bytes", sum.closeWB, totals.closeWB)
	chk("files_mutated", uint64(sum.mut), uint64(totals.mut))
	chk("net_connects", uint64(sum.connects), uint64(totals.connects))
	chk("net_sends", uint64(sum.sends), uint64(totals.sends))
	chk("net_recvs", uint64(sum.recvs), uint64(totals.recvs))
	chk("net_sent_bytes", sum.sentB, totals.sentB)
	chk("net_recv_bytes", sum.recvB, totals.recvB)
	cats := map[string]bool{}
	for k := range sum.sys {
		cats[k] = true
	}
	for k := range totals.sys {
		cats[k] = true
	}
	names := make([]string, 0, len(cats))
	for k := range cats {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		chk("syscalls."+k, sum.sys[k], totals.sys[k])
	}
	return &SpanReconciliation{OK: len(mm) == 0, Mismatches: mm}
}

// parallelize fills ParallelWith for spans whose intervals overlap.
func parallelize(spans []*ToolSpan) {
	for i, a := range spans {
		for j := i + 1; j < len(spans); j++ {
			b := spans[j]
			if !b.startT.Before(a.endT) {
				continue
			}
			if !a.startT.Before(b.endT) {
				continue
			}
			if a.Role == "hook" || b.Role == "hook" {
				continue
			}
			if len(a.ParallelWith) < maxSpanParallel {
				a.ParallelWith = append(a.ParallelWith, b.SpanID)
			}
			if len(b.ParallelWith) < maxSpanParallel {
				b.ParallelWith = append(b.ParallelWith, a.SpanID)
			}
		}
	}
}

// ---- text output ----

func humanBytes(p *uint64) string {
	if p == nil {
		return "-"
	}
	v := float64(*p)
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.1fG", v/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%.1fM", v/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.1fK", v/(1<<10))
	}
	return fmt.Sprintf("%d", *p)
}

func cpuText(r *SpanResources) string {
	if r.CPUUserMS == nil {
		return "-"
	}
	s := fmt.Sprintf("%d+%d", *r.CPUUserMS, *r.CPUSysMS)
	if r.CPUIncomplete {
		s += "*"
	}
	return s
}

func spanName(sp *ToolSpan) string {
	name := sp.Program
	if sp.ToolName != "" {
		name = sp.ToolName
	}
	detail := ""
	switch {
	case sp.Input != nil && inputString(sp.Input, "command") != "":
		detail = inputString(sp.Input, "command")
	case sp.Input != nil && inputString(sp.Input, "file_path") != "":
		detail = inputString(sp.Input, "file_path")
	case sp.Input != nil && inputString(sp.Input, "pattern") != "":
		detail = inputString(sp.Input, "pattern")
	case sp.Command != "":
		detail = sp.Command
	case len(sp.Argv) > 0:
		detail = strings.Join(sp.Argv, " ")
	}
	if sp.Role == "hook" {
		name = "hook(" + sp.ToolName + ")"
		detail = ""
	}
	detail = strings.Join(strings.Fields(detail), " ")
	if detail != "" {
		name += ": " + truncStr(detail, 70)
	}
	return name
}

var sourceShort = map[string]string{"process_tree": "proc", "harness+process_tree": "h+proc", "harness": "harn", "agent_self": "self"}

func writeSpanRow(w io.Writer, sp *ToolSpan) {
	r := sp.Resources
	flags := []string{}
	if sp.Attribution == "time_window" {
		flags = append(flags, "time_window")
	}
	if sp.OutlivedSpan {
		flags = append(flags, "outlived_span")
	}
	if len(sp.ParallelWith) > 0 {
		flags = append(flags, fmt.Sprintf("parallel×%d", len(sp.ParallelWith)))
	}
	if sp.OpenEnded {
		flags = append(flags, "open")
	}
	if sp.Status != "" && sp.Status != "ok" {
		flags = append(flags, sp.Status)
	}
	exit := "-"
	if sp.ExitCode != nil {
		exit = fmt.Sprintf("%d", *sp.ExitCode)
	}
	net := fmt.Sprintf("%d", r.NetConnects)
	if r.NetSends != nil {
		net += fmt.Sprintf("/%s/%s", humanBytes(r.NetSentBytes), humanBytes(r.NetRecvBytes))
	}
	fmt.Fprintf(w, "  %-14s %9s %9s %-6s %10s %6d %8s %8s %4d %-16s %4s %s%s\n",
		sp.SpanID, "+"+fmtDurMs(sp.StartMs), fmtDurMs(sp.WallMs), sourceShort[sp.Source],
		cpuText(r), r.FileOpens, humanBytes(r.ReadBytes), humanBytes(r.WriteBytes), r.FilesMutated,
		net, exit, spanName(sp), flagText(flags))
}

func writeSessionSpans(w io.Writer, s *SessionReport) {
	if s.AgentSelf == nil {
		return
	}
	recon := "yes"
	if s.SpanReconciliation != nil && !s.SpanReconciliation.OK {
		recon = "NO: " + strings.Join(s.SpanReconciliation.Mismatches, "; ")
	}
	agent := ""
	if s.AgentProcess != nil {
		agent = fmt.Sprintf(" (agent process %s pid %d, %s)", s.AgentProcess.Program, s.AgentProcess.PID, s.AgentProcess.ChosenBy)
	}
	fmt.Fprintf(w, "tool spans: %d%s; sum(spans)+agent_self == totals: %s; io bytes from %s\n", len(s.ToolSpans), agent, recon, s.IOBytesSource)
	fmt.Fprintf(w, "  %-14s %9s %9s %-6s %10s %6s %8s %8s %4s %-16s %4s %s\n",
		"span", "start", "wall", "source", "cpu u+s ms", "opens", "read", "write", "mut", "net conn/tx/rx", "exit", "tool / command")
	for _, sp := range s.ToolSpans {
		writeSpanRow(w, sp)
	}
	writeSpanRow(w, s.AgentSelf)
	if s.ResourceTotals != nil {
		t := s.ResourceTotals
		fmt.Fprintf(w, "  %-14s %9s %9s %-6s %10s %6d %8s %8s %4d\n", "totals", "", fmtDurMs(s.DurationMs), "", cpuText(t),
			t.FileOpens, humanBytes(t.ReadBytes), humanBytes(t.WriteBytes), t.FilesMutated)
	}
}

func writeSpansText(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "capture %s .. %s  (%d events, %d sessions)\n", rep.CaptureStart, rep.CaptureEnd, rep.TotalEvents, len(rep.Sessions))
	if h := rep.Harness; h != nil {
		fmt.Fprintf(w, "harness spans: %s, %d records, %d tool calls (%d merged with process tree, %d time-window, %d hook process spans)\n",
			h.SpansFile, h.Records, h.ToolCalls, h.ProcessMerged, h.TimeWindow, h.HookSpans)
		if h.Clock != nil {
			fmt.Fprintf(w, "clock alignment: %s, offset %.3fms, %d anchors (residual min/median/max %.1f/%.1f/%.1fms)\n",
				h.Clock.Method, h.Clock.OffsetMs, h.Clock.Anchors, h.Clock.AnchorResidualMinMs, h.Clock.AnchorResidualMedMs, h.Clock.AnchorResidualMaxMs)
		}
	}
	for _, s := range rep.Sessions {
		fmt.Fprintf(w, "\n== session %d  agent=%s root=%s (%.1fs) ==\n", s.SessionID, s.Agent, s.RootComm, float64(s.DurationMs)/1000)
		writeSessionSpans(w, s)
	}
}

func flagText(flags []string) string {
	if len(flags) == 0 {
		return ""
	}
	return "  [" + strings.Join(flags, ",") + "]"
}
