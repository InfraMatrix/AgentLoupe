// loupe-timeline turns an AgentLoupe JSONL capture into a per-session
// timeline and breakdown: a swimlane of processes, file/network markers,
// and syscall rate over time (from syscall_summary events).
//
// Usage:
//
//	loupe-timeline capture.jsonl                 # plain-text summary
//	loupe-timeline --json capture.jsonl          # machine-readable JSON
//	loupe-timeline --html out.html capture.jsonl # self-contained HTML
//
// Standard library only. The capture is streamed, never loaded whole.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxMarkersStoredPerSession = 2000 // HTML/JSON downsampling cap per lane
	maxBuckets                 = 180
	topSyscallsInSeries        = 8
)

type rawEvent struct {
	Ts           string                       `json:"ts"`
	Type         string                       `json:"type"`
	SessionID    uint64                       `json:"session_id"`
	AgentName    string                       `json:"agent_name"`
	Comm         string                       `json:"comm"`
	PID          uint32                       `json:"pid"`
	PPID         uint32                       `json:"ppid"`
	Filename     string                       `json:"filename"`
	Argv         []string                     `json:"argv"`
	Cwd          string                       `json:"cwd"`
	Path         string                       `json:"path"`
	OldPath      string                       `json:"old_path"`
	NewPath      string                       `json:"new_path"`
	Mode         string                       `json:"mode"`
	OpenFlags    uint32                       `json:"open_flags"`
	ChildPID     uint32                       `json:"child_pid"`
	Daddr        string                       `json:"daddr"`
	Dport        uint16                       `json:"dport"`
	DNS          bool                         `json:"dns"`
	Protocol     uint8                        `json:"protocol"`
	Counts       map[string]uint64            `json:"counts"`
	PerProcess   map[string]map[string]uint64 `json:"per_process_counts"`
	IntervalMS   int64                        `json:"interval_ms"`
	ExitCode     int32                        `json:"exit_code"`
	CPUUserMS    uint64                       `json:"cpu_user_ms"`
	CPUSysMS     uint64                       `json:"cpu_sys_ms"`
	MaxRSSKB     uint64                       `json:"max_rss_kb"`
	Reason       string                       `json:"reason"`
	StillRunning []uint32                     `json:"still_running"`
}

type Process struct {
	PID        uint32   `json:"pid"`
	PPID       uint32   `json:"ppid"`
	Comm       string   `json:"comm"`
	Label      string   `json:"label"`
	Filename   string   `json:"filename,omitempty"`
	Argv       []string `json:"argv,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Start      string   `json:"start"`
	End        string   `json:"end,omitempty"`
	StartMs    int64    `json:"start_ms"`
	EndMs      int64    `json:"end_ms"`
	DurationMs int64    `json:"duration_ms"`
	OpenEnded  bool     `json:"open_ended"`
	Depth      int      `json:"depth"`
	// Per-process resource use from the exit event (ABI v4): the
	// process's own thread-group CPU and peak RSS, not its children's.
	// Zero/absent on captures predating ABI v4 and for processes that
	// never exited within the capture.
	CPUUserMS uint64 `json:"cpu_user_ms,omitempty"`
	CPUSysMS  uint64 `json:"cpu_sys_ms,omitempty"`
	MaxRSSKB  uint64 `json:"max_rss_kb,omitempty"`

	startT, endT time.Time
	parent       *Process
	hasEnd       bool
}

type Marker struct {
	Ts       string `json:"ts"`
	OffsetMs int64  `json:"offset_ms"`
	Type     string `json:"type"`
	PID      uint32 `json:"pid"`
	Detail   string `json:"detail"`
}

type ProgramStat struct {
	Name      string `json:"name"`
	ExecCount int    `json:"exec_count"`
	TotalMs   int64  `json:"total_ms"`
}

type SyscallStat struct {
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Count    uint64  `json:"count"`
	Percent  float64 `json:"percent"`
}

// CategoryStat is a syscall category with its individual syscalls
// nested inside for drill-down.
type CategoryStat struct {
	Name     string         `json:"name"`
	Count    uint64         `json:"count"`
	Percent  float64        `json:"percent"`
	Syscalls []*SyscallStat `json:"syscalls"`
}

// NotableStat is an always-shown syscall of interest (see
// NotableSyscalls), with when the session first used it.
type NotableStat struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Count       uint64 `json:"count"`
	FirstSeenMs int64  `json:"first_seen_ms"`
	FirstSeen   string `json:"first_seen"`
}

// FirstSeenMark is the first interval in which the session used a
// syscall it had never used before; rendered on the swimlane.
type FirstSeenMark struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	OffsetMs int64  `json:"offset_ms"`
	Ts       string `json:"ts"`
	PID      uint32 `json:"pid,omitempty"`
}

// ProgramSyscallStat attributes a session's syscalls to one program
// (all TGIDs that exec'd it, rolled up), with its category mix.
type ProgramSyscallStat struct {
	Program    string          `json:"program"`
	PIDs       []uint32        `json:"pids"`
	Total      uint64          `json:"total"`
	Percent    float64         `json:"percent"` // share of the session's syscalls
	Categories []*CategoryStat `json:"categories"`
}

type PathStat struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type NetStat struct {
	Dest  string `json:"dest"`
	Count int    `json:"count"`
	DNS   int    `json:"dns_count"`
}

type SeriesBucket struct {
	OffsetMs int64    `json:"offset_ms"`
	Counts   []uint64 `json:"counts"` // aligned with SyscallSeries.Names
}

type SyscallSeries struct {
	BucketMs int64          `json:"bucket_ms"`
	Names    []string       `json:"names"`
	Buckets  []SeriesBucket `json:"buckets"`
}

type SessionReport struct {
	SessionID        uint64 `json:"session_id"`
	Agent            string `json:"agent"`
	RootComm         string `json:"root_comm"`
	Start            string `json:"start,omitempty"`
	End              string `json:"end,omitempty"`
	RootExit         string `json:"root_exit,omitempty"`
	RootExitMs       int64  `json:"root_exit_ms,omitempty"`
	SessionEndReason string `json:"session_end_reason,omitempty"`
	// OrphanGapMs is session_end minus root_exit: how long the
	// session outlived its root. Set only when both events exist.
	OrphanGapMs       int64                     `json:"orphan_gap_ms,omitempty"`
	StillRunning      []uint32                  `json:"still_running,omitempty"`
	DurationMs        int64                     `json:"duration_ms"`
	Events            int                       `json:"events"`
	Processes         []*Process                `json:"processes"`
	Markers           []*Marker                 `json:"markers"`
	MarkerTotal       int                       `json:"marker_total"`
	ProgramsByCount   []*ProgramStat            `json:"top_programs_by_exec_count"`
	ProgramsByTime    []*ProgramStat            `json:"top_programs_by_wall_time"`
	Syscalls          []*SyscallStat            `json:"syscall_distribution"`
	SyscallCategories []*CategoryStat           `json:"syscall_categories"`
	Notable           []*NotableStat            `json:"notable_syscalls"`
	FirstSeen         []*FirstSeenMark          `json:"first_seen_syscalls"`
	ProgramSyscalls   []*ProgramSyscallStat     `json:"program_syscall_attribution"`
	SyscallSeries     *SyscallSeries            `json:"syscall_series,omitempty"`
	SeriesByCategory  map[string]*SyscallSeries `json:"syscall_series_by_category,omitempty"`
	HasSyscallSummary bool                      `json:"has_syscall_summary"`
	Files             []*PathStat               `json:"files_touched"`
	Network           []*NetStat                `json:"network_destinations"`
}

type Report struct {
	CaptureStart      string           `json:"capture_start,omitempty"`
	CaptureEnd        string           `json:"capture_end,omitempty"`
	DurationMs        int64            `json:"duration_ms"`
	TotalEvents       int              `json:"total_events"`
	SkippedLines      int              `json:"skipped_lines"`
	HasSyscallSummary bool             `json:"has_syscall_summary"`
	Notes             []string         `json:"notes,omitempty"`
	Sessions          []*SessionReport `json:"sessions"`
}

// ---- streaming builder ----

type summaryPoint struct {
	t          time.Time
	counts     map[string]uint64
	perProcess map[string]map[string]uint64 // tgid (decimal string) -> name -> delta
}

type sessionBuilder struct {
	rep          *SessionReport
	first        time.Time
	last         time.Time
	rootExitT    time.Time
	sessionEndT  time.Time
	open         map[uint32]*Process
	execCount    map[string]int
	files        map[string]int
	net          map[string]*NetStat
	sysTotals    map[string]uint64
	progTotals   map[uint32]map[string]uint64 // tgid -> syscall -> total
	hasPerProc   bool
	summaries    []summaryPoint
	markerSeen   int
	markerStride int
}

func (b *sessionBuilder) addMarker(m *Marker) {
	b.rep.MarkerTotal++
	b.markerSeen++
	if b.markerStride <= 1 {
		b.rep.Markers = append(b.rep.Markers, m)
	} else if (b.markerSeen-1)%b.markerStride == 0 {
		b.rep.Markers = append(b.rep.Markers, m)
	}
	if len(b.rep.Markers) > maxMarkersStoredPerSession {
		// Thin by 2x so stored markers stay spread over the whole session.
		thinned := b.rep.Markers[:0]
		for i, mk := range b.rep.Markers {
			if i%2 == 0 {
				thinned = append(thinned, mk)
			}
		}
		b.rep.Markers = thinned
		if b.markerStride < 1 {
			b.markerStride = 1
		}
		b.markerStride *= 2
	}
}

type builder struct {
	sessions    map[uint64]*sessionBuilder
	order       []*sessionBuilder
	globalFirst time.Time
	globalLast  time.Time
	total       int
	skipped     int
	hasSummary  bool
	hasPerProc  bool
}

func (b *builder) session(ev *rawEvent) *sessionBuilder {
	s, ok := b.sessions[ev.SessionID]
	if !ok {
		s = &sessionBuilder{
			rep:          &SessionReport{SessionID: ev.SessionID, Agent: ev.AgentName},
			open:         map[uint32]*Process{},
			execCount:    map[string]int{},
			files:        map[string]int{},
			net:          map[string]*NetStat{},
			sysTotals:    map[string]uint64{},
			progTotals:   map[uint32]map[string]uint64{},
			markerStride: 1,
		}
		b.sessions[ev.SessionID] = s
		b.order = append(b.order, s)
	}
	if s.rep.Agent == "" {
		s.rep.Agent = ev.AgentName
	}
	return s
}

func base(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

func (s *sessionBuilder) getOpen(ev *rawEvent, ts time.Time, pid, ppid uint32) *Process {
	if pid == 0 {
		return nil
	}
	if p, ok := s.open[pid]; ok {
		return p
	}
	p := &Process{PID: pid, PPID: ppid, Comm: ev.Comm, Label: ev.Comm, startT: ts}
	if p.Label == "" {
		p.Label = fmt.Sprintf("pid %d", pid)
	}
	s.rep.Processes = append(s.rep.Processes, p)
	s.open[pid] = p
	return p
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 0:
		return ""
	default:
		return fmt.Sprintf("proto%d", p)
	}
}

func (b *builder) add(ev *rawEvent) {
	b.total++
	ts, hasTS := parseTS(ev.Ts)
	s := b.session(ev)
	s.rep.Events++
	if hasTS {
		if s.first.IsZero() || ts.Before(s.first) {
			s.first = ts
		}
		if ts.After(s.last) {
			s.last = ts
		}
		if b.globalFirst.IsZero() || ts.Before(b.globalFirst) {
			b.globalFirst = ts
		}
		if ts.After(b.globalLast) {
			b.globalLast = ts
		}
	}
	switch ev.Type {
	case "root_exit":
		if hasTS && s.rootExitT.IsZero() {
			s.rootExitT = ts
		}
		// root_exit mirrors the root exit's resource fields (ABI v4);
		// apply them if the exit event itself was missed.
		if ev.CPUUserMS != 0 || ev.CPUSysMS != 0 || ev.MaxRSSKB != 0 {
			for i := len(s.rep.Processes) - 1; i >= 0; i-- {
				if p := s.rep.Processes[i]; p.PID == ev.PID {
					if p.CPUUserMS == 0 && p.CPUSysMS == 0 && p.MaxRSSKB == 0 {
						p.CPUUserMS, p.CPUSysMS, p.MaxRSSKB = ev.CPUUserMS, ev.CPUSysMS, ev.MaxRSSKB
					}
					break
				}
			}
		}
	case "session_end":
		if hasTS {
			s.sessionEndT = ts
		}
		s.rep.SessionEndReason = ev.Reason
		s.rep.StillRunning = ev.StillRunning
	case "session_start":
		if s.rep.RootComm == "" {
			s.rep.RootComm = ev.Comm
		}
		if hasTS {
			s.getOpen(ev, ts, ev.PID, ev.PPID)
		}
	case "exec":
		name := base(ev.Filename)
		if name == "" {
			name = ev.Comm
		}
		if name != "" {
			s.execCount[name]++
		}
		if hasTS {
			p := s.getOpen(ev, ts, ev.PID, ev.PPID)
			if p != nil {
				if ev.PPID != 0 {
					p.PPID = ev.PPID
				}
				if ev.Comm != "" {
					p.Comm = ev.Comm
				}
				p.Filename = ev.Filename
				if name != "" {
					p.Label = name
				}
				p.Argv = ev.Argv
				p.Cwd = ev.Cwd
				if ts.Before(p.startT) {
					p.startT = ts
				}
			}
		}
		if s.rep.RootComm == "" {
			s.rep.RootComm = ev.Comm
		}
	case "fork":
		if hasTS && ev.ChildPID != 0 {
			child := s.getOpen(ev, ts, ev.ChildPID, ev.PID)
			if child != nil {
				child.PPID = ev.PID
				if ts.Before(child.startT) {
					child.startT = ts
				}
			}
			// Ensure the parent exists too (root may only appear via fork).
			s.getOpen(ev, ts, ev.PID, ev.PPID)
		}
	case "exit":
		if hasTS {
			p := s.getOpen(ev, ts, ev.PID, ev.PPID)
			if p != nil {
				p.endT = ts
				p.hasEnd = true
				p.CPUUserMS, p.CPUSysMS, p.MaxRSSKB = ev.CPUUserMS, ev.CPUSysMS, ev.MaxRSSKB
				delete(s.open, ev.PID)
			}
		}
	case "file_open", "file_unlink", "file_chmod":
		if ev.Path != "" {
			s.files[ev.Path]++
		}
		if hasTS {
			detail := ev.Path
			if ev.Type == "file_open" {
				detail = fmt.Sprintf("%s flags=%d", ev.Path, ev.OpenFlags)
			} else if ev.Type == "file_chmod" && ev.Mode != "" {
				detail = fmt.Sprintf("%s mode=%s", ev.Path, ev.Mode)
			}
			s.addMarker(&Marker{Ts: ev.Ts, Type: ev.Type, PID: ev.PID, Detail: detail})
		}
	case "file_rename":
		if ev.OldPath != "" {
			s.files[ev.OldPath]++
		}
		if ev.NewPath != "" {
			s.files[ev.NewPath]++
		}
		if hasTS {
			s.addMarker(&Marker{Ts: ev.Ts, Type: ev.Type, PID: ev.PID, Detail: ev.OldPath + " -> " + ev.NewPath})
		}
	case "net_connect":
		dest := fmt.Sprintf("%s:%d", ev.Daddr, ev.Dport)
		ns, ok := s.net[dest]
		if !ok {
			ns = &NetStat{Dest: dest}
			s.net[dest] = ns
		}
		ns.Count++
		if ev.DNS {
			ns.DNS++
		}
		if hasTS {
			detail := dest
			if pn := protoName(ev.Protocol); pn != "" {
				detail = pn + " " + detail
			}
			if ev.DNS {
				detail += " (DNS)"
			}
			s.addMarker(&Marker{Ts: ev.Ts, Type: "net_connect", PID: ev.PID, Detail: detail})
		}
	case "syscall_summary":
		b.hasSummary = true
		s.rep.HasSyscallSummary = true
		for name, c := range ev.Counts {
			s.sysTotals[name] += c
		}
		for pidStr, pc := range ev.PerProcess {
			if len(pc) == 0 {
				continue
			}
			s.hasPerProc = true
			b.hasPerProc = true
			pid64, perr := strconv.ParseUint(pidStr, 10, 32)
			if perr != nil {
				continue
			}
			m, ok := s.progTotals[uint32(pid64)]
			if !ok {
				m = map[string]uint64{}
				s.progTotals[uint32(pid64)] = m
			}
			for name, c := range pc {
				m[name] += c
			}
		}
		if hasTS && len(ev.Counts) > 0 {
			cp := make(map[string]uint64, len(ev.Counts))
			for k, v := range ev.Counts {
				cp[k] = v
			}
			pp := make(map[string]map[string]uint64, len(ev.PerProcess))
			for pid, pc := range ev.PerProcess {
				inner := make(map[string]uint64, len(pc))
				for k, v := range pc {
					inner[k] = v
				}
				pp[pid] = inner
			}
			s.summaries = append(s.summaries, summaryPoint{t: ts, counts: cp, perProcess: pp})
		}
	}
}

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Build streams JSONL from r and returns the aggregated report.
func Build(r io.Reader) (*Report, error) {
	b := &builder{sessions: map[uint64]*sessionBuilder{}}
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			var ev rawEvent
			if jerr := json.Unmarshal([]byte(line), &ev); jerr != nil {
				b.skipped++
			} else {
				b.add(&ev)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return b.finish(), nil
}

func (b *builder) finish() *Report {
	rep := &Report{
		TotalEvents: b.total, SkippedLines: b.skipped, HasSyscallSummary: b.hasSummary,
		Sessions: []*SessionReport{},
	}
	if !b.globalFirst.IsZero() {
		rep.CaptureStart = b.globalFirst.Format(time.RFC3339Nano)
		rep.CaptureEnd = b.globalLast.Format(time.RFC3339Nano)
		rep.DurationMs = b.globalLast.Sub(b.globalFirst).Milliseconds()
	}
	if !b.hasSummary {
		rep.Notes = append(rep.Notes, "no syscall_summary events in this capture (rebuild/re-run with --enable-syscall-summary for syscall rates); all other sections are complete")
	} else if !b.hasPerProc {
		rep.Notes = append(rep.Notes, "syscall_summary events have no per_process_counts (capture predates ABI v3): per-program attribution unavailable; session-level categories and rates are complete")
	}
	for _, s := range b.order {
		r := s.rep
		if !s.first.IsZero() {
			r.Start = s.first.Format(time.RFC3339Nano)
			r.End = s.last.Format(time.RFC3339Nano)
			r.DurationMs = s.last.Sub(s.first).Milliseconds()
		}
		if !s.rootExitT.IsZero() {
			r.RootExit = s.rootExitT.Format(time.RFC3339Nano)
			if !b.globalFirst.IsZero() {
				r.RootExitMs = s.rootExitT.Sub(b.globalFirst).Milliseconds()
			}
			if !s.sessionEndT.IsZero() {
				r.OrphanGapMs = s.sessionEndT.Sub(s.rootExitT).Milliseconds()
			}
		}
		// Finalise processes.
		for _, p := range r.Processes {
			if !p.hasEnd {
				p.endT = b.globalLast
				p.OpenEnded = true
			}
			p.Start = p.startT.Format(time.RFC3339Nano)
			if p.hasEnd || !p.OpenEnded {
				p.End = p.endT.Format(time.RFC3339Nano)
			} else {
				p.End = p.endT.Format(time.RFC3339Nano) // capture end
			}
			if !b.globalFirst.IsZero() {
				p.StartMs = p.startT.Sub(b.globalFirst).Milliseconds()
				p.EndMs = p.endT.Sub(b.globalFirst).Milliseconds()
			}
			if p.EndMs < p.StartMs {
				p.EndMs = p.StartMs
			}
			p.DurationMs = p.EndMs - p.StartMs
		}
		// Parent linkage: latest-starting process with matching pid that
		// was alive when this process started.
		byPID := map[uint32][]*Process{}
		for _, p := range r.Processes {
			byPID[p.PID] = append(byPID[p.PID], p)
		}
		for _, p := range r.Processes {
			if p.PPID == 0 || p.PPID == p.PID {
				continue
			}
			var best *Process
			for _, cand := range byPID[p.PPID] {
				if cand == p || cand.PID != p.PPID {
					continue
				}
				if cand.startT.After(p.startT) {
					continue
				}
				if cand.hasEnd && cand.endT.Before(p.startT) {
					continue
				}
				if best == nil || cand.startT.After(best.startT) {
					best = cand
				}
			}
			p.parent = best
		}
		// Tree order (parent before children) + depth via DFS.
		children := map[*Process][]*Process{}
		var roots []*Process
		for _, p := range r.Processes {
			if p.parent != nil {
				children[p.parent] = append(children[p.parent], p)
			} else {
				roots = append(roots, p)
			}
		}
		byStart := func(ps []*Process) {
			sort.SliceStable(ps, func(i, j int) bool {
				if !ps[i].startT.Equal(ps[j].startT) {
					return ps[i].startT.Before(ps[j].startT)
				}
				return ps[i].PID < ps[j].PID
			})
		}
		byStart(roots)
		for _, c := range children {
			byStart(c)
		}
		var ordered []*Process
		visited := map[*Process]bool{}
		var visit func(p *Process, depth int)
		visit = func(p *Process, depth int) {
			if visited[p] {
				return
			}
			visited[p] = true
			p.Depth = depth
			ordered = append(ordered, p)
			for _, c := range children[p] {
				visit(c, depth+1)
			}
		}
		for _, root := range roots {
			visit(root, 0)
		}
		for _, p := range r.Processes { // cycles / orphans
			if !visited[p] {
				visit(p, 0)
			}
		}
		r.Processes = ordered
		// Marker offsets.
		for _, m := range r.Markers {
			if t, ok := parseTS(m.Ts); ok && !b.globalFirst.IsZero() {
				m.OffsetMs = t.Sub(b.globalFirst).Milliseconds()
			}
		}
		if r.MarkerTotal > len(r.Markers) {
			rep.Notes = append(rep.Notes, fmt.Sprintf("session %d: markers downsampled for display (%d of %d shown, evenly thinned); breakdown counts are exact", r.SessionID, len(r.Markers), r.MarkerTotal))
		}
		// Breakdowns. Map each TGID to the program it exec'd (latest
		// process instance for that pid wins) for per-program rollups.
		pidLabel := map[uint32]string{}
		pidLabelStart := map[uint32]time.Time{}
		for _, p := range r.Processes {
			if prev, ok := pidLabelStart[p.PID]; !ok || p.startT.After(prev) {
				pidLabel[p.PID] = p.Label
				pidLabelStart[p.PID] = p.startT
			}
		}
		r.ProgramsByCount = topPrograms(s.execCount, r.Processes, true)
		r.ProgramsByTime = topPrograms(s.execCount, r.Processes, false)
		r.Syscalls, r.SyscallCategories, r.SyscallSeries, r.SeriesByCategory, r.Notable, r.FirstSeen, r.ProgramSyscalls =
			syscallBreakdown(s, b.globalFirst, rep.DurationMs, pidLabel)
		for path, c := range s.files {
			r.Files = append(r.Files, &PathStat{path, c})
		}
		sort.Slice(r.Files, func(i, j int) bool {
			if r.Files[i].Count != r.Files[j].Count {
				return r.Files[i].Count > r.Files[j].Count
			}
			return r.Files[i].Path < r.Files[j].Path
		})
		if len(r.Files) > 20 {
			r.Files = r.Files[:20]
		}
		for _, ns := range s.net {
			r.Network = append(r.Network, ns)
		}
		sort.Slice(r.Network, func(i, j int) bool {
			if r.Network[i].Count != r.Network[j].Count {
				return r.Network[i].Count > r.Network[j].Count
			}
			return r.Network[i].Dest < r.Network[j].Dest
		})
		if len(r.Network) > 20 {
			r.Network = r.Network[:20]
		}
		rep.Sessions = append(rep.Sessions, r)
	}
	sort.SliceStable(rep.Sessions, func(i, j int) bool {
		return rep.Sessions[i].Start < rep.Sessions[j].Start
	})
	return rep
}

func topPrograms(execCount map[string]int, procs []*Process, byCount bool) []*ProgramStat {
	stats := map[string]*ProgramStat{}
	get := func(name string) *ProgramStat {
		if name == "" {
			name = "?"
		}
		s, ok := stats[name]
		if !ok {
			s = &ProgramStat{Name: name}
			stats[name] = s
		}
		return s
	}
	for name, c := range execCount {
		get(name).ExecCount = c
	}
	for _, p := range procs {
		get(p.Label).TotalMs += p.DurationMs
	}
	out := make([]*ProgramStat, 0, len(stats))
	for _, s := range stats {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if byCount {
			if out[i].ExecCount != out[j].ExecCount {
				return out[i].ExecCount > out[j].ExecCount
			}
		} else {
			if out[i].TotalMs != out[j].TotalMs {
				return out[i].TotalMs > out[j].TotalMs
			}
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

func sortSyscallStats(ss []*SyscallStat) {
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Count != ss[j].Count {
			return ss[i].Count > ss[j].Count
		}
		return ss[i].Name < ss[j].Name
	})
}

// categoryStats groups a name->count map into categories (in
// CategoryNames display order) with individual syscalls nested inside.
func categoryStats(totals map[string]uint64, grand uint64) []*CategoryStat {
	byCat := map[string][]*SyscallStat{}
	catTotal := map[string]uint64{}
	for name, c := range totals {
		cat := SyscallCategory(name)
		byCat[cat] = append(byCat[cat], &SyscallStat{Name: name, Category: cat, Count: c})
		catTotal[cat] += c
	}
	out := []*CategoryStat{}
	for _, cat := range CategoryNames {
		ss, ok := byCat[cat]
		if !ok {
			continue
		}
		sortSyscallStats(ss)
		for _, s := range ss {
			if grand > 0 {
				s.Percent = float64(s.Count) * 100 / float64(grand)
			}
		}
		cs := &CategoryStat{Name: cat, Count: catTotal[cat], Syscalls: ss}
		if grand > 0 {
			cs.Percent = float64(cs.Count) * 100 / float64(grand)
		}
		out = append(out, cs)
	}
	return out
}

// buildSeries buckets summary points into a stacked series. mapName
// folds a raw syscall name into a series key (category name, own name,
// or "" to drop). Top-N keys by total volume, the rest fold to "other".
func buildSeries(summaries []summaryPoint, globalFirst time.Time, captureDurMs int64, mapName func(string) (string, bool)) *SyscallSeries {
	totals := map[string]uint64{}
	for _, pt := range summaries {
		for name, c := range pt.counts {
			if k, ok := mapName(name); ok {
				totals[k] += c
			}
		}
	}
	if len(totals) == 0 {
		return nil
	}
	keys := make([]string, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if totals[keys[i]] != totals[keys[j]] {
			return totals[keys[i]] > totals[keys[j]]
		}
		return keys[i] < keys[j]
	})
	names := keys
	if len(keys) > topSyscallsInSeries {
		names = append(append([]string{}, keys[:topSyscallsInSeries]...), "other")
	}
	nameIdx := map[string]int{}
	for i, n := range names {
		nameIdx[n] = i
	}
	bucketMs := int64(1000)
	if captureDurMs > 0 {
		bucketMs = (captureDurMs + maxBuckets - 1) / maxBuckets
		if bucketMs < 1 {
			bucketMs = 1
		}
	}
	nBuckets := 1
	if captureDurMs > 0 {
		nBuckets = int(captureDurMs/bucketMs) + 1
		if nBuckets > maxBuckets+1 {
			nBuckets = maxBuckets + 1
		}
	}
	buckets := make([]SeriesBucket, nBuckets)
	for i := range buckets {
		buckets[i] = SeriesBucket{OffsetMs: int64(i) * bucketMs, Counts: make([]uint64, len(names))}
	}
	for _, pt := range summaries {
		off := pt.t.Sub(globalFirst).Milliseconds()
		idx := 0
		if bucketMs > 0 {
			idx = int(off / bucketMs)
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(buckets) {
			idx = len(buckets) - 1
		}
		for name, c := range pt.counts {
			k, ok := mapName(name)
			if !ok {
				continue
			}
			i, ok := nameIdx[k]
			if !ok {
				i, ok = nameIdx["other"]
				if !ok {
					continue
				}
			}
			buckets[idx].Counts[i] += c
		}
	}
	return &SyscallSeries{BucketMs: bucketMs, Names: names, Buckets: buckets}
}

func syscallBreakdown(s *sessionBuilder, globalFirst time.Time, captureDurMs int64, pidLabel map[uint32]string) (
	dist []*SyscallStat, categories []*CategoryStat, catSeries *SyscallSeries,
	byCatSeries map[string]*SyscallSeries, notable []*NotableStat,
	firstSeen []*FirstSeenMark, programs []*ProgramSyscallStat) {
	if len(s.sysTotals) == 0 {
		return nil, nil, nil, nil, nil, nil, nil
	}
	var total uint64
	for _, c := range s.sysTotals {
		total += c
	}
	for name, c := range s.sysTotals {
		pct := 0.0
		if total > 0 {
			pct = float64(c) * 100 / float64(total)
		}
		dist = append(dist, &SyscallStat{Name: name, Category: SyscallCategory(name), Count: c, Percent: pct})
	}
	sortSyscallStats(dist)
	categories = categoryStats(s.sysTotals, total)

	// Time-ordered summaries drive first-seen and the rate series
	// (input order is not trusted: captures may interleave sessions).
	summaries := append([]summaryPoint{}, s.summaries...)
	sort.SliceStable(summaries, func(i, j int) bool { return summaries[i].t.Before(summaries[j].t) })

	seen := map[string]bool{}
	firstAt := map[string]*FirstSeenMark{}
	for _, pt := range summaries {
		names := make([]string, 0, len(pt.counts))
		for name := range pt.counts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if pt.counts[name] == 0 || seen[name] {
				continue
			}
			seen[name] = true
			mark := &FirstSeenMark{
				Name: name, Category: SyscallCategory(name),
				Ts: pt.t.Format(time.RFC3339Nano),
			}
			if !globalFirst.IsZero() {
				mark.OffsetMs = pt.t.Sub(globalFirst).Milliseconds()
			}
			// Attribute the first use to a pid that used it in this
			// interval, when per-process counts are available.
			pids := make([]string, 0, len(pt.perProcess))
			for pid := range pt.perProcess {
				pids = append(pids, pid)
			}
			sort.Strings(pids)
			for _, pidStr := range pids {
				if pt.perProcess[pidStr][name] > 0 {
					if pid64, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
						mark.PID = uint32(pid64)
					}
					break
				}
			}
			firstAt[name] = mark
			firstSeen = append(firstSeen, mark)
		}
	}
	sort.Slice(firstSeen, func(i, j int) bool {
		if firstSeen[i].OffsetMs != firstSeen[j].OffsetMs {
			return firstSeen[i].OffsetMs < firstSeen[j].OffsetMs
		}
		return firstSeen[i].Name < firstSeen[j].Name
	})
	for name, c := range s.sysTotals {
		if !isNotable(name) {
			continue
		}
		ns := &NotableStat{Name: name, Category: SyscallCategory(name), Count: c}
		if m, ok := firstAt[name]; ok {
			ns.FirstSeenMs, ns.FirstSeen = m.OffsetMs, m.Ts
		}
		notable = append(notable, ns)
	}
	sort.Slice(notable, func(i, j int) bool {
		if notable[i].FirstSeenMs != notable[j].FirstSeenMs {
			return notable[i].FirstSeenMs < notable[j].FirstSeenMs
		}
		return notable[i].Name < notable[j].Name
	})

	// Rate series: categories by default (drill into one category via
	// byCatSeries). Category order in the stack follows volume.
	catSeries = buildSeries(summaries, globalFirst, captureDurMs, func(name string) (string, bool) {
		return SyscallCategory(name), true
	})
	byCatSeries = map[string]*SyscallSeries{}
	for _, cat := range CategoryNames {
		ser := buildSeries(summaries, globalFirst, captureDurMs, func(name string) (string, bool) {
			if SyscallCategory(name) == cat {
				return name, true
			}
			return "", false
		})
		if ser != nil {
			byCatSeries[cat] = ser
		}
	}

	// Per-program attribution: roll TGIDs up to the program they exec'd.
	type progAgg struct {
		name   string
		pids   []uint32
		totals map[string]uint64
		total  uint64
	}
	byProg := map[string]*progAgg{}
	for pid, totalsByName := range s.progTotals {
		prog := pidLabel[pid]
		if prog == "" {
			prog = fmt.Sprintf("pid %d", pid)
		}
		a, ok := byProg[prog]
		if !ok {
			a = &progAgg{name: prog, totals: map[string]uint64{}}
			byProg[prog] = a
		}
		a.pids = append(a.pids, pid)
		for name, c := range totalsByName {
			a.totals[name] += c
			a.total += c
		}
	}
	for _, a := range byProg {
		sort.Slice(a.pids, func(i, j int) bool { return a.pids[i] < a.pids[j] })
		ps := &ProgramSyscallStat{Program: a.name, PIDs: a.pids, Total: a.total, Categories: categoryStats(a.totals, a.total)}
		if total > 0 {
			ps.Percent = float64(a.total) * 100 / float64(total)
		}
		programs = append(programs, ps)
	}
	sort.Slice(programs, func(i, j int) bool {
		if programs[i].Total != programs[j].Total {
			return programs[i].Total > programs[j].Total
		}
		return programs[i].Program < programs[j].Program
	})
	if len(programs) > 20 {
		programs = programs[:20]
	}
	return dist, categories, catSeries, byCatSeries, notable, firstSeen, programs
}

// ---- outputs ----

func fmtDurMs(ms int64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.2fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func writeText(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "capture %s .. %s  (%d events, %d sessions)\n", rep.CaptureStart, rep.CaptureEnd, rep.TotalEvents, len(rep.Sessions))
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	for _, s := range rep.Sessions {
		fmt.Fprintf(w, "\n== session %d  agent=%s root=%s  %s .. %s (%.1fs, %d events) ==\n",
			s.SessionID, s.Agent, s.RootComm, s.Start, s.End, float64(s.DurationMs)/1000, s.Events)
		if s.RootExit != "" {
			if s.SessionEndReason != "" {
				fmt.Fprintf(w, "root exit: +%s, orphan gap to session_end: %s (reason %s", fmtDurMs(s.RootExitMs), fmtDurMs(s.OrphanGapMs), s.SessionEndReason)
				if len(s.StillRunning) > 0 {
					fmt.Fprintf(w, ", still running: %v", s.StillRunning)
				}
				fmt.Fprintln(w, ")")
			} else {
				fmt.Fprintf(w, "root exit: +%s (session still open at capture end)\n", fmtDurMs(s.RootExitMs))
			}
		}
		fmt.Fprintf(w, "top programs by exec count:")
		for _, p := range s.ProgramsByCount {
			fmt.Fprintf(w, " %s=%d", p.Name, p.ExecCount)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "top programs by wall time:")
		for _, p := range s.ProgramsByTime {
			fmt.Fprintf(w, " %s=%.1fs", p.Name, float64(p.TotalMs)/1000)
		}
		fmt.Fprintln(w)
		if len(s.Syscalls) == 0 {
			fmt.Fprintln(w, "syscalls: (no syscall_summary data)")
		} else {
			fmt.Fprintln(w, "syscall categories (drill-down indented):")
			for _, cat := range s.SyscallCategories {
				fmt.Fprintf(w, "  %-10s %8d  %5.1f%%\n", cat.Name, cat.Count, cat.Percent)
				for _, sc := range cat.Syscalls {
					fmt.Fprintf(w, "    %-22s %8d  %5.1f%%\n", sc.Name, sc.Count, sc.Percent)
				}
			}
		}
		if len(s.Notable) > 0 {
			fmt.Fprintln(w, "notable syscalls (first seen, count):")
			for _, n := range s.Notable {
				fmt.Fprintf(w, "  %-14s first=+%s count=%d\n", n.Name, fmtDurMs(n.FirstSeenMs), n.Count)
			}
		}
		if len(s.ProgramSyscalls) > 0 {
			fmt.Fprintln(w, "syscalls by program:")
			for _, p := range s.ProgramSyscalls {
				cats := ""
				for i, c := range p.Categories {
					if i >= 3 {
						break
					}
					if cats != "" {
						cats += ", "
					}
					cats += fmt.Sprintf("%s %.0f%%", c.Name, float64(c.Count)*100/float64(maxU64(p.Total, 1)))
				}
				fmt.Fprintf(w, "  %-16s %8d  %5.1f%% of session  (%s)\n", p.Program, p.Total, p.Percent, cats)
			}
		}
		if len(s.FirstSeen) > 0 {
			fmt.Fprintf(w, "first-seen syscalls:")
			for _, m := range s.FirstSeen {
				fmt.Fprintf(w, " +%s %s", fmtDurMs(m.OffsetMs), m.Name)
			}
			fmt.Fprintln(w)
		}
		if len(s.Files) > 0 {
			fmt.Fprintf(w, "files touched (top):")
			for _, f := range s.Files {
				fmt.Fprintf(w, " %s(%d)", f.Path, f.Count)
			}
			fmt.Fprintln(w)
		}
		if len(s.Network) > 0 {
			fmt.Fprintf(w, "network:")
			for _, n := range s.Network {
				fmt.Fprintf(w, " %s(%d)", n.Dest, n.Count)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "process tree:")
		for _, p := range s.Processes {
			indent := strings.Repeat("  ", p.Depth)
			endNote := ""
			if p.OpenEnded {
				endNote = " (still running at capture end)"
			}
			resNote := ""
			if p.CPUUserMS != 0 || p.CPUSysMS != 0 || p.MaxRSSKB != 0 {
				resNote = fmt.Sprintf("  cpu_user=%dms cpu_sys=%dms max_rss=%dKiB", p.CPUUserMS, p.CPUSysMS, p.MaxRSSKB)
			}
			fmt.Fprintf(w, "  %s%s pid=%d ppid=%d  %.3fs%s%s\n", indent, p.Label, p.PID, p.PPID, float64(p.DurationMs)/1000, endNote, resNote)
			if len(p.Argv) > 0 {
				fmt.Fprintf(w, "  %s  argv: %s  cwd: %s\n", indent, strings.Join(p.Argv, " "), p.Cwd)
			}
		}
	}
}

func main() {
	htmlOut := flag.String("html", "", "write a self-contained HTML timeline to this file")
	asJSON := flag.Bool("json", false, "write the breakdown as JSON to stdout")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: loupe-timeline [--html out.html] [--json] capture.jsonl")
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rep, err := Build(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *htmlOut != "" {
		var hf *os.File
		hf, err = os.Create(*htmlOut)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := renderHTML(hf, rep); err != nil {
			hf.Close()
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		hf.Close()
		fmt.Fprintf(os.Stderr, "loupe-timeline: wrote %s\n", *htmlOut)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	if *htmlOut == "" {
		writeText(os.Stdout, rep)
	}
}
