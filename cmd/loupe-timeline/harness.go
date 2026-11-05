// Harness spans: correlate tool-call records written by a harness hook
// (hooks/agentloupe_hook.py, Claude Code PreToolUse/PostToolUse) with the
// process-tree spans built from kernel events.
//
// Clock alignment. Kernel event `ts` = wall_base + CLOCK_MONOTONIC
// (bpf_ktime_get_ns), where wall_base is sampled once at loader start
// and written to the capture_meta record. The hook records both
// CLOCK_REALTIME (ts_ns) and CLOCK_MONOTONIC (mono_ns), so when both
// capture_meta and mono_ns are present the conversion is exact:
// capture_t = wall_base_unix_ns + mono_ns ("monotonic"). Without them we
// fall back to CLOCK_REALTIME, which drifts from capture time by any
// suspend or NTP step since loader start; the offset is then estimated
// from "pid anchors" — the hook's own process appears in the capture,
// and the hook's timestamp must fall after that process started — and
// the method is reported as "realtime_pid_anchored" (or
// "realtime_assumed" with no anchors). Every method reports the anchor
// residuals (hook ts minus its own process start) as a cross-check: they
// must be >= 0 and small (interpreter startup).
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"
)

const hookScriptMarker = "agentloupe_hook"

type hookRec struct {
	Event       string         `json:"event"`
	ToolName    string         `json:"tool_name"`
	ToolUseID   string         `json:"tool_use_id"`
	SessionID   string         `json:"session_id"`
	TsNS        int64          `json:"ts_ns"`
	MonoNS      int64          `json:"mono_ns"`
	PID         uint32         `json:"pid"`
	PPID        uint32         `json:"ppid"`
	Ancestors   []uint32       `json:"ancestors"`
	Input       map[string]any `json:"input"`
	DurationMs  *int64         `json:"duration_ms"`
	Error       string         `json:"error"`
	Interrupted bool           `json:"interrupted"`

	t time.Time // capture time domain, set by alignment
}

// ClockInfo reports how hook timestamps were mapped to capture time.
type ClockInfo struct {
	// Method: "monotonic" (exact: capture_meta wall_base + hook mono_ns),
	// "realtime_pid_anchored" (CLOCK_REALTIME shifted by an offset
	// estimated from the hook processes' own exec times), or
	// "realtime_assumed" (CLOCK_REALTIME used as-is: no anchors).
	Method string `json:"method"`
	// OffsetMs is hook CLOCK_REALTIME minus capture time, as applied
	// (realtime methods) or as measured (monotonic method, from the
	// records carrying both clocks): the realtime/monotonic drift.
	OffsetMs float64 `json:"offset_ms"`
	// Anchors: hook records whose own process was found in the capture.
	// Residual = aligned hook ts - that process's start; must be >= 0.
	Anchors             int     `json:"anchors"`
	AnchorResidualMinMs float64 `json:"anchor_residual_min_ms,omitempty"`
	AnchorResidualMedMs float64 `json:"anchor_residual_median_ms,omitempty"`
	AnchorResidualMaxMs float64 `json:"anchor_residual_max_ms,omitempty"`
	NegativeResiduals   int     `json:"negative_residuals,omitempty"`
	Note                string  `json:"note,omitempty"`
}

// HarnessInfo summarizes the hook spans file correlation.
type HarnessInfo struct {
	SpansFile     string     `json:"spans_file,omitempty"`
	Records       int        `json:"records"`
	SkippedLines  int        `json:"skipped_lines,omitempty"`
	ToolCalls     int        `json:"tool_calls"`
	ProcessMerged int        `json:"merged_with_process_tree"`
	TimeWindow    int        `json:"time_window"`
	HookSpans     int        `json:"hook_process_spans"`
	NoSession     int        `json:"no_matching_session,omitempty"`
	NoPost        int        `json:"no_post_record,omitempty"`
	Clock         *ClockInfo `json:"clock"`
	Notes         []string   `json:"notes,omitempty"`
}

func loadHookRecs(r io.Reader) ([]*hookRec, int) {
	var out []*hookRec
	skipped := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var h hookRec
		if err := json.Unmarshal([]byte(line), &h); err != nil || h.Event == "" || (h.TsNS == 0 && h.MonoNS == 0) {
			skipped++
			continue
		}
		out = append(out, &h)
	}
	return out, skipped
}

// harnessCall is one tool_use_id: pre -> post.
type harnessCall struct {
	id, tool   string
	pre, post  *hookRec
	start, end time.Time
	sess       *sessionBuilder
	matched    []*ToolSpan
	span       *ToolSpan
}

type hookInst struct {
	s *sessionBuilder
	p *inst
}

func isHookInst(p *inst) bool {
	for _, a := range p.argv {
		if strings.Contains(a, hookScriptMarker) {
			return true
		}
	}
	return false
}

// alignHooks sets h.t for every record and reports the method.
func (b *builder) alignHooks(recs []*hookRec, hookInsts map[uint32][]hookInst) *ClockInfo {
	ci := &ClockInfo{}
	var wallBase int64
	if b.meta != nil {
		wallBase = b.meta.WallBaseUnixNS
	}
	allMono := wallBase != 0 && len(recs) > 0
	for _, h := range recs {
		if h.MonoNS == 0 {
			allMono = false
		}
	}
	// nearest finds the hook's own process instance for an approximate t.
	nearest := func(h *hookRec, t time.Time) *inst {
		var best *inst
		var bestD time.Duration
		for _, hi := range hookInsts[h.PID] {
			d := t.Sub(hi.p.start)
			if d < 0 {
				d = -d
			}
			if best == nil || d < bestD {
				best, bestD = hi.p, d
			}
		}
		return best
	}
	switch {
	case allMono:
		ci.Method = "monotonic"
		var drift []float64
		for _, h := range recs {
			h.t = time.Unix(0, wallBase+h.MonoNS).UTC()
			if h.TsNS != 0 {
				drift = append(drift, float64(h.TsNS-(wallBase+h.MonoNS))/1e6)
			}
		}
		if len(drift) > 0 {
			sort.Float64s(drift)
			ci.OffsetMs = drift[len(drift)/2]
		}
		ci.Note = "exact: capture ts and hook mono_ns are both CLOCK_MONOTONIC; offset_ms is the measured CLOCK_REALTIME drift (not applied)"
	default:
		// Estimate offset = min(hook_realtime - own process start): the
		// hook cannot record before its process exists, so the true
		// offset is <= every such difference; the minimum is the
		// tightest bound (biased by the fastest interpreter startup).
		var offset int64
		have := false
		for _, h := range recs {
			if h.TsNS == 0 {
				continue
			}
			p := nearest(h, time.Unix(0, h.TsNS))
			if p == nil {
				continue
			}
			d := h.TsNS - p.start.UnixNano()
			if !have || d < offset {
				offset, have = d, true
			}
		}
		if have {
			ci.Method = "realtime_pid_anchored"
			ci.Note = "approximate: no capture_meta/mono_ns; CLOCK_REALTIME shifted by the tightest hook-process anchor (bias ~ fastest hook startup)"
		} else {
			ci.Method = "realtime_assumed"
			ci.Note = "approximate: no capture_meta/mono_ns and no hook process found in the capture; CLOCK_REALTIME assumed equal to capture time (wrong by any suspend/NTP step since loader start)"
		}
		ci.OffsetMs = float64(offset) / 1e6
		for _, h := range recs {
			ts := h.TsNS
			if ts == 0 && wallBase != 0 {
				ts = wallBase + h.MonoNS + offset
			}
			h.t = time.Unix(0, ts-offset).UTC()
		}
	}
	// Cross-check residuals.
	var res []float64
	for _, h := range recs {
		p := nearest(h, h.t)
		if p == nil {
			continue
		}
		r := float64(h.t.Sub(p.start).Nanoseconds()) / 1e6
		res = append(res, r)
		if r < 0 {
			ci.NegativeResiduals++
		}
	}
	ci.Anchors = len(res)
	if len(res) > 0 {
		sort.Float64s(res)
		ci.AnchorResidualMinMs = res[0]
		ci.AnchorResidualMedMs = res[len(res)/2]
		ci.AnchorResidualMaxMs = res[len(res)-1]
	}
	return ci
}

// spawningTools run their work in a child process in Claude Code.
var spawningTools = map[string]bool{"Bash": true, "Grep": true, "Glob": true}

func normCmd(s string) string {
	s = strings.NewReplacer("'", "", "\"", "", "\\", "", "\n", " ", "\t", " ").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

func (sp *ToolSpan) argvText() string {
	var parts []string
	for _, m := range sp.members {
		parts = append(parts, strings.Join(m.argv, " "))
	}
	return normCmd(strings.Join(parts, " "))
}

func inputString(in map[string]any, key string) string {
	if in == nil {
		return ""
	}
	if v, ok := in[key].(string); ok {
		return v
	}
	return ""
}

// correlate pairs hook records into calls, maps them to sessions and
// process-tree spans, and creates merged / time-window spans.
func (b *builder) correlate(recs []*hookRec, sessions []*sessionBuilder) *HarnessInfo {
	info := &HarnessInfo{Records: len(recs)}
	hookInsts := map[uint32][]hookInst{}
	for _, s := range sessions {
		for _, p := range s.sb.tr.insts {
			if isHookInst(p) {
				hookInsts[p.pid] = append(hookInsts[p.pid], hookInst{s, p})
			}
		}
	}
	info.Clock = b.alignHooks(recs, hookInsts)

	// Pair by tool_use_id.
	calls := map[string]*harnessCall{}
	var order []*harnessCall
	for _, h := range recs {
		if h.ToolUseID == "" {
			continue
		}
		c, ok := calls[h.ToolUseID]
		if !ok {
			c = &harnessCall{id: h.ToolUseID, tool: h.ToolName}
			calls[h.ToolUseID] = c
			order = append(order, c)
		}
		switch h.Event {
		case "pre":
			if c.pre == nil {
				c.pre = h
			}
		case "post", "post_failure":
			if c.post == nil {
				c.post = h
			}
		}
		if c.tool == "" {
			c.tool = h.ToolName
		}
	}
	info.ToolCalls = len(order)

	// Mark hook process spans, remembering their session.
	ownSession := map[uint32][]hookInst{}
	for pid, his := range hookInsts {
		ownSession[pid] = his
	}
	for _, s := range sessions {
		for _, sp := range s.sb.spans {
			for _, m := range sp.members {
				if isHookInst(m) {
					sp.Role = "hook"
					break
				}
			}
			if sp.Role == "hook" {
				info.HookSpans++
				sp.Notes = append(sp.Notes, "AgentLoupe hook process: observation overhead, not agent work")
			}
		}
	}

	findSession := func(h *hookRec) *sessionBuilder {
		if h == nil {
			return nil
		}
		// 1. The hook's own process is in the capture.
		var best *sessionBuilder
		var bestD time.Duration = -1
		for _, hi := range ownSession[h.PID] {
			d := h.t.Sub(hi.p.start)
			if d < 0 {
				d = -d
			}
			if bestD < 0 || d < bestD {
				best, bestD = hi.s, d
			}
		}
		if best != nil && bestD < 10*time.Second {
			return best
		}
		// 2. An ancestor of the hook is a session's agent process,
		//    alive at that time.
		for _, s := range sessions {
			for a := range s.sb.agents {
				if h.t.Before(a.start) || (a.hasEnd && h.t.After(a.end)) {
					continue
				}
				for _, anc := range h.Ancestors {
					if anc == a.pid {
						return s
					}
				}
			}
		}
		return nil
	}

	for _, c := range order {
		if c.pre != nil {
			c.start = c.pre.t
		} else {
			c.start = c.post.t
		}
		if c.post != nil {
			c.end = c.post.t
		} else {
			info.NoPost++
		}
		c.sess = findSession(c.pre)
		if c.sess == nil {
			c.sess = findSession(c.post)
		}
		if c.sess == nil {
			info.NoSession++
			continue
		}
		if c.post == nil {
			// Open call: runs to the session's last event.
			c.end = c.sess.last
			if c.end.Before(c.start) {
				c.end = c.start
			}
		}
		// Tag hook spans with the call they belong to.
		for _, h := range []*hookRec{c.pre, c.post} {
			if h == nil {
				continue
			}
			for _, sp := range c.sess.sb.spans {
				if sp.Role != "hook" || sp.ToolUseID != "" {
					continue
				}
				for _, m := range sp.members {
					if m.pid == h.PID && !h.t.Before(m.start) && (!m.hasEnd || !h.t.After(m.end)) {
						sp.ToolUseID, sp.ToolName = c.id, c.tool
						break
					}
				}
			}
		}
	}

	// Match process spans to calls, per session.
	const tol = 5 * time.Millisecond
	bySession := map[*sessionBuilder][]*harnessCall{}
	for _, c := range order {
		if c.sess != nil {
			bySession[c.sess] = append(bySession[c.sess], c)
		}
	}
	for s, cs := range bySession {
		within := func(c *harnessCall, t time.Time) bool {
			return !t.Before(c.start.Add(-tol)) && !t.After(c.end.Add(tol))
		}
		assigned := map[*ToolSpan]*harnessCall{}
		pick := func(cands []*harnessCall) *harnessCall {
			var best *harnessCall
			for _, c := range cands {
				if best == nil || c.start.After(best.start) { // innermost
					best = c
				}
			}
			return best
		}
		// Pass 1: command text match (Bash input.command in argv).
		for _, sp := range s.sb.spans {
			if sp.Role == "hook" {
				continue
			}
			text := sp.argvText()
			var cands []*harnessCall
			for _, c := range cs {
				cmd := normCmd(inputString(c.pre.inputOrNil(), "command"))
				if cmd == "" || !within(c, sp.startT) {
					continue
				}
				if len(cmd) > 80 {
					cmd = cmd[:80]
				}
				if strings.Contains(text, cmd) {
					cands = append(cands, c)
				}
			}
			if c := pick(cands); c != nil {
				assigned[sp] = c
			}
		}
		cmdMatched := map[*harnessCall]bool{}
		for _, c := range assigned {
			cmdMatched[c] = true
		}
		// Pass 2: time containment + a tool that spawns processes.
		for _, sp := range s.sb.spans {
			if sp.Role == "hook" || assigned[sp] != nil {
				continue
			}
			prog := sp.roots[0].label()
			var cands []*harnessCall
			for _, c := range cs {
				if !within(c, sp.startT) || !spawningTools[c.tool] {
					continue
				}
				if c.tool == "Bash" && (cmdMatched[c] || !shells[prog]) {
					continue
				}
				cands = append(cands, c)
			}
			if c := pick(cands); c != nil {
				assigned[sp] = c
			}
		}
		for _, sp := range s.sb.spans {
			if c := assigned[sp]; c != nil {
				c.matched = append(c.matched, sp)
			}
		}
	}

	// Build merged and time-window spans.
	for s, cs := range bySession {
		sb := s.sb
		var windows []*harnessCall
		for _, c := range cs {
			sp := &ToolSpan{ToolName: c.tool, ToolUseID: c.id, startT: c.start, endT: c.end}
			sp.Input = c.pre.inputOrNil()
			if sp.Input == nil && c.post != nil {
				sp.Input = c.post.Input
			}
			switch {
			case c.post == nil:
				sp.Status = "no_post"
				sp.OpenEnded = true
			case c.post.Event == "post_failure" && c.post.Interrupted:
				sp.Status = "interrupted"
			case c.post.Event == "post_failure":
				sp.Status = "error"
			default:
				sp.Status = "ok"
			}
			if c.post != nil && c.post.DurationMs != nil {
				sp.HarnessDurationMs = c.post.DurationMs
			}
			if len(c.matched) > 0 {
				info.ProcessMerged++
				sp.Source, sp.Attribution = "harness+process_tree", "process_tree"
				sort.SliceStable(c.matched, func(i, j int) bool { return c.matched[i].startT.Before(c.matched[j].startT) })
				first := c.matched[0]
				sp.RootPID, sp.Program, sp.Argv, sp.ArgvTruncated, sp.Command = first.RootPID, first.Program, first.Argv, first.ArgvTruncated, first.Command
				sp.ExitCode = first.ExitCode
				pStart, pEnd := first.startT, first.endT
				for _, m := range c.matched {
					m.mergedInto = sp
					sp.roots = append(sp.roots, m.roots...)
					sp.members = append(sp.members, m.members...)
					for _, pid := range m.PIDs {
						sp.PIDs = appendPID(sp.PIDs, pid)
					}
					if len(c.matched) > 1 {
						sp.MergedRootPIDs = append(sp.MergedRootPIDs, m.RootPID)
					}
					if m.startT.Before(pStart) {
						pStart = m.startT
					}
					if m.endT.After(pEnd) {
						pEnd = m.endT
					}
					if m.OutlivedSpan {
						sp.OutlivedSpan = true
						sp.SubtreeEndMs = m.SubtreeEndMs
					}
					sp.Notes = append(sp.Notes, m.Notes...)
				}
				pw := pEnd.Sub(pStart).Milliseconds()
				sp.ProcessWallMs = &pw
				if pEnd.After(sp.endT) && c.post != nil {
					sp.OutlivedSpan = true
					sp.Notes = append(sp.Notes, "process subtree still running after the harness reported the tool done")
				}
			} else {
				info.TimeWindow++
				sp.Source, sp.Attribution = "harness", "time_window"
				if sb.agent != nil {
					sp.RootPID = sb.agent.pid
					sp.Program = sb.agent.label()
				}
				sp.Notes = append(sp.Notes, "no child process: resources are the agent process's own file/network events inside the pre->post window (approximate: concurrent in-process work in that window is included; CPU and syscalls cannot be split by window and stay in agent_self)")
				windows = append(windows, c)
			}
			c.span = sp
			sb.spans = append(sb.spans, sp)
		}
		// Claim agent-process file/net records into time windows
		// (innermost = latest-starting containing window).
		if len(windows) > 0 && sb.agent != nil {
			overlap := map[*harnessCall]bool{}
			for i, a := range windows {
				for _, c := range windows[i+1:] {
					if a.start.Before(c.end) && c.start.Before(a.end) {
						overlap[a], overlap[c] = true, true
					}
				}
			}
			for i := range sb.recs {
				if !sb.agents[sb.tr.recInst[i]] || !claimable[sb.recs[i].kind] {
					continue
				}
				t := sb.recs[i].t
				var best *harnessCall
				for _, c := range windows {
					if !t.Before(c.start) && !t.After(c.end) && (best == nil || c.start.After(best.start)) {
						best = c
					}
				}
				if best != nil {
					sb.recBucket[i] = best.span
				}
			}
			for c := range overlap {
				c.span.Notes = append(c.span.Notes, "window overlapped another in-process tool call; each event went to the innermost (latest-starting) window")
			}
		}
		// Drop merged process spans from the list.
		kept := sb.spans[:0]
		for _, sp := range sb.spans {
			if sp.mergedInto == nil {
				kept = append(kept, sp)
			}
		}
		sb.spans = kept
	}
	if info.NoSession > 0 {
		info.Notes = append(info.Notes, "some tool calls matched no captured session (hook ancestors/pids not in this capture, or recorded outside the capture window)")
	}
	return info
}

// claimable record kinds for time-window attribution: per-event I/O.
// Exit/exec/syscall_summary are whole-process or interval data and stay
// with the agent process.
var claimable = map[string]bool{
	"file_open": true, "file_read": true, "file_write": true, "file_close": true,
	"file_unlink": true, "file_rename": true, "file_chmod": true,
	"net_connect": true, "net_send": true, "net_recv": true,
}

func (h *hookRec) inputOrNil() map[string]any {
	if h == nil {
		return nil
	}
	return h.Input
}

// availability decides which signals were collected (null-not-zero).
func (b *builder) availability() spanAvail {
	var probes map[string]bool
	if b.meta != nil {
		probes = b.meta.Probes
	}
	probe := func(key string, inferred bool) bool {
		if v, ok := probes[key]; ok {
			return v || inferred
		}
		return inferred
	}
	av := spanAvail{
		rw:  probe("file_rw_events", b.seenTypes["file_read"] || b.seenTypes["file_write"]),
		net: probe("net_send_events", b.seenTypes["net_send"]) || probe("net_recv_events", b.seenTypes["net_recv"]),
		sys: probe("syscall_summary", b.hasSummary),
	}
	switch {
	case av.rw:
		av.bytesFrom = "file_rw_events"
	case probe("io_accounting", b.closeBytes):
		av.bytesFrom = "file_close"
	}
	return av
}

// finishSpans finalizes tool spans for every session: harness
// correlation, accumulation, reconciliation, IDs, parallel overlap.
func (b *builder) finishSpans(rep *Report) {
	byRep := map[*SessionReport]*sessionBuilder{}
	for _, s := range b.order {
		byRep[s.rep] = s
	}
	var ordered []*sessionBuilder
	for _, r := range rep.Sessions {
		if s := byRep[r]; s != nil && s.sb != nil {
			ordered = append(ordered, s)
		}
	}
	if b.meta != nil && len(b.meta.Probes) > 0 {
		rep.Probes = b.meta.Probes
	}
	for _, s := range ordered {
		for _, sp := range s.sb.spans {
			sp.fillProcessMeta(b.globalFirst, b.globalLast, sp.members)
		}
	}
	b.linkNestedSessions(ordered)
	if b.opts.Hooks != nil {
		recs, skipped := loadHookRecs(b.opts.Hooks)
		rep.Harness = b.correlate(recs, ordered)
		rep.Harness.SkippedLines = skipped
		rep.Harness.SpansFile = b.opts.HooksName
	}
	av := b.availability()
	next := 1
	for k, s := range ordered {
		sb, r := s.sb, s.rep
		sb.finalizeAccs()
		sort.SliceStable(sb.spans, func(i, j int) bool {
			if !sb.spans[i].startT.Equal(sb.spans[j].startT) {
				return sb.spans[i].startT.Before(sb.spans[j].startT)
			}
			return sb.spans[i].RootPID < sb.spans[j].RootPID
		})
		r.ToolSpans = []*ToolSpan{}
		for _, sp := range sb.spans {
			sp.SpanID = "span-" + itoa(next)
			next++
			sp.finalizeTimes(b.globalFirst)
			sp.finalizeResources(av)
			r.ToolSpans = append(r.ToolSpans, sp)
		}
		parallelize(r.ToolSpans)
		self := &ToolSpan{SpanID: "agent_self-" + itoa(k+1), Source: "agent_self", Attribution: "remainder",
			acc: sb.self, startT: s.first, endT: s.last, PIDs: sb.selfPIDs}
		if sb.agent != nil {
			self.RootPID = sb.agent.pid
			self.Program = sb.agent.label()
			self.Argv, self.ArgvTruncated = truncArgv(sb.agent.argv)
			self.ExitCode = sb.agent.exitCode
		}
		self.Notes = append(self.Notes, "events of the agent process itself (in-process tools, model calls, runtime startup, waits) plus any process not under the agent; time-window spans have already taken their share")
		self.finalizeTimes(b.globalFirst)
		self.finalizeResources(av)
		r.AgentSelf = self
		r.AgentProcess = sb.agentInfo
		r.ResourceTotals = sb.totals.resources(av, true, true)
		r.IOBytesSource = av.bytesFrom
		if r.IOBytesSource == "" {
			r.IOBytesSource = "none"
		}
		r.SpanReconciliation = sb.recon
		if !sb.recon.OK {
			rep.Notes = append(rep.Notes, "session "+utoa(r.SessionID)+": tool span reconciliation FAILED: "+strings.Join(sb.recon.Mismatches, "; "))
		}
	}
}

// linkNestedSessions: a process forked in session P that execs a tracked
// agent binary becomes the root of a nested session C (parent_session_id
// = P); P only saw its fork, so its span would look open-ended for the
// rest of the capture. Take end/argv/exit from C's root and point at C.
func (b *builder) linkNestedSessions(ordered []*sessionBuilder) {
	byID := map[uint64]*sessionBuilder{}
	for _, s := range ordered {
		byID[s.rep.SessionID] = s
	}
	for _, c := range ordered {
		parent := byID[c.parentSID]
		if c.parentSID == 0 || parent == nil || len(c.sb.tr.rootInsts) == 0 {
			continue
		}
		croot := c.sb.tr.rootInsts[0]
		for _, sp := range parent.sb.spans {
			root := sp.roots[0]
			if root.pid != croot.pid || croot.start.Before(root.start) || (root.hasEnd && root.end.Before(croot.start)) {
				continue
			}
			sp.ContinuedInSession = utoa(c.rep.SessionID)
			if len(croot.argv) > 0 && len(root.argv) == 0 {
				sp.Program = croot.label()
				sp.Argv, sp.ArgvTruncated = truncArgv(croot.argv)
				sp.Command = truncStr(shellCommand(croot.argv), maxSpanCommand)
			}
			if !root.hasEnd {
				if croot.hasEnd {
					sp.endT, sp.OpenEnded = croot.end, false
				} else if !c.last.IsZero() {
					sp.endT = c.last
				}
				sp.ExitCode = croot.exitCode
			}
			sp.Notes = append(sp.Notes, "continued as nested session "+sp.ContinuedInSession+" (exec'd a tracked agent binary); its resources are reported under that session")
			break
		}
	}
}

func itoa(n int) string { return utoa(uint64(n)) }

func utoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
