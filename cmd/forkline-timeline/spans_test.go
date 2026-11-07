package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// capBuilder writes a synthetic capture: one JSON object per line, with
// ts = base + ms offset, all in session sid.
type capBuilder struct {
	base  time.Time
	sid   uint64
	lines []string
}

func newCap() *capBuilder {
	return &capBuilder{base: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC), sid: 42}
}

func (c *capBuilder) at(ms float64) time.Time {
	return c.base.Add(time.Duration(ms * float64(time.Millisecond)))
}

func (c *capBuilder) ev(ms float64, typ string, pid, ppid uint32, comm string, extra map[string]any) {
	m := map[string]any{
		"ts": c.at(ms).Format(time.RFC3339Nano), "type": typ, "session_id": c.sid,
		"agent_name": "test-agent", "pid": pid, "ppid": ppid, "comm": comm,
	}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	c.lines = append(c.lines, string(b))
}

func (c *capBuilder) raw(m map[string]any) {
	b, _ := json.Marshal(m)
	c.lines = append(c.lines, string(b))
}

// spawn: fork from parent, exec argv in child.
func (c *capBuilder) spawn(ms float64, parent, parentPPID, child uint32, argv ...string) {
	c.ev(ms, "fork", parent, parentPPID, "parent", map[string]any{"child_pid": child})
	c.ev(ms+0.1, "exec", child, parent, filepath.Base(argv[0]), map[string]any{"argv": argv, "filename": "/usr/bin/" + filepath.Base(argv[0])})
}

func (c *capBuilder) exit(ms float64, pid, ppid uint32, cpuU, cpuS, rss uint64) {
	c.ev(ms, "exit", pid, ppid, "x", map[string]any{"exit_code": 0, "cpu_user_ms": cpuU, "cpu_sys_ms": cpuS, "max_rss_kb": rss})
}

func (c *capBuilder) open(ms float64, pid, ppid uint32, path string) {
	c.ev(ms, "file_open", pid, ppid, "x", map[string]any{"path": path, "result": 0})
}

func (c *capBuilder) build(t *testing.T, opts Options) *Report {
	t.Helper()
	rep, err := BuildWithOptions(strings.NewReader(strings.Join(c.lines, "\n")+"\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// agentStart: session_start + exec of the agent root (pid 1000).
func (c *capBuilder) agentStart() {
	c.ev(0, "session_start", 1000, 1, "agent", nil)
	c.ev(0, "exec", 1000, 1, "agent", map[string]any{"argv": []string{"agent", "--run"}, "filename": "/usr/bin/agent"})
}

func onlySession(t *testing.T, rep *Report) *SessionReport {
	t.Helper()
	if len(rep.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(rep.Sessions))
	}
	return rep.Sessions[0]
}

func mustReconcile(t *testing.T, s *SessionReport) {
	t.Helper()
	if s.SpanReconciliation == nil || !s.SpanReconciliation.OK {
		t.Fatalf("reconciliation failed: %+v", s.SpanReconciliation)
	}
}

func findSpan(s *SessionReport, pred func(*ToolSpan) bool) *ToolSpan {
	for _, sp := range s.ToolSpans {
		if pred(sp) {
			return sp
		}
	}
	return nil
}

// toyCapture mirrors the AgentCutter demo workload: a python agent that
// starts up (file opens), sleeps, runs true/echo/true/echo, then probes
// loopback TCP+UDP, with per-process syscall summaries.
func toyCapture() *capBuilder {
	c := newCap()
	c.agentStart()
	for i := 0; i < 5; i++ {
		c.open(1+float64(i), 1000, 1, "/usr/lib/python3/startup"+itoa(i)+".py")
	}
	kids := []struct {
		pid  uint32
		argv []string
	}{{1001, []string{"true"}}, {1002, []string{"echo", "x"}}, {1003, []string{"true"}}, {1004, []string{"echo", "x"}}}
	ms := 2000.0
	for _, k := range kids {
		c.spawn(ms, 1000, 1, k.pid, k.argv...)
		c.open(ms+0.3, k.pid, 1000, "/etc/ld.so.cache")
		c.exit(ms+1, k.pid, 1000, 0, 1, 3000)
		ms += 2
	}
	c.ev(4000, "net_connect", 1000, 1, "agent", map[string]any{"daddr": "127.0.0.1", "dport": 4444, "protocol": 6})
	c.ev(4001, "net_connect", 1000, 1, "agent", map[string]any{"daddr": "127.0.0.1", "dport": 53, "protocol": 17, "dns": true})
	c.ev(4500, "syscall_summary", 0, 0, "", map[string]any{
		"counts":             map[string]uint64{"openat": 9, "read": 3, "execve": 4},
		"per_process_counts": map[string]map[string]uint64{"1000": {"openat": 5, "read": 3}, "1001": {"openat": 1, "execve": 1}, "1002": {"openat": 1, "execve": 1}, "1003": {"openat": 1, "execve": 1}, "1004": {"openat": 1, "execve": 1}},
	})
	c.exit(5000, 1000, 1, 17, 5, 9000)
	c.ev(5000, "root_exit", 1000, 1, "agent", map[string]any{"cpu_user_ms": 17, "cpu_sys_ms": 5, "max_rss_kb": 9000})
	c.ev(5000, "session_end", 1000, 1, "agent", map[string]any{"reason": "all_exited"})
	return c
}

func TestToolSpansToyReconcile(t *testing.T) {
	s := onlySession(t, toyCapture().build(t, Options{}))
	mustReconcile(t, s)
	if len(s.ToolSpans) != 4 {
		t.Fatalf("tool spans = %d, want 4 (true, echo, true, echo)", len(s.ToolSpans))
	}
	want := []string{"true", "echo", "true", "echo"}
	for i, sp := range s.ToolSpans {
		if sp.Program != want[i] || sp.Source != "process_tree" || sp.Resources.Processes != 1 {
			t.Errorf("span %d = %s/%s procs=%d", i, sp.Program, sp.Source, sp.Resources.Processes)
		}
		if sp.Resources.CPUSysMS == nil || *sp.Resources.CPUSysMS != 1 || sp.Resources.FileOpens != 1 {
			t.Errorf("span %d resources = %+v", i, sp.Resources)
		}
		if sp.Resources.SyscallsTotal == nil || *sp.Resources.SyscallsTotal != 2 {
			t.Errorf("span %d syscalls = %v", i, sp.Resources.SyscallsTotal)
		}
		if sp.SpanID == "" || sp.ExitCode == nil {
			t.Errorf("span %d id/exit missing", i)
		}
	}
	self := s.AgentSelf.Resources
	if self.FileOpens != 5 || self.NetConnects != 2 || *self.CPUUserMS != 17 || *self.SyscallsTotal != 8 {
		t.Errorf("agent_self = %+v", self)
	}
	tot := s.ResourceTotals
	if tot.FileOpens != 9 || tot.NetConnects != 2 || *tot.CPUSysMS != 9 || tot.Processes != 5 {
		t.Errorf("totals = %+v", tot)
	}
	// No rw events / io accounting / send events in this capture: null.
	if tot.ReadBytes != nil || tot.FileReads != nil || tot.NetSends != nil {
		t.Errorf("uncollected signals must be null, got %+v", tot)
	}
	if s.IOBytesSource != "none" {
		t.Errorf("io_bytes_source = %q", s.IOBytesSource)
	}
}

// Every existing fixture must reconcile too.
func TestToolSpansReconcileFixtures(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "test", "fixtures", "timeline_*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no fixtures")
	}
	for _, f := range files {
		rep := buildFixture(t, filepath.Base(f))
		for _, s := range rep.Sessions {
			if s.SpanReconciliation == nil || !s.SpanReconciliation.OK {
				t.Errorf("%s session %d: %+v", filepath.Base(f), s.SessionID, s.SpanReconciliation)
			}
			if s.AgentSelf == nil || s.ToolSpans == nil {
				t.Errorf("%s session %d: missing agent_self/tool_spans", filepath.Base(f), s.SessionID)
			}
		}
	}
}

func TestToolSpansNestedShellIsOneSpan(t *testing.T) {
	c := newCap()
	c.agentStart()
	c.spawn(100, 1000, 1, 2000, "bash", "-c", "pytest -q tests/")
	c.spawn(101, 2000, 1000, 2001, "python3", "-m", "pytest", "-q", "tests/")
	c.spawn(150, 2001, 2000, 2002, "python3", "-c", "worker")
	c.open(160, 2002, 2001, "/src/a.py")
	c.ev(170, "file_read", 2001, 2000, "python3", map[string]any{"path": "/src/a.py", "bytes": 4096})
	c.exit(900, 2002, 2001, 100, 10, 50000)
	c.exit(1000, 2001, 2000, 300, 40, 80000)
	c.exit(1001, 2000, 1000, 1, 1, 4000)
	c.exit(2000, 1000, 1, 10, 10, 1000)
	s := onlySession(t, c.build(t, Options{}))
	mustReconcile(t, s)
	if len(s.ToolSpans) != 1 {
		t.Fatalf("spans = %d, want 1 (bash -c pytest is one span)", len(s.ToolSpans))
	}
	sp := s.ToolSpans[0]
	if sp.Program != "bash" || sp.Command != "pytest -q tests/" || sp.Resources.Processes != 3 {
		t.Errorf("span = %s %q procs=%d", sp.Program, sp.Command, sp.Resources.Processes)
	}
	if *sp.Resources.CPUUserMS != 401 || *sp.Resources.MaxRSSKB != 80000 || sp.WallMs != 901 {
		t.Errorf("aggregate cpu=%d rss=%d wall=%d", *sp.Resources.CPUUserMS, *sp.Resources.MaxRSSKB, sp.WallMs)
	}
	// rw events present => per-call counts and rw bytes are non-null.
	if sp.Resources.FileReads == nil || *sp.Resources.FileReads != 1 || *sp.Resources.ReadBytes != 4096 {
		t.Errorf("rw = %v %v", sp.Resources.FileReads, sp.Resources.ReadBytes)
	}
	if s.IOBytesSource != "file_rw_events" {
		t.Errorf("io_bytes_source = %q", s.IOBytesSource)
	}
}

func TestToolSpansParallel(t *testing.T) {
	c := newCap()
	c.agentStart()
	c.spawn(100, 1000, 1, 2000, "rg", "foo")
	c.spawn(120, 1000, 1, 3000, "rg", "bar")
	c.spawn(600, 1000, 1, 4000, "ls")
	c.exit(500, 2000, 1000, 5, 5, 1)
	c.exit(400, 3000, 1000, 5, 5, 1)
	c.exit(610, 4000, 1000, 1, 1, 1)
	c.exit(1000, 1000, 1, 1, 1, 1)
	s := onlySession(t, c.build(t, Options{}))
	mustReconcile(t, s)
	if len(s.ToolSpans) != 3 {
		t.Fatalf("spans = %d", len(s.ToolSpans))
	}
	a, b, l := s.ToolSpans[0], s.ToolSpans[1], s.ToolSpans[2]
	if len(a.ParallelWith) != 1 || a.ParallelWith[0] != b.SpanID || len(b.ParallelWith) != 1 || b.ParallelWith[0] != a.SpanID {
		t.Errorf("parallel: %v / %v", a.ParallelWith, b.ParallelWith)
	}
	if len(l.ParallelWith) != 0 {
		t.Errorf("sequential span marked parallel: %v", l.ParallelWith)
	}
}

func TestToolSpansOrphanDaemonStaysWithSpawner(t *testing.T) {
	c := newCap()
	c.agentStart()
	// bash forks a daemon helper (double fork), then exits; the
	// grandchild is reparented to init (later events carry ppid 1) and
	// even execs after the reparent.
	c.spawn(100, 1000, 1, 2000, "bash", "-c", "server &")
	c.ev(110, "fork", 2000, 1000, "bash", map[string]any{"child_pid": 2001})
	c.ev(111, "fork", 2001, 2000, "bash", map[string]any{"child_pid": 2002})
	c.exit(112, 2001, 2000, 0, 0, 1)
	c.exit(200, 2000, 1000, 1, 1, 1)
	c.ev(300, "exec", 2002, 1, "server", map[string]any{"argv": []string{"server"}})
	c.open(400, 2002, 1, "/var/server.log")
	c.ev(450, "net_connect", 2002, 1, "server", map[string]any{"daddr": "10.0.0.1", "dport": 443})
	c.exit(1500, 1000, 1, 1, 1, 1)
	c.ev(1500, "root_exit", 1000, 1, "agent", nil)
	c.exit(3000, 2002, 1, 50, 5, 1)
	s := onlySession(t, c.build(t, Options{}))
	mustReconcile(t, s)
	if len(s.ToolSpans) != 1 {
		t.Fatalf("spans = %d, want the daemon folded into its spawner's span", len(s.ToolSpans))
	}
	sp := s.ToolSpans[0]
	if !sp.OutlivedSpan || sp.SubtreeEndMs != 3000 || sp.WallMs != 100 {
		t.Errorf("outlived=%v subtree_end=%d wall=%d", sp.OutlivedSpan, sp.SubtreeEndMs, sp.WallMs)
	}
	if sp.Resources.FileOpens != 1 || sp.Resources.NetConnects != 1 || sp.Resources.Processes != 3 || *sp.Resources.CPUUserMS != 51 {
		t.Errorf("daemon resources not attributed: %+v", sp.Resources)
	}
	if s.AgentSelf.Resources.FileOpens != 0 {
		t.Errorf("daemon events leaked into agent_self")
	}
}

func TestToolSpansAgentProcessOverride(t *testing.T) {
	c := newCap()
	// wrapper (root) -> node agent "claude"; wrapper also runs a helper.
	c.ev(0, "session_start", 1000, 1, "npx", nil)
	c.ev(0, "exec", 1000, 1, "npx", map[string]any{"argv": []string{"npx", "claude"}})
	c.spawn(10, 1000, 1, 1100, "claude")
	c.spawn(20, 1000, 1, 1200, "updater")
	c.spawn(100, 1100, 1000, 2000, "bash", "-c", "make")
	c.exit(200, 2000, 1100, 1, 1, 1)
	c.exit(300, 1200, 1000, 1, 1, 1)
	def := onlySession(t, c.build(t, Options{}))
	if len(def.ToolSpans) != 2 { // claude subtree + updater
		t.Fatalf("default spans = %d", len(def.ToolSpans))
	}
	s := onlySession(t, c.build(t, Options{AgentProcess: "claude"}))
	mustReconcile(t, s)
	if s.AgentProcess == nil || s.AgentProcess.PID != 1100 || s.AgentProcess.OutsideAgentTree != 2 {
		t.Fatalf("agent process = %+v", s.AgentProcess)
	}
	if len(s.ToolSpans) != 1 || s.ToolSpans[0].Command != "make" {
		t.Fatalf("spans = %+v", s.ToolSpans)
	}
}

// ---- harness correlation + clock alignment ----

// hookCapture: an agent whose harness hook records (via a python hook
// process that is itself in the capture) one Bash call that spawns a
// shell, and one Read call that only touches files in-process.
// realOffsetMs simulates CLOCK_REALTIME running ahead of capture time
// (e.g. a suspend after loader start).
func hookCapture(withMeta bool) (*capBuilder, func(realOffsetMs float64, mono bool) string) {
	c := newCap()
	wallBase := c.base.Add(-time.Hour) // capture ts = wall_base + ktime
	if withMeta {
		c.raw(map[string]any{"ts": c.base.Format(time.RFC3339Nano), "type": "capture_meta", "session_id": 0,
			"clock": "CLOCK_MONOTONIC", "wall_base_unix_ns": wallBase.UnixNano(),
			"probes": map[string]bool{"file_rw_events": false, "syscall_summary": false}})
	}
	c.ev(0, "session_start", 1000, 1, "claude", nil)
	c.ev(0, "exec", 1000, 1, "claude", map[string]any{"argv": []string{"claude"}})
	hook := func(ms float64, pid uint32) {
		c.spawn(ms, 1000, 1, pid, "/bin/sh", "-c", "python3 /opt/forkline/hooks/forkline_hook.py")
		c.ev(ms+1, "exec", pid, 1000, "python3", map[string]any{"argv": []string{"python3", "/opt/forkline/hooks/forkline_hook.py"}})
		c.exit(ms+30, pid, 1000, 10, 5, 9000)
	}
	// Bash call: pre hook at 1000ms, shell 1040..1900, post hook 1950.
	hook(1000, 3001)
	c.spawn(1040, 1000, 1, 3010, "/bin/bash", "-c", "-l", "source /tmp/snap && eval 'pytest -q' < /dev/null")
	c.open(1100, 3010, 1000, "/repo/test_x.py")
	c.exit(1900, 3010, 1000, 800, 100, 60000)
	hook(1950, 3002)
	// Helper the agent spawns on its own during the Read window (git).
	// Read call: pre 3000, in-process opens at 3050/3060, post 3100.
	hook(3000, 3003)
	c.open(3050, 1000, 1, "/repo/networkx/weighted.py")
	c.open(3060, 1000, 1, "/repo/networkx/weighted.py")
	c.spawn(3070, 1000, 1, 3020, "git", "status")
	c.exit(3080, 3020, 1000, 1, 1, 1)
	hook(3100, 3004)
	c.open(5000, 1000, 1, "/var/agent/state.json") // outside any window
	c.exit(6000, 1000, 1, 2000, 300, 200000)
	c.ev(6000, "root_exit", 1000, 1, "claude", nil)

	spans := func(realOffsetMs float64, mono bool) string {
		var lines []string
		rec := func(ev, tool, id string, ms float64, pid uint32, input map[string]any, extra map[string]any) {
			capT := c.at(ms)
			m := map[string]any{"event": ev, "tool_name": tool, "tool_use_id": id, "session_id": "cc-1",
				"ts_ns": capT.Add(time.Duration(realOffsetMs * float64(time.Millisecond))).UnixNano(),
				"pid":   pid, "ppid": 3000, "ancestors": []uint32{pid - 0, 1000}, "input": input}
			if mono {
				m["mono_ns"] = capT.Sub(wallBase).Nanoseconds()
			}
			for k, v := range extra {
				m[k] = v
			}
			b, _ := json.Marshal(m)
			lines = append(lines, string(b))
		}
		// The hook records ~20ms after its python process execs.
		rec("pre", "Bash", "toolu_1", 1021, 3001, map[string]any{"command": "pytest -q"}, nil)
		rec("post", "Bash", "toolu_1", 1971, 3002, nil, map[string]any{"duration_ms": 860})
		rec("pre", "Read", "toolu_2", 3021, 3003, map[string]any{"file_path": "/repo/networkx/weighted.py"}, nil)
		rec("post", "Read", "toolu_2", 3121, 3004, nil, map[string]any{"duration_ms": 5})
		return strings.Join(lines, "\n") + "\n"
	}
	return c, spans
}

func checkHarness(t *testing.T, s *SessionReport) {
	t.Helper()
	mustReconcile(t, s)
	bash := findSpan(s, func(sp *ToolSpan) bool { return sp.ToolUseID == "toolu_1" && sp.Role == "" })
	read := findSpan(s, func(sp *ToolSpan) bool { return sp.ToolUseID == "toolu_2" && sp.Role == "" })
	if bash == nil || read == nil {
		for _, sp := range s.ToolSpans {
			t.Logf("span %s %s %s %s role=%s start=%d", sp.SpanID, sp.Source, sp.ToolName, sp.ToolUseID, sp.Role, sp.StartMs)
		}
		t.Fatalf("missing harness spans")
	}
	if bash.Source != "harness+process_tree" || bash.RootPID != 3010 || bash.ToolName != "Bash" {
		t.Errorf("bash span = %s root=%d", bash.Source, bash.RootPID)
	}
	if *bash.Resources.CPUUserMS != 800 || bash.Resources.FileOpens != 1 || bash.ProcessWallMs == nil || *bash.ProcessWallMs != 860 {
		t.Errorf("bash resources = %+v pw=%v", bash.Resources, bash.ProcessWallMs)
	}
	if bash.HarnessDurationMs == nil || *bash.HarnessDurationMs != 860 || bash.Status != "ok" {
		t.Errorf("bash harness fields: %v %q", bash.HarnessDurationMs, bash.Status)
	}
	if inputString(bash.Input, "command") != "pytest -q" {
		t.Errorf("bash input = %v", bash.Input)
	}
	if read.Source != "harness" || read.Attribution != "time_window" || read.Resources.FileOpens != 2 {
		t.Errorf("read span = %s/%s opens=%d", read.Source, read.Attribution, read.Resources.FileOpens)
	}
	if read.Resources.CPUUserMS != nil || read.Resources.SyscallsTotal != nil {
		t.Errorf("time-window span must not claim CPU/syscalls")
	}
	// git spawned by the agent inside the Read window is NOT the Read
	// tool (Read never spawns): it stays its own process-tree span.
	git := findSpan(s, func(sp *ToolSpan) bool { return sp.Program == "git" })
	if git == nil || git.Source != "process_tree" || git.ToolUseID != "" {
		t.Errorf("git helper misattributed: %+v", git)
	}
	hooks := 0
	for _, sp := range s.ToolSpans {
		if sp.Role == "hook" {
			hooks++
			if sp.ToolUseID == "" {
				t.Errorf("hook span %s not tied to a tool call", sp.SpanID)
			}
		}
	}
	if hooks != 4 {
		t.Errorf("hook spans = %d, want 4", hooks)
	}
	// agent_self keeps only the out-of-window open.
	if s.AgentSelf.Resources.FileOpens != 1 {
		t.Errorf("agent_self opens = %d, want 1", s.AgentSelf.Resources.FileOpens)
	}
}

func TestHarnessClockMonotonicExact(t *testing.T) {
	c, spans := hookCapture(true)
	// Realtime is 37s ahead (suspend); mono_ns + capture_meta make it moot.
	rep := c.build(t, Options{Hooks: strings.NewReader(spans(37000, true)), HooksName: "x.spans.jsonl"})
	h := rep.Harness
	if h == nil || h.Clock.Method != "monotonic" {
		t.Fatalf("harness = %+v", h)
	}
	if h.Clock.OffsetMs < 36999 || h.Clock.OffsetMs > 37001 {
		t.Errorf("measured drift = %.3fms, want 37000", h.Clock.OffsetMs)
	}
	if h.Clock.Anchors != 4 || h.Clock.NegativeResiduals != 0 || h.Clock.AnchorResidualMinMs < 19 || h.Clock.AnchorResidualMaxMs > 21 {
		t.Errorf("anchor residuals = %+v", h.Clock)
	}
	if h.ToolCalls != 2 || h.ProcessMerged != 1 || h.TimeWindow != 1 || h.HookSpans != 4 {
		t.Errorf("counts = %+v", h)
	}
	checkHarness(t, onlySession(t, rep))
}

func TestHarnessClockRealtimeAnchoredOffset(t *testing.T) {
	c, spans := hookCapture(false) // old capture: no capture_meta
	rep := c.build(t, Options{Hooks: strings.NewReader(spans(37000, false))})
	h := rep.Harness
	if h.Clock.Method != "realtime_pid_anchored" {
		t.Fatalf("method = %s", h.Clock.Method)
	}
	// Estimated offset = true offset + fastest hook startup (~20ms).
	if h.Clock.OffsetMs < 37000 || h.Clock.OffsetMs > 37025 {
		t.Errorf("offset = %.3fms, want ~37020", h.Clock.OffsetMs)
	}
	if h.Clock.NegativeResiduals != 0 {
		t.Errorf("negative residuals after alignment: %+v", h.Clock)
	}
	checkHarness(t, onlySession(t, rep))
}

func TestHarnessClockUncorrectedOffsetIsDetectable(t *testing.T) {
	// Without capture_meta and with the hook processes missing from the
	// capture, a 37s realtime offset cannot be corrected: the method must
	// say "realtime_assumed" and nothing may be merged.
	c, spans := hookCapture(false)
	var kept []string
	for _, l := range c.lines {
		if !strings.Contains(l, "forkline_hook") {
			kept = append(kept, l)
		}
	}
	c.lines = kept
	rep := c.build(t, Options{Hooks: strings.NewReader(spans(37000, false))})
	if rep.Harness.Clock.Method != "realtime_assumed" {
		t.Fatalf("method = %s", rep.Harness.Clock.Method)
	}
	s := onlySession(t, rep)
	mustReconcile(t, s)
	if rep.Harness.ProcessMerged != 0 {
		t.Errorf("merged %d spans across a 37s clock error", rep.Harness.ProcessMerged)
	}
}

func TestHarnessParallelReadsInnermostWindow(t *testing.T) {
	c := newCap()
	c.agentStart()
	c.open(150, 1000, 1, "/a") // only in window A
	c.open(250, 1000, 1, "/b") // in A and B: innermost is B
	c.exit(1000, 1000, 1, 1, 1, 1)
	recs := []string{
		`{"event":"pre","tool_name":"Read","tool_use_id":"A","ts_ns":` + itoa64(c.at(100).UnixNano()) + `,"pid":9,"ancestors":[1000]}`,
		`{"event":"pre","tool_name":"Read","tool_use_id":"B","ts_ns":` + itoa64(c.at(200).UnixNano()) + `,"pid":9,"ancestors":[1000]}`,
		`{"event":"post","tool_name":"Read","tool_use_id":"A","ts_ns":` + itoa64(c.at(300).UnixNano()) + `,"pid":9,"ancestors":[1000]}`,
		`{"event":"post_failure","tool_name":"Read","tool_use_id":"B","ts_ns":` + itoa64(c.at(400).UnixNano()) + `,"pid":9,"ancestors":[1000],"error":"boom"}`,
	}
	s := onlySession(t, c.build(t, Options{Hooks: strings.NewReader(strings.Join(recs, "\n"))}))
	mustReconcile(t, s)
	a := findSpan(s, func(sp *ToolSpan) bool { return sp.ToolUseID == "A" })
	b := findSpan(s, func(sp *ToolSpan) bool { return sp.ToolUseID == "B" })
	if a == nil || b == nil || a.Resources.FileOpens != 1 || b.Resources.FileOpens != 1 {
		t.Fatalf("a=%+v b=%+v", a, b)
	}
	if b.Status != "error" || len(a.ParallelWith) != 1 || a.ParallelWith[0] != b.SpanID {
		t.Errorf("status=%q parallel=%v", b.Status, a.ParallelWith)
	}
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestCaptureMetaIgnoredBySessions(t *testing.T) {
	c, _ := hookCapture(true)
	rep := c.build(t, Options{})
	if len(rep.Sessions) != 1 || rep.TotalEvents != len(c.lines)-1 {
		t.Fatalf("capture_meta leaked into sessions/totals: %d sessions, %d events", len(rep.Sessions), rep.TotalEvents)
	}
	if rep.CaptureStart != c.base.Format(time.RFC3339Nano) {
		t.Errorf("capture_start moved: %s", rep.CaptureStart)
	}
	if rep.Probes == nil {
		t.Errorf("probes not surfaced")
	}
}

func TestSpansTextOutput(t *testing.T) {
	var sb strings.Builder
	writeSpansText(&sb, toyCapture().build(t, Options{}))
	out := sb.String()
	for _, want := range []string{"tool spans: 4", "agent_self == totals: yes", "agent_self-1", "echo: echo x"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestToolSpansMultipleRootsAreAgents(t *testing.T) {
	c := newCap()
	c.agentStart()
	// A second session_start root (adoption / pre-exact-ID capture)
	// whose parent is not in the capture: its children are spans too.
	c.ev(50, "session_start", 5000, 4999, "claude", nil)
	c.ev(50, "exec", 5000, 4999, "claude", map[string]any{"argv": []string{"claude"}})
	c.spawn(100, 5000, 4999, 5001, "git", "status")
	c.exit(110, 5001, 5000, 1, 1, 1)
	c.open(120, 5000, 4999, "/state")
	s := onlySession(t, c.build(t, Options{}))
	mustReconcile(t, s)
	if len(s.ToolSpans) != 1 || s.ToolSpans[0].Program != "git" {
		t.Fatalf("spans = %+v", s.ToolSpans)
	}
	if s.AgentProcess.OutsideAgentTree != 0 || len(s.AgentProcess.AdditionalRoots) != 1 || s.AgentProcess.AdditionalRoots[0] != 5000 {
		t.Errorf("agent process = %+v", s.AgentProcess)
	}
	if s.AgentSelf.Resources.FileOpens != 1 {
		t.Errorf("second root's own events must be agent_self")
	}
}

func TestToolSpansPreABIv4ExitCPUIsNull(t *testing.T) {
	c := newCap()
	c.agentStart()
	c.spawn(100, 1000, 1, 2000, "true")
	// pre-ABI-v4 exit: no cpu_user_ms / cpu_sys_ms / max_rss_kb keys.
	c.ev(110, "exit", 2000, 1000, "true", map[string]any{"exit_code": 0})
	s := onlySession(t, c.build(t, Options{}))
	mustReconcile(t, s)
	r := s.ToolSpans[0].Resources
	if r.CPUUserMS != nil || r.MaxRSSKB != nil {
		t.Errorf("unknown CPU reported as a number: %v %v", r.CPUUserMS, r.MaxRSSKB)
	}
	if s.ToolSpans[0].ExitCode == nil || s.ToolSpans[0].OpenEnded {
		t.Errorf("exit still recorded: %+v", s.ToolSpans[0])
	}
}

func TestToolSpansNestedSessionLinked(t *testing.T) {
	c := newCap()
	c.agentStart()
	c.ev(100, "fork", 1000, 1, "claude", map[string]any{"child_pid": 2000})
	c.open(100.5, 2000, 1000, "/pre-exec")
	c.exit(9000, 1000, 1, 1, 1, 1)
	// The child execs the agent binary as rg: nested session 43.
	c.raw(map[string]any{"ts": c.at(101).Format(time.RFC3339Nano), "type": "session_start", "session_id": 43,
		"parent_session_id": 42, "pid": 2000, "ppid": 1000, "comm": "claude"})
	c.raw(map[string]any{"ts": c.at(101).Format(time.RFC3339Nano), "type": "exec", "session_id": 43,
		"pid": 2000, "ppid": 1000, "comm": "rg", "argv": []string{"rg", "--files"}})
	c.raw(map[string]any{"ts": c.at(107).Format(time.RFC3339Nano), "type": "exit", "session_id": 43,
		"pid": 2000, "ppid": 1000, "comm": "rg", "exit_code": 0, "cpu_user_ms": 3, "cpu_sys_ms": 5, "max_rss_kb": 1})
	rep := c.build(t, Options{})
	s := sessionByID(rep, 42)
	mustReconcile(t, s)
	sp := s.ToolSpans[0]
	if sp.ContinuedInSession != "43" || sp.OpenEnded || sp.WallMs != 7 || sp.Program != "rg" || sp.ExitCode == nil {
		t.Errorf("nested span = %+v", sp)
	}
}
