package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildFixture(t *testing.T, name string) *Report {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "test", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := Build(f)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func sessionByID(rep *Report, id uint64) *SessionReport {
	for _, s := range rep.Sessions {
		if s.SessionID == id {
			return s
		}
	}
	return nil
}

func TestBuildTimelineBasic(t *testing.T) {
	rep := buildFixture(t, "timeline_basic.jsonl")
	if len(rep.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 concurrent sessions of the same agent", len(rep.Sessions))
	}
	if !rep.HasSyscallSummary {
		t.Error("HasSyscallSummary = false")
	}
	// Out-of-order lines: capture range is min..max timestamps, not file order.
	if rep.CaptureStart != "2026-01-01T00:00:00Z" || rep.DurationMs != 4000 {
		t.Errorf("capture %s .. +%dms", rep.CaptureStart, rep.DurationMs)
	}
	s100 := sessionByID(rep, 100)
	s200 := sessionByID(rep, 200)
	if s100 == nil || s200 == nil {
		t.Fatal("missing session")
	}
	if s100.Agent != "claude-code" || s200.Agent != "claude-code" || s100.RootComm != "claude" {
		t.Errorf("agents/root: %q %q root=%q", s100.Agent, s200.Agent, s100.RootComm)
	}
	// Process tree nesting: echo/python are children (depth 1).
	var echo, py *Process
	for _, p := range s100.Processes {
		if p.Label == "echo" {
			echo = p
		}
	}
	for _, p := range s200.Processes {
		if p.Label == "python3" {
			py = p
		}
	}
	if echo == nil || py == nil {
		t.Fatalf("processes: %+v / %+v", s100.Processes, s200.Processes)
	}
	if echo.Depth != 1 || echo.PPID != 1000 || echo.DurationMs != 1000 {
		t.Errorf("echo = depth %d ppid %d dur %d", echo.Depth, echo.PPID, echo.DurationMs)
	}
	if len(echo.Argv) != 2 || echo.Cwd != "/work" {
		t.Errorf("echo argv/cwd = %v %q", echo.Argv, echo.Cwd)
	}
	if py.Depth != 1 {
		t.Errorf("python depth = %d", py.Depth)
	}
	// Per-process CPU / peak RSS come from the exit events (ABI v4).
	if echo.CPUUserMS != 1 || echo.CPUSysMS != 1 || echo.MaxRSSKB != 2048 {
		t.Errorf("echo resources = cpu_user %dms cpu_sys %dms max_rss %dKiB, want 1/1/2048",
			echo.CPUUserMS, echo.CPUSysMS, echo.MaxRSSKB)
	}
	var root100 *Process
	for _, p := range s100.Processes {
		if p.PID == 1000 {
			root100 = p
		}
	}
	if root100 == nil || root100.CPUUserMS != 120 || root100.CPUSysMS != 30 || root100.MaxRSSKB != 51200 {
		t.Errorf("root resources = %+v, want cpu_user 120ms cpu_sys 30ms max_rss 51200KiB", root100)
	}
	// Open-ended: session 200 never exits, extends to capture end (4000ms).
	if !py.OpenEnded || py.EndMs != 4000 {
		t.Errorf("python open-ended = %v end_ms=%d", py.OpenEnded, py.EndMs)
	}
	for _, p := range s100.Processes {
		if p.OpenEnded {
			t.Errorf("session 100 process %s unexpectedly open-ended", p.Label)
		}
	}
	// Syscall distribution aggregates deltas across summaries.
	totals := map[string]uint64{}
	for _, sc := range s100.Syscalls {
		totals[sc.Name] = sc.Count
	}
	if totals["read"] != 15 || totals["write"] != 2 || totals["openat"] != 3 {
		t.Errorf("s100 syscalls = %v", totals)
	}
	if s100.SyscallSeries == nil || len(s100.SyscallSeries.Names) == 0 {
		t.Error("missing syscall series")
	}
	// Categories group the raw names; the rate series is category-based.
	cats := map[string]uint64{}
	for _, c := range s100.SyscallCategories {
		cats[c.Name] = c.Count
	}
	if cats["file"] != 21 || cats["memory"] != 40 || cats["sync/wait"] != 30 || cats["process"] != 1 || cats["network"] != 2 {
		t.Errorf("s100 categories = %v", cats)
	}
	for _, n := range s100.SyscallSeries.Names {
		if n == "read" || n == "mmap" {
			t.Errorf("rate series should be categories, got name %q in %v", n, s100.SyscallSeries.Names)
		}
	}
	if s100.SeriesByCategory["file"] == nil {
		t.Error("missing per-category drill-down series for file")
	}
	// Notable syscalls: always shown, with first-seen offsets.
	notable := map[string]*NotableStat{}
	for _, n := range s100.Notable {
		notable[n.Name] = n
	}
	if notable["execve"] == nil || notable["execve"].Count != 1 || notable["execve"].FirstSeenMs != 1000 {
		t.Errorf("notable execve = %+v", notable["execve"])
	}
	if notable["unlink"] == nil || notable["unlink"].Count != 1 || notable["unlink"].FirstSeenMs != 2000 {
		t.Errorf("notable unlink = %+v", notable["unlink"])
	}
	// First-seen marks: read first at +1s, openat not until +2s.
	firstSeen := map[string]*FirstSeenMark{}
	for _, m := range s100.FirstSeen {
		firstSeen[m.Name] = m
	}
	if firstSeen["read"] == nil || firstSeen["read"].OffsetMs != 1000 || firstSeen["read"].PID != 1000 {
		t.Errorf("first-seen read = %+v", firstSeen["read"])
	}
	if firstSeen["openat"] == nil || firstSeen["openat"].OffsetMs != 2000 {
		t.Errorf("first-seen openat = %+v", firstSeen["openat"])
	}
	// Per-program attribution rolls TGIDs up to their exec'd program.
	if len(s100.ProgramSyscalls) != 2 || s100.ProgramSyscalls[0].Program != "claude" || s100.ProgramSyscalls[0].Total != 91 {
		t.Errorf("s100 program syscalls = %+v", s100.ProgramSyscalls)
	}
	if len(s100.ProgramSyscalls) == 2 && (s100.ProgramSyscalls[1].Program != "echo" || s100.ProgramSyscalls[1].Total != 3) {
		t.Errorf("s100 echo attribution = %+v", s100.ProgramSyscalls[1])
	}
	if len(s200.ProgramSyscalls) != 1 || s200.ProgramSyscalls[0].Program != "python3" || s200.ProgramSyscalls[0].Total != 16 {
		t.Errorf("s200 program syscalls = %+v", s200.ProgramSyscalls)
	}
	// Breakdowns.
	if len(s100.ProgramsByCount) == 0 || s100.ProgramsByCount[0].ExecCount < 1 {
		t.Errorf("programs by count = %+v", s100.ProgramsByCount)
	}
	foundFile, foundNet := false, false
	for _, f := range s100.Files {
		if f.Path == "/tmp/a.txt" {
			foundFile = true
		}
	}
	for _, n := range s100.Network {
		if n.Dest == "127.0.0.1:53" && n.DNS == 1 {
			foundNet = true
		}
	}
	if !foundFile || !foundNet {
		t.Errorf("files=%v network=%v", s100.Files, s100.Network)
	}
	if s100.MarkerTotal != 3 { // file_open + 2 net
		t.Errorf("s100 markers total = %d", s100.MarkerTotal)
	}
	if s200.MarkerTotal != 2 { // unlink + file_open
		t.Errorf("s200 markers total = %d", s200.MarkerTotal)
	}
}

func TestBuildTimelineMultiAgent(t *testing.T) {
	rep := buildFixture(t, "timeline_multi_agent.jsonl")
	if len(rep.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 overlapping sessions of different agents", len(rep.Sessions))
	}
	if !rep.HasSyscallSummary {
		t.Error("HasSyscallSummary = false")
	}
	if rep.CaptureStart != "2026-01-01T00:00:00Z" || rep.DurationMs != 4000 {
		t.Errorf("capture %s .. +%dms", rep.CaptureStart, rep.DurationMs)
	}
	sClaude := sessionByID(rep, 300)
	sAider := sessionByID(rep, 400)
	if sClaude == nil || sAider == nil {
		t.Fatal("missing session")
	}
	// Two different agents, overlapping in time (aider starts at +500ms,
	// claude runs 0..4s), kept as separate sessions.
	if sClaude.Agent != "claude-code" || sAider.Agent != "aider" {
		t.Errorf("agents = %q / %q", sClaude.Agent, sAider.Agent)
	}
	if sClaude.RootComm != "claude" || sAider.RootComm != "python3" {
		t.Errorf("roots = %q / %q", sClaude.RootComm, sAider.RootComm)
	}
	if sClaude.Start != "2026-01-01T00:00:00Z" || sAider.Start != "2026-01-01T00:00:00.5Z" {
		t.Errorf("starts = %s / %s, want aider to start inside claude's window", sClaude.Start, sAider.Start)
	}

	// Separate processes: no PID, label, or tree nesting leaks across
	// sessions, even though both sessions are alive at the same time.
	pidsOf := func(s *SessionReport) map[uint32]*Process {
		t.Helper()
		out := map[uint32]*Process{}
		for _, p := range s.Processes {
			out[p.PID] = p
		}
		return out
	}
	claudeProcs, aiderProcs := pidsOf(sClaude), pidsOf(sAider)
	if len(claudeProcs) != 2 || claudeProcs[3000] == nil || claudeProcs[3001] == nil {
		t.Errorf("claude processes = %+v", sClaude.Processes)
	}
	if len(aiderProcs) != 2 || aiderProcs[4000] == nil || aiderProcs[4001] == nil {
		t.Errorf("aider processes = %+v", sAider.Processes)
	}
	for pid := range claudeProcs {
		if aiderProcs[pid] != nil {
			t.Errorf("pid %d appears in both sessions", pid)
		}
	}
	if p := claudeProcs[3001]; p == nil || p.Label != "echo" || p.Depth != 1 || p.PPID != 3000 || p.Cwd != "/work/alpha" {
		t.Errorf("claude child = %+v", p)
	}
	if p := aiderProcs[4001]; p == nil || p.Label != "git" || p.Depth != 1 || p.PPID != 4000 || p.Cwd != "/work/beta" {
		t.Errorf("aider child = %+v", p)
	}
	if p := aiderProcs[4000]; p == nil || !p.OpenEnded || p.EndMs != 4000 {
		t.Errorf("aider root open-ended = %+v, want still running at capture end", p)
	}

	// Separate categories: same-named syscalls (read/mmap/futex/connect)
	// are counted per session, and each session's mix stays distinct.
	catsOf := func(s *SessionReport) map[string]uint64 {
		out := map[string]uint64{}
		for _, c := range s.SyscallCategories {
			out[c.Name] = c.Count
		}
		return out
	}
	if got, want := catsOf(sClaude), map[string]uint64{"file": 21, "memory": 40, "sync/wait": 30, "process": 1, "network": 2}; !equalCounts(got, want) {
		t.Errorf("claude categories = %v, want %v", got, want)
	}
	if got, want := catsOf(sAider), map[string]uint64{"file": 17, "memory": 9, "sync/wait": 5, "process": 1, "network": 4}; !equalCounts(got, want) {
		t.Errorf("aider categories = %v, want %v", got, want)
	}

	// Per-program attribution: each session rolls its own TGIDs up to
	// the program that TGID exec'd, with no cross-session programs.
	if len(sClaude.ProgramSyscalls) != 2 ||
		sClaude.ProgramSyscalls[0].Program != "claude" || sClaude.ProgramSyscalls[0].Total != 91 ||
		sClaude.ProgramSyscalls[1].Program != "echo" || sClaude.ProgramSyscalls[1].Total != 3 {
		t.Errorf("claude program syscalls = %+v", sClaude.ProgramSyscalls)
	}
	if len(sAider.ProgramSyscalls) != 2 ||
		sAider.ProgramSyscalls[0].Program != "python3" || sAider.ProgramSyscalls[0].Total != 23 ||
		sAider.ProgramSyscalls[1].Program != "git" || sAider.ProgramSyscalls[1].Total != 13 {
		t.Errorf("aider program syscalls = %+v", sAider.ProgramSyscalls)
	}
	for _, ps := range sClaude.ProgramSyscalls {
		for _, pid := range ps.PIDs {
			if pid != 3000 && pid != 3001 {
				t.Errorf("claude program %q attributed to foreign pid %d", ps.Program, pid)
			}
		}
	}
	for _, ps := range sAider.ProgramSyscalls {
		for _, pid := range ps.PIDs {
			if pid != 4000 && pid != 4001 {
				t.Errorf("aider program %q attributed to foreign pid %d", ps.Program, pid)
			}
		}
	}
	// The child programs' own category mixes are attributed, not merged
	// into their session root's.
	if len(sAider.ProgramSyscalls) == 2 {
		gitCats := map[string]uint64{}
		for _, c := range sAider.ProgramSyscalls[1].Categories {
			gitCats[c.Name] = c.Count
		}
		if want := map[string]uint64{"file": 7, "sync/wait": 5, "process": 1}; !equalCounts(gitCats, want) {
			t.Errorf("git categories = %v, want %v", gitCats, want)
		}
	}

	// Files/network markers stay in their own session.
	if len(sClaude.Files) != 1 || sClaude.Files[0].Path != "/tmp/alpha.txt" ||
		len(sClaude.Network) != 1 || sClaude.Network[0].Dest != "93.184.216.34:443" ||
		sClaude.MarkerTotal != 2 {
		t.Errorf("claude files/network/markers = %v %v total=%d", sClaude.Files, sClaude.Network, sClaude.MarkerTotal)
	}
	if len(sAider.Files) != 2 || sAider.Files[0].Path == sAider.Files[1].Path ||
		len(sAider.Network) != 1 || sAider.Network[0].Dest != "127.0.0.1:53" || sAider.Network[0].DNS != 1 ||
		sAider.MarkerTotal != 3 {
		t.Errorf("aider files/network/markers = %v %v total=%d", sAider.Files, sAider.Network, sAider.MarkerTotal)
	}
	for _, f := range sAider.Files {
		if f.Path == "/tmp/alpha.txt" {
			t.Error("claude file leaked into aider session")
		}
	}
}

func TestBuildTimelineOrphan(t *testing.T) {
	rep := buildFixture(t, "timeline_orphan.jsonl")
	if len(rep.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(rep.Sessions))
	}
	if rep.DurationMs != 5000 {
		t.Errorf("capture duration = %dms, want 5000", rep.DurationMs)
	}
	s500 := sessionByID(rep, 500)
	s600 := sessionByID(rep, 600)
	if s500 == nil || s600 == nil {
		t.Fatal("missing session")
	}

	// Session 500: the orphan outlives the root, keeps working under the
	// same session, then exits on its own: reason all_exited, gap 3s.
	if s500.RootExit != "2026-01-01T00:00:02Z" || s500.RootExitMs != 2000 {
		t.Errorf("s500 root exit = %q +%dms", s500.RootExit, s500.RootExitMs)
	}
	if s500.OrphanGapMs != 3000 {
		t.Errorf("s500 orphan gap = %dms, want 3000", s500.OrphanGapMs)
	}
	if s500.SessionEndReason != "all_exited" || len(s500.StillRunning) != 0 {
		t.Errorf("s500 end reason/still = %q %v", s500.SessionEndReason, s500.StillRunning)
	}
	if len(s500.Files) != 1 || s500.Files[0].Path != "/tmp/orphan.txt" {
		t.Errorf("s500 files = %v, want orphan activity after root exit", s500.Files)
	}
	// The orphan's post-root-exit syscalls are attributed to the orphan's
	// program (echo), not dropped and not folded into the root.
	if len(s500.ProgramSyscalls) != 2 ||
		s500.ProgramSyscalls[0].Program != "claude" || s500.ProgramSyscalls[0].Total != 10 ||
		s500.ProgramSyscalls[1].Program != "echo" || s500.ProgramSyscalls[1].Total != 6 {
		t.Errorf("s500 program syscalls = %+v", s500.ProgramSyscalls)
	}
	// Both processes closed (the orphan's exit closed the session).
	for _, p := range s500.Processes {
		if p.OpenEnded {
			t.Errorf("s500 process %s unexpectedly open-ended", p.Label)
		}
	}
	// Exit/root_exit resource fields (ABI v4) land on the right processes.
	resByPID := map[uint32]*Process{}
	for _, p := range s500.Processes {
		resByPID[p.PID] = p
	}
	if p := resByPID[5000]; p == nil || p.CPUUserMS != 200 || p.CPUSysMS != 50 || p.MaxRSSKB != 65536 {
		t.Errorf("s500 root resources = %+v, want 200/50/65536", p)
	}
	if p := resByPID[5001]; p == nil || p.CPUUserMS != 1 || p.CPUSysMS != 1 || p.MaxRSSKB != 2048 {
		t.Errorf("s500 orphan resources = %+v, want 1/1/2048", p)
	}

	// Session 600: the orphan outlives the orphan timeout: reason
	// orphan_timeout, still_running lists the surviving TGID, gap 2.5s.
	if s600.RootExit != "2026-01-01T00:00:01.5Z" || s600.RootExitMs != 1500 {
		t.Errorf("s600 root exit = %q +%dms", s600.RootExit, s600.RootExitMs)
	}
	if s600.OrphanGapMs != 2500 {
		t.Errorf("s600 orphan gap = %dms, want 2500", s600.OrphanGapMs)
	}
	if s600.SessionEndReason != "orphan_timeout" {
		t.Errorf("s600 end reason = %q", s600.SessionEndReason)
	}
	if len(s600.StillRunning) != 1 || s600.StillRunning[0] != 6001 {
		t.Errorf("s600 still running = %v, want [6001]", s600.StillRunning)
	}
	// The timed-out orphan never exited within the capture.
	var git *Process
	for _, p := range s600.Processes {
		if p.Label == "git" {
			git = p
		}
	}
	if git == nil || !git.OpenEnded {
		t.Errorf("s600 orphan process = %+v, want still running at capture end", git)
	}

	// Text rendering shows the orphan gap and reason.
	var sb strings.Builder
	writeText(&sb, rep)
	out := sb.String()
	for _, want := range []string{"root exit: +2.00s", "orphan gap to session_end: 3.00s (reason all_exited)",
		"root exit: +1.50s", "orphan gap to session_end: 2.50s (reason orphan_timeout, still running: [6001])"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func equalCounts(got, want map[string]uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func TestBuildNoSyscallSummaryTolerated(t *testing.T) {
	rep := buildFixture(t, "timeline_no_syscall.jsonl")
	if rep.HasSyscallSummary {
		t.Error("HasSyscallSummary = true for old capture")
	}
	if len(rep.Notes) == 0 {
		t.Error("expected a note about missing syscall_summary")
	}
	s := sessionByID(rep, 7)
	if s == nil || len(s.Processes) != 1 || s.Processes[0].OpenEnded {
		t.Fatalf("session = %+v", s)
	}
	if len(s.Syscalls) != 0 || s.SyscallSeries != nil {
		t.Errorf("syscalls = %v series=%v", s.Syscalls, s.SyscallSeries)
	}
}

func TestRenderHTMLSelfContained(t *testing.T) {
	for _, fixture := range []string{"timeline_basic.jsonl", "timeline_no_syscall.jsonl"} {
		rep := buildFixture(t, fixture)
		var sb strings.Builder
		if err := renderHTML(&sb, rep); err != nil {
			t.Fatal(err)
		}
		out := sb.String()
		if !strings.Contains(out, "<!DOCTYPE html>") || !strings.Contains(out, "syscall") {
			t.Errorf("%s: html missing doctype/syscall content", fixture)
		}
		if strings.Contains(out, "<script src") || strings.Contains(out, "<link") || strings.Contains(out, "cdn") {
			t.Errorf("%s: html references external resources", fixture)
		}
	}
	rep := buildFixture(t, "timeline_no_syscall.jsonl")
	var sb strings.Builder
	_ = renderHTML(&sb, rep)
	if !strings.Contains(sb.String(), "No syscall_summary events") {
		t.Error("html should note missing syscall_summary")
	}
}

func TestWriteText(t *testing.T) {
	rep := buildFixture(t, "timeline_basic.jsonl")
	var sb strings.Builder
	writeText(&sb, rep)
	out := sb.String()
	for _, want := range []string{"session 100", "process tree:", "echo", "still running at capture end", "read",
		"syscall categories", "notable syscalls", "syscalls by program", "first-seen syscalls",
		"cpu_user=120ms cpu_sys=30ms max_rss=51200KiB"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestBuildEmptyAndMalformed(t *testing.T) {
	rep, err := Build(strings.NewReader("\nnot json\n{\"ts\":\"bad\",\"type\":\"exec\",\"session_id\":1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.SkippedLines != 1 {
		t.Errorf("skipped = %d", rep.SkippedLines)
	}
	if rep.TotalEvents != 1 {
		t.Errorf("total = %d", rep.TotalEvents)
	}
}
