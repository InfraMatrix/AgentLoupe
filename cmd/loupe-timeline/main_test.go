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
		"syscall categories", "notable syscalls", "syscalls by program", "first-seen syscalls"} {
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
