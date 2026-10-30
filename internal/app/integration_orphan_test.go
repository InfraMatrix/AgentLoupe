//go:build integration

// Orphaned-child integration test: real loader, real kernel (companion
// to integration_multi_agent_test.go; same root/BPF-object requirements
// — see `sudo make integration`).
//
// A session is a process tree, not just its root. When an agent's root
// exits while a spawned child keeps working, the loader must emit
// root_exit and keep the session open: the orphan's later activity is
// attributed to the same session (no second session_start, and its
// syscalls are flushed before the eventual session_end). Both endings
// are tested:
//   - the orphan exits on its own  -> session_end reason "all_exited";
//   - the orphan outlives the configured orphan timeout (5s here) ->
//     session_end reason "orphan_timeout" listing the orphan's TGID in
//     still_running, while the orphan is in fact still alive.
//
// Staggering is driven only by gate/marker files and event polling,
// never by fixed sleeps. On failure the full captured stream is dumped
// grouped by session.
package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type orphanWorkload struct {
	label     string
	dir       string
	rootFile  string
	childFile string

	cmd      *exec.Cmd
	waitCh   chan error
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	rootPID  int
	childPID int
	sid      uint64
}

func (w *orphanWorkload) path(name string) string { return filepath.Join(w.dir, name) }

// childScript: does its own activity, signals done (with its pid),
// waits for the go gate, does MORE activity (the post-root-exit orphan
// activity), signals again, then waits for the exit gate.
func (w *orphanWorkload) childScript(tcpPort, udpPort uint16) string {
	return pythonActivity(w.childFile, tcpPort, udpPort) + pythonWaitHelpers() + fmt.Sprintf(`
activity()
touch_pid(%q)
wait_path(%q)
activity()
touch_pid(%q)
wait_path(%q)
`, w.path("child.done"), w.path("child.go"), w.path("child.after"), w.path("child.exit"))
}

// rootScript: spawns the child, waits for the child's first activity,
// does its own activity, signals done, and exits WITHOUT waiting for
// the child — deliberately orphaning it.
func (w *orphanWorkload) rootScript(tcpPort, udpPort uint16, ruleToken string) string {
	return fmt.Sprintf("RULE_TOKEN = %q\n", ruleToken) +
		pythonActivity(w.rootFile, tcpPort, udpPort) + pythonWaitHelpers() + fmt.Sprintf(`
import subprocess, sys
touch_pid(%q)
child_code = %q
# DEVNULL: a daemonising child must not inherit the root's stdout/stderr
# pipes — it would hold them open after the root dies and block the
# test's Cmd.Wait() on pipe drain even though the root has exited.
p = subprocess.Popen([sys.executable, "-c", child_code],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
wait_path(%q)
activity()
touch_pid(%q)
# Exit without p.wait(): the child is orphaned on purpose.
`, w.path("root.ready"), w.childScript(tcpPort, udpPort),
		w.path("child.done"), w.path("root.done"))
}

func waitPIDGone(t *testing.T, pid int, desc string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out (%s) waiting for %s: pid %d still alive", timeout, desc, pid)
		}
		time.Sleep(50 * time.Millisecond) // poll cadence only; phases are gated by process state
	}
}

func TestIntegrationOrphanedChild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root: run `sudo make integration`")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bpfObject := filepath.Join(root, "bpf", "agentloupe.bpf.o")
	if _, err := os.Stat(bpfObject); err != nil {
		t.Fatalf("BPF object missing (%v): run `make build` as your normal user first, then `sudo make integration`", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required for the integration workload: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(python); err == nil {
		python = resolved
	}

	tmp := t.TempDir()
	outFile := filepath.Join(tmp, "events.jsonl")
	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	ruleToken := "al-orphan-" + runID
	const agentName = "itg-orphan"

	configPath := filepath.Join(tmp, "agents.yaml")
	configYAML := fmt.Sprintf(`agents:
  - name: %s
    kind: tool
    match:
      interpreter: %s
      argv_contains: %s
`, agentName, python, ruleToken)
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	tcpPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)

	baseMaps, _ := mapSnapshot()

	// --- loader: 5s orphan timeout so the timeout path is testable -----
	ctx, cancel := context.WithCancel(context.Background())
	var runResult error
	loaderDone := make(chan struct{})
	go func() {
		runResult = Run(ctx, Options{
			BPFObject:            bpfObject,
			ConfigPath:           configPath,
			Output:               outFile,
			EnableSyscallSummary: true,
			SyscallInterval:      100 * time.Millisecond,
			OrphanTimeout:        5 * time.Second,
		})
		close(loaderDone)
	}()
	defer func() {
		cancel()
		select {
		case <-loaderDone:
		case <-time.After(15 * time.Second):
			t.Errorf("loader did not stop within 15s of context cancel")
		}
	}()

	fail := func(events []capturedEvent, format string, args ...any) {
		t.Helper()
		if events == nil {
			events = readEvents(outFile)
		}
		t.Fatalf(format+"\ncaptured event stream grouped by session (%d events):\n%s",
			append(args, len(events), dumpEventsBySession(events))...)
	}

	poll := func(desc string, timeout time.Duration, cond func([]capturedEvent) bool) []capturedEvent {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for {
			select {
			case <-loaderDone:
				fail(nil, "loader exited while waiting for %s: %v", desc, runResult)
			default:
			}
			events := readEvents(outFile)
			if cond(events) {
				return events
			}
			if time.Now().After(deadline) {
				fail(events, "timed out (%s) waiting for %s", timeout, desc)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// --- warm-up: prove the pipeline is live (same retry pattern) ------
	warmFile := filepath.Join(tmp, "warmup.txt")
	warmScript := fmt.Sprintf("RULE_TOKEN = %q\n", ruleToken) +
		pythonActivity(warmFile, tcpPort, udpPort) + "\nactivity()\n"
	warmDeadline := time.Now().Add(60 * time.Second)
	for {
		cmd := exec.Command(python, "-c", warmScript)
		var werr bytes.Buffer
		cmd.Stderr = &werr
		if err := cmd.Run(); err != nil {
			fail(nil, "warmup workload: %v (%s)", err, werr.String())
		}
		pid := uint32(cmd.Process.Pid)
		seen := false
		pollUntil := time.Now().Add(5 * time.Second)
		for time.Now().Before(pollUntil) && time.Now().Before(warmDeadline) {
			for _, ev := range readEvents(outFile) {
				if ev.PID == pid && ev.Type == "file_open" && ev.Path == warmFile {
					seen = true
				}
			}
			if seen {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if seen {
			break
		}
		if time.Now().After(warmDeadline) {
			fail(nil, "warmup workload events never appeared (loader pipeline not live?)")
		}
	}

	// startOrphan starts one workload and drives it to the state: root
	// has exited (reaped by the test), child is alive and gated, and the
	// session's root_exit event has been observed.
	startOrphan := func(label string) *orphanWorkload {
		t.Helper()
		w := &orphanWorkload{label: label, dir: filepath.Join(tmp, label)}
		w.rootFile = filepath.Join(w.dir, label+"-root.txt")
		w.childFile = filepath.Join(w.dir, label+"-child.txt")
		if err := os.MkdirAll(w.dir, 0o755); err != nil {
			t.Fatal(err)
		}
		w.cmd = exec.Command(python, "-c", w.rootScript(tcpPort, udpPort, ruleToken))
		w.cmd.Stdout, w.cmd.Stderr = &w.stdout, &w.stderr
		if err := w.cmd.Start(); err != nil {
			fail(nil, "%s: start workload: %v", label, err)
		}
		w.rootPID = w.cmd.Process.Pid
		w.waitCh = make(chan error, 1)
		go func() { w.waitCh <- w.cmd.Wait() }()

		if pid := parsePIDFile(t, w.path("root.ready"), label+" root ready", 60*time.Second); pid != w.rootPID {
			fail(nil, "%s: ready file pid %d != started pid %d", label, pid, w.rootPID)
		}
		w.childPID = parsePIDFile(t, w.path("child.done"), label+" child done", 60*time.Second)
		waitFile(t, w.path("root.done"), label+" root done", 60*time.Second)

		// The root exits on its own, orphaning the gated child.
		select {
		case err := <-w.waitCh:
			if err != nil {
				fail(nil, "%s: root exited %v\nstdout: %s\nstderr: %s", label, err, w.stdout.String(), w.stderr.String())
			}
		case <-time.After(60 * time.Second):
			fail(nil, "%s: root did not exit", label)
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", w.childPID)); err != nil {
			fail(nil, "%s: orphan child %d not alive after root exit: %v", label, w.childPID, err)
		}

		events := poll(label+": root_exit", 60*time.Second, func(evs []capturedEvent) bool {
			for _, ev := range evs {
				if ev.Type == "exec" && ev.PID == uint32(w.rootPID) {
					w.sid = ev.SessionID
				}
				if ev.Type == "root_exit" && w.sid != 0 && ev.SessionID == w.sid {
					return true
				}
			}
			return false
		})
		if w.sid == 0 {
			fail(events, "%s: root exec has session_id 0", label)
		}
		for _, ev := range events {
			if ev.SessionID == w.sid && ev.Type == "session_end" {
				fail(events, "%s: session_end emitted at root exit while orphan %d still alive", label, w.childPID)
			}
		}
		return w
	}

	idxOf := func(evs []capturedEvent, sid uint64, typ string, pid int) int {
		for i, ev := range evs {
			if ev.SessionID == sid && ev.Type == typ && (pid < 0 || ev.PID == uint32(pid)) {
				return i
			}
		}
		return -1
	}
	countOf := func(evs []capturedEvent, sid uint64, typ string) int {
		n := 0
		for _, ev := range evs {
			if ev.SessionID == sid && ev.Type == typ {
				n++
			}
		}
		return n
	}

	kernelTotals := func(sid uint64) (map[string]uint64, map[string]map[string]uint64) {
		t.Helper()
		totals := map[string]uint64{}
		perProc := map[string]map[string]uint64{}
		scMap, err := newMapByName("syscall_counts", baseMaps)
		if err != nil {
			fail(nil, "reading syscall_counts map: %v", err)
		}
		defer scMap.Close()
		it := scMap.Iterate()
		var k [16]byte
		var v uint64
		for it.Next(&k, &v) {
			if binary.LittleEndian.Uint64(k[0:8]) != sid {
				continue
			}
			name := syscallSummaryName(binary.LittleEndian.Uint32(k[12:16]))
			totals[name] += v
			pid := fmt.Sprintf("%d", binary.LittleEndian.Uint32(k[8:12]))
			if perProc[pid] == nil {
				perProc[pid] = map[string]uint64{}
			}
			perProc[pid][name] += v
		}
		if err := it.Err(); err != nil {
			fail(nil, "iterating syscall_counts: %v", err)
		}
		return totals, perProc
	}

	// ==== path 1: the orphan exits on its own -> all_exited ==============
	a := startOrphan("selfexit")
	rootExitIdx := idxOf(readEvents(outFile), a.sid, "root_exit", a.rootPID)
	if rootExitIdx < 0 {
		fail(nil, "%s: root_exit for root pid %d not found", a.label, a.rootPID)
	}

	// Let the orphan work again, now that its root is dead.
	touch(t, a.path("child.go"))
	waitFile(t, a.path("child.after"), a.label+" orphan post-root-exit activity", 60*time.Second)
	events := poll(a.label+": orphan activity attributed after root_exit", 60*time.Second, func(evs []capturedEvent) bool {
		ri := idxOf(evs, a.sid, "root_exit", a.rootPID)
		if ri < 0 {
			return false
		}
		fileAfter, summaryAfter := false, false
		for i, ev := range evs {
			if i <= ri || ev.SessionID != a.sid {
				continue
			}
			if ev.Type == "file_open" && ev.PID == uint32(a.childPID) && ev.Path == a.childFile {
				fileAfter = true
			}
			if ev.Type == "syscall_summary" {
				if _, ok := ev.PerProcess[fmt.Sprintf("%d", a.childPID)]; ok {
					summaryAfter = true
				}
			}
		}
		return fileAfter && summaryAfter
	})
	if n := countOf(events, a.sid, "session_start"); n != 1 {
		fail(events, "%s: session_start count = %d, want exactly 1 (orphan must not reopen the session)", a.label, n)
	}
	if n := countOf(events, a.sid, "session_end"); n != 0 {
		fail(events, "%s: session_end count = %d while orphan still alive, want 0", a.label, n)
	}

	// Release the orphan; the session ends only now, as all_exited.
	touch(t, a.path("child.exit"))
	events = poll(a.label+": session_end after orphan exit", 60*time.Second, func(evs []capturedEvent) bool {
		return idxOf(evs, a.sid, "session_end", -1) >= 0
	})
	ri := idxOf(events, a.sid, "root_exit", a.rootPID)
	endIdx := idxOf(events, a.sid, "session_end", -1)
	end := events[endIdx]
	if end.Reason != "all_exited" {
		fail(events, "%s: session_end reason = %q, want all_exited", a.label, end.Reason)
	}
	if len(end.StillRunning) != 0 {
		fail(events, "%s: all_exited session_end still_running = %v, want empty", a.label, end.StillRunning)
	}
	if got := events[ri]; got.PID != uint32(a.rootPID) || got.ExitCode != 0 || got.AgentName != agentName {
		fail(events, "%s: root_exit = pid %d exit_code %d agent %q", a.label, got.PID, got.ExitCode, got.AgentName)
	}
	if !(idxOf(events, a.sid, "session_start", -1) < ri && ri < endIdx) {
		fail(events, "%s: ordering session_start < root_exit < session_end broken", a.label)
	}
	postRootFile := false
	for i, ev := range events {
		if i > ri && i < endIdx && ev.Type == "file_open" && ev.PID == uint32(a.childPID) && ev.SessionID == a.sid {
			postRootFile = true
		}
	}
	if !postRootFile {
		fail(events, "%s: no orphan file_open between root_exit and session_end", a.label)
	}
	if n := countOf(events, a.sid, "session_start"); n != 1 {
		fail(events, "%s: session_start count = %d after end, want 1", a.label, n)
	}
	// The orphan is really dead, so kernel totals are frozen: the JSONL
	// deltas (including the final flush before session_end) must sum
	// exactly to them, per session and per TGID.
	waitPIDGone(t, a.childPID, a.label+" orphan", 60*time.Second)
	kTotals, kPerProc := kernelTotals(a.sid)
	jsonTotals := map[string]uint64{}
	jsonPerProc := map[string]map[string]uint64{}
	for _, ev := range readEvents(outFile) {
		if ev.Type != "syscall_summary" || ev.SessionID != a.sid {
			continue
		}
		for n, c := range ev.Counts {
			jsonTotals[n] += c
		}
		for pid, pc := range ev.PerProcess {
			if jsonPerProc[pid] == nil {
				jsonPerProc[pid] = map[string]uint64{}
			}
			for n, c := range pc {
				jsonPerProc[pid][n] += c
			}
		}
	}
	if !equalUint64Map(jsonTotals, kTotals) {
		fail(nil, "%s: syscall_summary delta sums %v != kernel totals %v", a.label, jsonTotals, kTotals)
	}
	if len(jsonPerProc) != len(kPerProc) {
		fail(nil, "%s: per_process_counts tgids %v != kernel tgids %v", a.label, keysOf(jsonPerProc), keysOf(kPerProc))
	}
	for pid, pc := range kPerProc {
		if !equalUint64Map(jsonPerProc[pid], pc) {
			fail(nil, "%s: per_process_counts[%s] sums %v != kernel %v", a.label, pid, jsonPerProc[pid], pc)
		}
	}
	if len(kPerProc[fmt.Sprintf("%d", a.childPID)]) == 0 {
		fail(nil, "%s: kernel has no syscall counts for orphan tgid %d", a.label, a.childPID)
	}

	// ==== path 2: the orphan outlives the timeout -> orphan_timeout =====
	b := startOrphan("timeout")
	if b.sid == a.sid {
		fail(nil, "orphan workloads share session %d, want distinct", b.sid)
	}
	// Never open the orphan's gates: it stays alive past the 5s timeout.
	events = poll(b.label+": orphan_timeout session_end", 60*time.Second, func(evs []capturedEvent) bool {
		return idxOf(evs, b.sid, "session_end", -1) >= 0
	})
	endIdx = idxOf(events, b.sid, "session_end", -1)
	end = events[endIdx]
	if end.Reason != "orphan_timeout" {
		fail(events, "%s: session_end reason = %q, want orphan_timeout", b.label, end.Reason)
	}
	if len(end.StillRunning) != 1 || end.StillRunning[0] != uint32(b.childPID) {
		fail(events, "%s: still_running = %v, want [%d]", b.label, end.StillRunning, b.childPID)
	}
	if idxOf(events, b.sid, "root_exit", b.rootPID) < 0 ||
		idxOf(events, b.sid, "root_exit", b.rootPID) > endIdx {
		fail(events, "%s: root_exit must precede the orphan_timeout session_end", b.label)
	}
	if n := countOf(events, b.sid, "session_start"); n != 1 {
		fail(events, "%s: session_start count = %d, want 1", b.label, n)
	}
	// The whole point of the timeout listing: the orphan really is
	// still running at this moment.
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", b.childPID)); err != nil {
		fail(events, "%s: orphan %d listed still_running but not alive: %v", b.label, b.childPID, err)
	}

	// Cleanup: kill the orphan (the test, not the loader, owns it now).
	proc, err := os.FindProcess(b.childPID)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Kill(); err != nil {
		t.Fatal(err)
	}
	waitPIDGone(t, b.childPID, b.label+" orphan after kill", 60*time.Second)

	// Shutdown.
	cancel()
	select {
	case <-loaderDone:
		if runResult != nil {
			fail(nil, "loader returned error on shutdown: %v", runResult)
		}
	case <-time.After(15 * time.Second):
		fail(nil, "loader did not stop within 15s of cancel")
	}
}
