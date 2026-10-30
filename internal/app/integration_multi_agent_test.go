//go:build integration

// Multi-agent concurrency integration test: real loader, real kernel,
// real workloads (companion to integration_test.go; same root/BPF-object
// requirements — see `sudo make integration`).
//
// What this adds over TestIntegrationLoaderObserveOnly:
//   - two DIFFERENT agent rules running at the same time, plus a
//     NEGATIVE CONTROL (a non-agent python doing the same kinds of
//     file/network activity: none of its events may appear in any
//     session);
//   - the SAME agent rule twice at the same time (two instances must
//     still produce two distinct sessions);
//   - every agent workload spawns a child (fork+exec of a second python)
//     that does its own file open and TCP/UDP connects, so child
//     attribution is exercised, not just root attribution;
//   - staggering is driven only by explicit synchronisation: workloads
//     block on marker ("gate") files the test creates, signal progress
//     with ready/done files, and the test polls for files/events with
//     generous timeouts. No fixed sleep decides when a phase starts.
//   - syscall_summary partition sums are checked exactly ONLY after
//     both sessions have ended (final flush seen, processes dead, so
//     kernel totals can no longer move). Mid-run, only per-session/TGID
//     isolation is asserted.
//   - on failure the full captured stream is dumped grouped by session.
//
// The orphaned-child case (agent root exits while a spawned child keeps
// working) is covered separately in integration_orphan_test.go, for both
// endings: the orphan exits on its own (all_exited) and the orphan
// outlives the orphan timeout (orphan_timeout).
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
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- failure dump: full stream, grouped by session ----------------------

func dumpEventsBySession(events []capturedEvent) string {
	if len(events) == 0 {
		return "(no events captured)"
	}
	var order []uint64
	bySID := map[uint64][]capturedEvent{}
	agentOf := map[uint64]string{}
	for _, ev := range events {
		if _, ok := bySID[ev.SessionID]; !ok {
			order = append(order, ev.SessionID)
		}
		bySID[ev.SessionID] = append(bySID[ev.SessionID], ev)
		if ev.AgentName != "" {
			agentOf[ev.SessionID] = ev.AgentName
		}
	}
	var b strings.Builder
	for _, sid := range order {
		fmt.Fprintf(&b, "== session %d agent=%q (%d events) ==\n", sid, agentOf[sid], len(bySID[sid]))
		for _, ev := range bySID[sid] {
			b.WriteString(ev.Raw)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// ---- gated workloads ------------------------------------------------------

type gatedWorkload struct {
	label     string // e.g. "alpha" — used in file names/messages
	agent     string // expected agent_name
	ruleToken string // exact argv_contains token baked into the script

	dir       string
	rootFile  string // file the root opens (its own activity)
	childFile string // file the child opens (its own activity)

	cmd      *exec.Cmd
	waitCh   chan error
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	rootPID  int
	childPID int
	sid      uint64
}

func (w *gatedWorkload) path(name string) string { return filepath.Join(w.dir, name) }

// waitFile polls for a marker file and returns its contents.
func waitFile(t *testing.T, path, desc string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return string(data)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out (%s) waiting for %s (%s)", timeout, desc, path)
		}
		time.Sleep(50 * time.Millisecond) // poll cadence only; phases are gated by the files themselves
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("go"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func parsePIDFile(t *testing.T, path, desc string, timeout time.Duration) int {
	t.Helper()
	s := strings.TrimSpace(waitFile(t, path, desc, timeout))
	pid, err := strconv.Atoi(s)
	if err != nil || pid <= 0 {
		t.Fatalf("%s: contents %q is not a pid", desc, s)
	}
	return pid
}

// pythonActivity is the file+TCP+UDP activity every workload process
// (agent root, agent child, negative control) performs, parameterised by
// the file it touches. It returns python source defining activity().
func pythonActivity(file string, tcpPort, udpPort uint16) string {
	return fmt.Sprintf(`
import os, socket
def activity():
    with open(%q, "w") as f:
        f.write("activity")
    s = socket.create_connection(("127.0.0.1", %d), timeout=5)
    s.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.connect(("127.0.0.1", %d))
    u.send(b"x")
    u.close()
`, file, tcpPort, udpPort)
}

func pythonWaitHelpers() string {
	return `
import os, time
def wait_path(p):
    end = time.time() + 120
    while not os.path.exists(p):
        if time.time() > end:
            raise SystemExit("timeout waiting for " + p)
        time.sleep(0.02)
def touch_pid(p):
    with open(p, "w") as f:
        f.write(str(os.getpid()))
`
}

// childScript: does its own activity, signals done (with its pid), then
// blocks on the exit gate so the test controls when it dies.
func (w *gatedWorkload) childScript(tcpPort, udpPort uint16) string {
	return pythonActivity(w.childFile, tcpPort, udpPort) + pythonWaitHelpers() + fmt.Sprintf(`
activity()
touch_pid(%q)
wait_path(%q)
`, w.path("child.done"), w.path("child.exit"))
}

// rootScript: signals ready, blocks on the go gate, spawns the child
// (fork+exec), waits for the child's activity, does its own activity,
// signals done, then reaps the child (so the root outlives it until the
// test opens the child's exit gate).
func (w *gatedWorkload) rootScript(tcpPort, udpPort uint16) string {
	return fmt.Sprintf("RULE_TOKEN = %q\n", w.ruleToken) +
		pythonActivity(w.rootFile, tcpPort, udpPort) + pythonWaitHelpers() + fmt.Sprintf(`
import subprocess, sys
touch_pid(%q)
wait_path(%q)
child_code = %q
p = subprocess.Popen([sys.executable, "-c", child_code])
wait_path(%q)
activity()
touch_pid(%q)
rc = p.wait()
if rc != 0:
    raise SystemExit("child exited %%d" %% rc)
`, w.path("root.ready"), w.path("root.go"), w.childScript(tcpPort, udpPort),
		w.path("child.done"), w.path("root.done"))
}

// ---- the test -------------------------------------------------------------

func TestIntegrationMultiAgentConcurrent(t *testing.T) {
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
	tokenFor := func(who string) string { return "al-multi-" + runID + "-" + who }
	const (
		agentAlpha = "itg-alpha"
		agentBeta  = "itg-beta"
	)

	// Two agent rules; workloads are told apart purely by argv token.
	configPath := filepath.Join(tmp, "agents.yaml")
	configYAML := fmt.Sprintf(`agents:
  - name: %s
    kind: tool
    match:
      interpreter: %s
      argv_contains: %s
  - name: %s
    kind: tool
    match:
      interpreter: %s
      argv_contains: %s
`, agentAlpha, python, tokenFor("alpha"), agentBeta, python, tokenFor("beta"))
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Listeners (same pattern as the single-agent test).
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

	// --- loader -------------------------------------------------------------
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

	// poll re-reads the capture until cond holds or the deadline passes.
	// It is the ONLY waiting mechanism for loader-side state.
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

	// --- warm-up: prove the pipeline is live before gating real workloads --
	// (Same retry pattern as the single-agent test: a workload started in
	// the load->attach window would be missed, so run sacrificial ones
	// until one's events are seen.)
	warmFile := filepath.Join(tmp, "warmup.txt")
	warmScript := fmt.Sprintf("RULE_TOKEN = %q\n", tokenFor("alpha")) +
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

	// --- kernel syscall totals for a set of sessions (loader still up) -----
	kernelTotals := func(sids ...uint64) (totals map[uint64]map[string]uint64, perProcOut map[uint64]map[string]map[string]uint64) {
		t.Helper()
		want := map[uint64]bool{}
		for _, s := range sids {
			want[s] = true
		}
		totals = map[uint64]map[string]uint64{}
		perProcOut = map[uint64]map[string]map[string]uint64{}
		scMap, err := newMapByName("syscall_counts", baseMaps)
		if err != nil {
			fail(nil, "reading syscall_counts map: %v", err)
		}
		defer scMap.Close()
		it := scMap.Iterate()
		var k [16]byte
		var v uint64
		for it.Next(&k, &v) {
			sid := binary.LittleEndian.Uint64(k[0:8])
			if !want[sid] {
				continue
			}
			if totals[sid] == nil {
				totals[sid] = map[string]uint64{}
				perProcOut[sid] = map[string]map[string]uint64{}
			}
			name := syscallSummaryName(binary.LittleEndian.Uint32(k[12:16]))
			totals[sid][name] += v
			pid := fmt.Sprintf("%d", binary.LittleEndian.Uint32(k[8:12]))
			if perProcOut[sid][pid] == nil {
				perProcOut[sid][pid] = map[string]uint64{}
			}
			perProcOut[sid][pid][name] += v
		}
		if err := it.Err(); err != nil {
			fail(nil, "iterating syscall_counts: %v", err)
		}
		return totals, perProcOut
	}

	// --- one concurrent scenario --------------------------------------------
	// specs are started together, staggered purely by gate files. If
	// withNeg, a negative-control (non-agent) process runs the same
	// kinds of activity while the agents are gated, and its pids/files
	// are returned for the not-in-any-session assertions.
	runScenario := func(name string, specs []*gatedWorkload, withNeg bool) (negPIDs map[uint32]bool, negFiles []string) {
		t.Helper()
		negPIDs = map[uint32]bool{}

		for _, w := range specs {
			if err := os.MkdirAll(w.dir, 0o755); err != nil {
				t.Fatal(err)
			}
			w.cmd = exec.Command(python, "-c", w.rootScript(tcpPort, udpPort))
			w.cmd.Stdout, w.cmd.Stderr = &w.stdout, &w.stderr
			if err := w.cmd.Start(); err != nil {
				fail(nil, "%s: start %s: %v", name, w.label, err)
			}
			w.rootPID = w.cmd.Process.Pid
			w.waitCh = make(chan error, 1)
			go func(w *gatedWorkload) { w.waitCh <- w.cmd.Wait() }(w)
		}

		// Negative control: same interpreter, no matching token. It runs
		// (root + its own fork+exec child, same kinds of file/net
		// activity) while the agent roots sit gated, then exits.
		var negWait chan error
		if withNeg {
			negDir := filepath.Join(tmp, name+"-neg")
			if err := os.MkdirAll(negDir, 0o755); err != nil {
				t.Fatal(err)
			}
			negRootFile := filepath.Join(negDir, "neg-root.txt")
			negChildFile := filepath.Join(negDir, "neg-child.txt")
			negFiles = []string{negRootFile, negChildFile}
			childCode := pythonActivity(negChildFile, tcpPort, udpPort) + pythonWaitHelpers() +
				fmt.Sprintf("\nactivity()\ntouch_pid(%q)\n", filepath.Join(negDir, "neg-child.done"))
			negScript := fmt.Sprintf("RULE_TOKEN = %q\n", tokenFor("neg")) +
				pythonActivity(negRootFile, tcpPort, udpPort) + pythonWaitHelpers() + fmt.Sprintf(`
import subprocess, sys
child_code = %q
p = subprocess.Popen([sys.executable, "-c", child_code])
rc = p.wait()
if rc != 0:
    raise SystemExit("neg child exited %%d" %% rc)
activity()
touch_pid(%q)
`, childCode, filepath.Join(negDir, "neg.done"))
			negCmd := exec.Command(python, "-c", negScript)
			var negErr bytes.Buffer
			negCmd.Stderr = &negErr
			if err := negCmd.Start(); err != nil {
				fail(nil, "%s: start negative control: %v", name, err)
			}
			negPIDs[uint32(negCmd.Process.Pid)] = true
			negWait = make(chan error, 1)
			go func() { negWait <- negCmd.Wait() }()
			childPID := parsePIDFile(t, filepath.Join(negDir, "neg-child.done"), name+" negative-control child done", 60*time.Second)
			negPIDs[uint32(childPID)] = true
			waitFile(t, filepath.Join(negDir, "neg.done"), name+" negative-control done", 60*time.Second)
			if err := <-negWait; err != nil {
				fail(nil, "%s: negative control failed: %v (%s)", name, err, negErr.String())
			}
		}

		// Both agent roots are up and gated. Open the gates.
		for _, w := range specs {
			if pid := parsePIDFile(t, w.path("root.ready"), name+"/"+w.label+" root ready", 60*time.Second); pid != w.rootPID {
				fail(nil, "%s/%s: ready file pid %d != started pid %d", name, w.label, pid, w.rootPID)
			}
		}
		for _, w := range specs {
			touch(t, w.path("root.go"))
		}
		// Children do their activity, then roots do theirs; both signal.
		for _, w := range specs {
			w.childPID = parsePIDFile(t, w.path("child.done"), name+"/"+w.label+" child done", 60*time.Second)
			waitFile(t, w.path("root.done"), name+"/"+w.label+" root done", 60*time.Second)
		}

		// Discover sessions from the root exec events.
		events := poll(name+": root exec events", 60*time.Second, func(evs []capturedEvent) bool {
			found := 0
			for _, w := range specs {
				for i := range evs {
					if evs[i].Type == "exec" && evs[i].PID == uint32(w.rootPID) {
						w.sid = evs[i].SessionID
						found++
						break
					}
				}
			}
			return found == len(specs)
		})
		owner := map[uint32]*gatedWorkload{} // tgid -> workload
		sidSet := map[uint64]bool{}
		for _, w := range specs {
			if w.sid == 0 {
				fail(events, "%s/%s: root exec has session_id 0", name, w.label)
			}
			if sidSet[w.sid] {
				fail(events, "%s: workloads share session %d (want distinct sessions)", name, w.sid)
			}
			sidSet[w.sid] = true
			owner[uint32(w.rootPID)] = w
			owner[uint32(w.childPID)] = w
			for i := range events {
				if events[i].Type == "exec" && events[i].PID == uint32(w.rootPID) && events[i].AgentName != w.agent {
					fail(events, "%s/%s: root exec agent_name = %q, want %q", name, w.label, events[i].AgentName, w.agent)
				}
			}
		}

		// Mid-run isolation: wait until every workload's root+child
		// file/TCP activity and a per-process summary naming the child
		// have been seen, then assert isolation on what exists so far.
		// (Exact summary sums are NOT checked here — sessions are live.)
		hasEv := func(evs []capturedEvent, typ string, w *gatedWorkload, pid int, path string) bool {
			for _, ev := range evs {
				if ev.Type != typ || ev.PID != uint32(pid) || ev.SessionID != w.sid {
					continue
				}
				if path != "" && ev.Path != path {
					continue
				}
				if typ == "net_connect" && ev.Protocol == 17 {
					continue // TCP only for this check; UDP shares the type
				}
				return true
			}
			return false
		}
		events = poll(name+": mid-run activity", 60*time.Second, func(evs []capturedEvent) bool {
			for _, w := range specs {
				if !hasEv(evs, "file_open", w, w.rootPID, w.rootFile) ||
					!hasEv(evs, "file_open", w, w.childPID, w.childFile) ||
					!hasEv(evs, "net_connect", w, w.rootPID, "") ||
					!hasEv(evs, "net_connect", w, w.childPID, "") {
					return false
				}
				childCounted := false
				for _, ev := range evs {
					if ev.Type == "syscall_summary" && ev.SessionID == w.sid {
						if _, ok := ev.PerProcess[fmt.Sprintf("%d", w.childPID)]; ok {
							childCounted = true
						}
					}
				}
				if !childCounted {
					return false
				}
			}
			return true
		})
		assertIsolation := func(evs []capturedEvent, phase string) {
			t.Helper()
			for _, ev := range evs {
				if negPIDs[ev.PID] {
					fail(evs, "%s %s: negative-control pid %d produced an event in session %d: %s", name, phase, ev.PID, ev.SessionID, ev.Raw)
				}
				if w, ok := owner[ev.PID]; ok && ev.SessionID != 0 && ev.SessionID != w.sid {
					fail(evs, "%s %s: pid %d (%s) event in foreign session %d, want %d: %s", name, phase, ev.PID, w.label, ev.SessionID, w.sid, ev.Raw)
				}
				if ev.Type == "syscall_summary" && sidSet[ev.SessionID] {
					var countSum, procSum uint64
					for _, c := range ev.Counts {
						countSum += c
					}
					for pidStr, pc := range ev.PerProcess {
						pid64, err := strconv.ParseUint(pidStr, 10, 32)
						if err != nil {
							fail(evs, "%s %s: bad per_process_counts pid %q", name, phase, pidStr)
						}
						if w, ok := owner[uint32(pid64)]; !ok || w.sid != ev.SessionID {
							fail(evs, "%s %s: syscall_summary for session %d attributes syscalls to foreign tgid %s", name, phase, ev.SessionID, pidStr)
						}
						for _, c := range pc {
							procSum += c
						}
					}
					if countSum != procSum {
						fail(evs, "%s %s: syscall_summary counts sum %d != per_process_counts sum %d (partition broken): %s", name, phase, countSum, procSum, ev.Raw)
					}
				}
			}
			for _, f := range negFiles {
				for _, ev := range evs {
					if ev.Path == f {
						fail(evs, "%s %s: negative-control file %s attributed to session %d (pid %d)", name, phase, f, ev.SessionID, ev.PID)
					}
				}
			}
		}
		assertIsolation(events, "mid-run")

		// Release the children; roots reap them and exit; sessions end.
		for _, w := range specs {
			touch(t, w.path("child.exit"))
		}
		for _, w := range specs {
			select {
			case err := <-w.waitCh:
				if err != nil {
					fail(nil, "%s/%s: workload exited %v\nstdout: %s\nstderr: %s", name, w.label, err, w.stdout.String(), w.stderr.String())
				}
			case <-time.After(60 * time.Second):
				fail(nil, "%s/%s: workload did not exit after child exit gate opened", name, w.label)
			}
		}
		events = poll(name+": session_end for all sessions", 60*time.Second, func(evs []capturedEvent) bool {
			ended := map[uint64]bool{}
			for _, ev := range evs {
				if ev.Type == "session_end" {
					ended[ev.SessionID] = true
				}
			}
			for _, w := range specs {
				if !ended[w.sid] {
					return false
				}
			}
			return true
		})
		assertIsolation(events, "after-end")

		// Exact syscall_summary partition sums — only now: both sessions
		// have ended (final flush precedes session_end), every workload
		// process is dead, so kernel totals are frozen.
		var sids []uint64
		for _, w := range specs {
			sids = append(sids, w.sid)
		}
		kTotals, kPerProc := kernelTotals(sids...)
		final := readEvents(outFile)
		for _, w := range specs {
			jsonTotals := map[string]uint64{}
			jsonPerProc := map[string]map[string]uint64{}
			summaries := 0
			for _, ev := range final {
				if ev.Type != "syscall_summary" || ev.SessionID != w.sid {
					continue
				}
				summaries++
				if ev.AgentName != w.agent {
					fail(final, "%s/%s: syscall_summary agent_name = %q, want %q", name, w.label, ev.AgentName, w.agent)
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
			if summaries == 0 {
				fail(final, "%s/%s: no syscall_summary events for session %d", name, w.label, w.sid)
			}
			if !equalUint64Map(jsonTotals, kTotals[w.sid]) {
				fail(final, "%s/%s: syscall_summary delta sums %v != kernel totals %v", name, w.label, jsonTotals, kTotals[w.sid])
			}
			if len(jsonPerProc) != len(kPerProc[w.sid]) {
				fail(final, "%s/%s: per_process_counts tgids %v != kernel tgids %v", name, w.label, keysOf(jsonPerProc), keysOf(kPerProc[w.sid]))
			}
			for pid, pc := range kPerProc[w.sid] {
				if !equalUint64Map(jsonPerProc[pid], pc) {
					fail(final, "%s/%s: per_process_counts[%s] sums %v != kernel %v", name, w.label, pid, jsonPerProc[pid], pc)
				}
			}
			// Child attribution, exactly: the child's TGID must carry its
			// own kernel counts in THIS session (and therefore in JSON).
			for _, pid := range []int{w.rootPID, w.childPID} {
				key := fmt.Sprintf("%d", pid)
				if len(kPerProc[w.sid][key]) == 0 {
					fail(final, "%s/%s: kernel syscall_counts has no entry for tgid %s in session %d", name, w.label, key, w.sid)
				}
			}
		}
		// Partition across sessions: no TGID counted in two sessions.
		seenTGID := map[string]uint64{}
		for _, w := range specs {
			for pid := range kPerProc[w.sid] {
				if other, dup := seenTGID[pid]; dup {
					fail(final, "%s: tgid %s counted in both session %d and %d", name, pid, other, w.sid)
				}
				seenTGID[pid] = w.sid
			}
		}
		return negPIDs, negFiles
	}

	// --- scenario 1: two different agents + negative control -----------------
	scenarioDir := filepath.Join(tmp, "different")
	alpha := &gatedWorkload{label: "alpha", agent: agentAlpha, ruleToken: tokenFor("alpha"),
		dir: filepath.Join(scenarioDir, "alpha")}
	alpha.rootFile = filepath.Join(alpha.dir, "alpha-root.txt")
	alpha.childFile = filepath.Join(alpha.dir, "alpha-child.txt")
	beta := &gatedWorkload{label: "beta", agent: agentBeta, ruleToken: tokenFor("beta"),
		dir: filepath.Join(scenarioDir, "beta")}
	beta.rootFile = filepath.Join(beta.dir, "beta-root.txt")
	beta.childFile = filepath.Join(beta.dir, "beta-child.txt")
	runScenario("different-agents", []*gatedWorkload{alpha, beta}, true)
	if alpha.sid == beta.sid {
		fail(nil, "different agents produced the same session %d", alpha.sid)
	}

	// --- scenario 2: same agent rule, two instances ---------------------------
	scenarioDir2 := filepath.Join(tmp, "same")
	one := &gatedWorkload{label: "alpha-one", agent: agentAlpha, ruleToken: tokenFor("alpha"),
		dir: filepath.Join(scenarioDir2, "one")}
	one.rootFile = filepath.Join(one.dir, "one-root.txt")
	one.childFile = filepath.Join(one.dir, "one-child.txt")
	two := &gatedWorkload{label: "alpha-two", agent: agentAlpha, ruleToken: tokenFor("alpha"),
		dir: filepath.Join(scenarioDir2, "two")}
	two.rootFile = filepath.Join(two.dir, "two-root.txt")
	two.childFile = filepath.Join(two.dir, "two-child.txt")
	runScenario("same-agent", []*gatedWorkload{one, two}, false)
	if one.sid == two.sid {
		fail(nil, "two instances of the same agent rule produced one session %d, want two distinct sessions", one.sid)
	}

	// --- shutdown: leak/drop checks are covered by ---------------------------
	// TestIntegrationLoaderObserveOnly; here just confirm a clean stop.
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

func equalUint64Map(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
