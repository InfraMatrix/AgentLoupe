//go:build integration

// Adoption integration test: real loader, real kernel (companion to
// integration_multi_agent_test.go; same root/BPF-object requirements —
// see `sudo make integration`).
//
// An agent workload is started BEFORE the loader. Once the loader is
// up it must adopt the already-running root AND its pre-existing child
// (same session, correct agent_name from the interpreter argv rule),
// and the workload's later file/network/syscall activity must be
// attributed to that adopted session. Activity from before the loader
// started must NOT appear. A second agent started after the loader
// runs concurrently, with the usual per-session isolation.
//
// Synchronisation is explicit throughout: gate/marker files for the
// workloads, polling the kernel tracked_sessions map for the adoption
// itself, and event polling with generous timeouts. On failure the
// full captured stream is dumped grouped by session.
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
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type adoptedWorkload struct {
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

func (w *adoptedWorkload) path(name string) string { return filepath.Join(w.dir, name) }

// childScript: activity BEFORE the loader exists (must stay invisible),
// signal done, then block on the go gate; afterwards more activity
// (this part must be adopted/attributed), then block on the exit gate.
func (w *adoptedWorkload) childScript(tcpPort, udpPort uint16) string {
	return pythonActivity(w.childFile, tcpPort, udpPort) + pythonWaitHelpers() + fmt.Sprintf(`
activity()
touch_pid(%q)
wait_path(%q)
activity()
touch_pid(%q)
wait_path(%q)
`, w.path("child.done"), w.path("child.go"), w.path("child.after"), w.path("child.exit"))
}

// rootScript: spawns the child, waits until the child's pre-loader
// activity is done, signals "tree is up", then blocks on the go gate.
// After the gate: own activity, then reap the child.
func (w *adoptedWorkload) rootScript(tcpPort, udpPort uint16, ruleToken string) string {
	return fmt.Sprintf("RULE_TOKEN = %q\n", ruleToken) +
		pythonActivity(w.rootFile, tcpPort, udpPort) + pythonWaitHelpers() + fmt.Sprintf(`
import subprocess, sys
touch_pid(%q)
child_code = %q
p = subprocess.Popen([sys.executable, "-c", child_code],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
wait_path(%q)
touch_pid(%q)
wait_path(%q)
activity()
touch_pid(%q)
rc = p.wait()
if rc != 0:
    raise SystemExit("child exited %%d" %% rc)
`, w.path("root.ready"), w.childScript(tcpPort, udpPort), w.path("child.done"),
		w.path("root.prepped"), w.path("root.go"), w.path("root.done"))
}

func TestIntegrationAdoption(t *testing.T) {
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
	tokenFor := func(who string) string { return "al-adopt-" + runID + "-" + who }
	const (
		agentAlpha = "itg-adopted" // pre-started, then adopted
		agentBeta  = "itg-new"     // started after the loader
	)

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

	fail := func(events []capturedEvent, format string, args ...any) {
		t.Helper()
		if events == nil {
			events = readEvents(outFile)
		}
		t.Fatalf(format+"\ncaptured event stream grouped by session (%d events):\n%s",
			append(args, len(events), dumpEventsBySession(events))...)
	}

	// ==== phase 0: the "already running" agent, started pre-loader ======
	a := &adoptedWorkload{dir: filepath.Join(tmp, "adopted")}
	a.rootFile = filepath.Join(a.dir, "adopted-root.txt")
	a.childFile = filepath.Join(a.dir, "adopted-child.txt")
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	a.cmd = exec.Command(python, "-c", a.rootScript(tcpPort, udpPort, tokenFor("alpha")))
	a.cmd.Stdout, a.cmd.Stderr = &a.stdout, &a.stderr
	if err := a.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	a.rootPID = a.cmd.Process.Pid
	a.waitCh = make(chan error, 1)
	go func() { a.waitCh <- a.cmd.Wait() }()
	a.childPID = parsePIDFile(t, a.path("child.done"), "adopted child pre-loader activity done", 60*time.Second)
	waitFile(t, a.path("root.prepped"), "adopted tree up (pre-loader)", 60*time.Second)
	if pid := parsePIDFile(t, a.path("root.ready"), "adopted root ready", 60*time.Second); pid != a.rootPID {
		fail(nil, "adopted root ready pid %d != started pid %d", pid, a.rootPID)
	}
	// Both processes are alive and gated, and the loader does not exist
	// yet: nothing they did so far can ever be attributed.

	// ==== phase 1: loader starts; adoption must find the tree ==========
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

	// Sync on adoption itself, in the kernel tracked_sessions map: root
	// and its pre-existing child must map to the same non-zero session.
	// (Kernel map names are capped at 15 visible chars, so the map is
	// reported as "tracked_session" — match by prefix.)
	openTracked := func() (*ebpf.Map, error) {
		var start ebpf.MapID
		for {
			id, err := ebpf.MapGetNextID(start)
			if err != nil {
				return nil, err
			}
			start = id
			if baseMaps[uint32(id)] {
				continue
			}
			m, err := ebpf.NewMapFromID(id)
			if err != nil {
				continue
			}
			if info, err := m.Info(); err == nil && strings.HasPrefix(info.Name, "tracked_sess") {
				return m, nil
			}
			m.Close()
		}
	}
	trackedSID := func() (uint64, map[int]uint64) {
		m, err := openTracked()
		if err != nil {
			return 0, nil
		}
		defer m.Close()
		out := map[int]uint64{}
		for _, pid := range []int{a.rootPID, a.childPID} {
			key := uint32(pid)
			var v [8]byte
			if err := m.Lookup(&key, &v); err == nil {
				out[pid] = binary.LittleEndian.Uint64(v[:])
			}
		}
		return out[a.rootPID], out
	}
	adoptDeadline := time.Now().Add(60 * time.Second)
	for {
		sid, byPID := trackedSID()
		if sid != 0 && byPID[a.childPID] == sid {
			a.sid = sid
			break
		}
		select {
		case <-loaderDone:
			fail(nil, "loader exited during adoption wait: %v", runResult)
		default:
		}
		if time.Now().After(adoptDeadline) {
			_, byPID := trackedSID()
			fail(nil, "adoption never tracked the pre-existing tree (root %d, child %d): tracked=%v",
				a.rootPID, a.childPID, byPID)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Warm-up with the beta rule: proves hooks are attached before the
	// real beta workload starts (same retry pattern as the other tests).
	warmFile := filepath.Join(tmp, "warmup.txt")
	warmScript := fmt.Sprintf("RULE_TOKEN = %q\n", tokenFor("beta")) +
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

	// ==== phase 2: a newly started agent, concurrent with the adoptee ===
	b := &gatedWorkload{label: "beta", agent: agentBeta, ruleToken: tokenFor("beta"),
		dir: filepath.Join(tmp, "new")}
	b.rootFile = filepath.Join(b.dir, "new-root.txt")
	b.childFile = filepath.Join(b.dir, "new-child.txt")
	if err := os.MkdirAll(b.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b.cmd = exec.Command(python, "-c", b.rootScript(tcpPort, udpPort))
	b.cmd.Stdout, b.cmd.Stderr = &b.stdout, &b.stderr
	if err := b.cmd.Start(); err != nil {
		fail(nil, "start beta workload: %v", err)
	}
	b.rootPID = b.cmd.Process.Pid
	b.waitCh = make(chan error, 1)
	go func() { b.waitCh <- b.cmd.Wait() }()
	if pid := parsePIDFile(t, b.path("root.ready"), "beta root ready", 60*time.Second); pid != b.rootPID {
		fail(nil, "beta root ready pid %d != started pid %d", pid, b.rootPID)
	}

	// Open all gates: adopted tree and new agent work concurrently.
	touch(t, a.path("root.go"))
	touch(t, a.path("child.go"))
	touch(t, b.path("root.go"))
	b.childPID = parsePIDFile(t, b.path("child.done"), "beta child done", 60*time.Second)
	waitFile(t, b.path("root.done"), "beta root done", 60*time.Second)
	waitFile(t, a.path("child.after"), "adopted child post-adoption activity", 60*time.Second)
	waitFile(t, a.path("root.done"), "adopted root post-adoption activity", 60*time.Second)

	hasEv := func(evs []capturedEvent, typ string, sid uint64, pid int, path string) bool {
		for _, ev := range evs {
			if ev.Type == typ && ev.SessionID == sid && ev.PID == uint32(pid) && (path == "" || ev.Path == path) {
				return true
			}
		}
		return false
	}
	events := poll("adopted + new activity attributed", 60*time.Second, func(evs []capturedEvent) bool {
		// Discover beta's session from its root exec.
		for i := range evs {
			if evs[i].Type == "exec" && evs[i].PID == uint32(b.rootPID) {
				b.sid = evs[i].SessionID
			}
		}
		if b.sid == 0 || b.sid == a.sid {
			return false
		}
		return hasEv(evs, "file_open", a.sid, a.rootPID, a.rootFile) &&
			hasEv(evs, "file_open", a.sid, a.childPID, a.childFile) &&
			hasEv(evs, "net_connect", a.sid, a.childPID, "") &&
			hasEv(evs, "file_open", b.sid, b.rootPID, b.rootFile) &&
			hasEv(evs, "file_open", b.sid, b.childPID, b.childFile)
	})
	if b.sid == a.sid {
		fail(events, "adopted and new workloads share session %d", a.sid)
	}

	owner := map[uint32]struct {
		sid   uint64
		agent string
		label string
	}{
		uint32(a.rootPID):  {a.sid, agentAlpha, "adopted-root"},
		uint32(a.childPID): {a.sid, agentAlpha, "adopted-child"},
		uint32(b.rootPID):  {b.sid, agentBeta, "new-root"},
		uint32(b.childPID): {b.sid, agentBeta, "new-child"},
	}
	assertAttribution := func(evs []capturedEvent, phase string) {
		t.Helper()
		starts := map[uint64]int{}
		for _, ev := range evs {
			if ev.Type == "session_start" {
				starts[ev.SessionID]++
			}
			if o, ok := owner[ev.PID]; ok && ev.SessionID != 0 {
				if ev.SessionID != o.sid {
					fail(evs, "%s: %s pid %d event in foreign session %d, want %d: %s",
						phase, o.label, ev.PID, ev.SessionID, o.sid, ev.Raw)
				}
				if ev.AgentName != "" && ev.AgentName != o.agent {
					fail(evs, "%s: %s pid %d agent_name = %q, want %q: %s",
						phase, o.label, ev.PID, ev.AgentName, o.agent, ev.Raw)
				}
			}
			if ev.Type == "syscall_summary" && (ev.SessionID == a.sid || ev.SessionID == b.sid) {
				for pidStr := range ev.PerProcess {
					var pid uint32
					if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
						fail(evs, "%s: bad per_process_counts pid %q", phase, pidStr)
					}
					if o, ok := owner[pid]; !ok || o.sid != ev.SessionID {
						fail(evs, "%s: summary for session %d attributes syscalls to foreign tgid %s", phase, ev.SessionID, pidStr)
					}
				}
			}
		}
		for _, sid := range []uint64{a.sid, b.sid} {
			if starts[sid] != 1 {
				fail(evs, "%s: session %d has %d session_start events, want exactly 1", phase, sid, starts[sid])
			}
		}
	}
	assertAttribution(events, "mid-run")
	// The adopted child's pre-loader activity ran activity() once
	// already; exactly one file_open of its file may be captured (the
	// post-adoption one).
	preOpens := 0
	for _, ev := range events {
		if ev.Type == "file_open" && ev.PID == uint32(a.childPID) && ev.Path == a.childFile {
			preOpens++
		}
	}
	if preOpens != 1 {
		fail(events, "adopted child file_open count for %s = %d, want 1 (pre-loader activity must not be captured)", a.childFile, preOpens)
	}

	// ==== phase 3: both trees exit; sessions end as all_exited ==========
	touch(t, a.path("child.exit"))
	touch(t, b.path("child.exit"))
	for _, w := range []struct {
		label  string
		waitCh chan error
	}{{"adopted", a.waitCh}, {"beta", b.waitCh}} {
		select {
		case err := <-w.waitCh:
			if err != nil {
				fail(nil, "%s: workload exited %v", w.label, err)
			}
		case <-time.After(60 * time.Second):
			fail(nil, "%s: workload did not exit after exit gate opened", w.label)
		}
	}
	events = poll("session_end for adopted and new sessions", 60*time.Second, func(evs []capturedEvent) bool {
		ended := map[uint64]bool{}
		for _, ev := range evs {
			if ev.Type == "session_end" {
				ended[ev.SessionID] = true
			}
		}
		return ended[a.sid] && ended[b.sid]
	})
	assertAttribution(events, "after-end")
	for _, want := range []struct {
		sid     uint64
		rootPID int
		agent   string
		label   string
	}{{a.sid, a.rootPID, agentAlpha, "adopted"}, {b.sid, b.rootPID, agentBeta, "new"}} {
		var rootExit, end *capturedEvent
		for i := range events {
			if events[i].SessionID != want.sid {
				continue
			}
			if events[i].Type == "root_exit" && events[i].PID == uint32(want.rootPID) {
				rootExit = &events[i]
			}
			if events[i].Type == "session_end" {
				end = &events[i]
			}
		}
		if rootExit == nil {
			fail(events, "%s: no root_exit for root pid %d (adopted root identity lost?)", want.label, want.rootPID)
		}
		if rootExit.AgentName != want.agent {
			fail(events, "%s: root_exit agent_name = %q, want %q", want.label, rootExit.AgentName, want.agent)
		}
		if end == nil || end.Reason != "all_exited" {
			fail(events, "%s: session_end = %+v, want reason all_exited", want.label, end)
		}
	}

	// Exact syscall sums, now that both sessions have ended and every
	// process is dead (adopted syscalls count only from adoption on —
	// in both JSONL and the kernel map — so they must agree exactly).
	waitPIDGone(t, a.childPID, "adopted child", 60*time.Second)
	waitPIDGone(t, b.childPID, "new child", 60*time.Second)
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
	final := readEvents(outFile)
	for _, tc := range []struct {
		sid               uint64
		rootPID, childPID int
		label             string
	}{{a.sid, a.rootPID, a.childPID, "adopted"}, {b.sid, b.rootPID, b.childPID, "new"}} {
		kTotals, kPerProc := kernelTotals(tc.sid)
		jsonTotals := map[string]uint64{}
		jsonPerProc := map[string]map[string]uint64{}
		for _, ev := range final {
			if ev.Type != "syscall_summary" || ev.SessionID != tc.sid {
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
			fail(final, "%s: syscall_summary delta sums %v != kernel totals %v", tc.label, jsonTotals, kTotals)
		}
		if len(jsonPerProc) != len(kPerProc) {
			fail(final, "%s: per_process_counts tgids %v != kernel tgids %v", tc.label, keysOf(jsonPerProc), keysOf(kPerProc))
		}
		for pid, pc := range kPerProc {
			if !equalUint64Map(jsonPerProc[pid], pc) {
				fail(final, "%s: per_process_counts[%s] sums %v != kernel %v", tc.label, pid, jsonPerProc[pid], pc)
			}
		}
		for _, pid := range []int{tc.rootPID, tc.childPID} {
			if len(kPerProc[fmt.Sprintf("%d", pid)]) == 0 {
				fail(final, "%s: kernel has no syscall counts for tgid %d in session %d", tc.label, pid, tc.sid)
			}
		}
	}

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
