//go:build integration

// Integration test: real loader, real kernel, real workloads.
// Requires root and a compiled BPF object:
//
//	make build              (as your normal user)
//	sudo make integration   (in a real terminal)
//
// No VM, no kernel matrix — this runs on the host kernel. It is skipped
// unless running as root, and never runs in CI.
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type capturedEvent struct {
	Raw       string
	Type      string `json:"type"`
	SessionID uint64 `json:"session_id"`
	AgentName string `json:"agent_name"`
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
	Path      string `json:"path"`
	Daddr     string `json:"daddr"`
	Dport     uint16 `json:"dport"`
}

func readEvents(path string) []capturedEvent {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []capturedEvent
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev capturedEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // partially written final line while the loader runs
		}
		ev.Raw = line
		out = append(out, ev)
	}
	return out
}

func dumpEvents(events []capturedEvent) string {
	if len(events) == 0 {
		return "(no events captured)"
	}
	var b strings.Builder
	for _, ev := range events {
		b.WriteString(ev.Raw)
		b.WriteByte('\n')
	}
	return b.String()
}

// ---- kernel object snapshots (cilium/ebpf iteration APIs) -----------------

func programSnapshot() (ids map[uint32]bool, names map[uint32]string) {
	ids, names = map[uint32]bool{}, map[uint32]string{}
	var start ebpf.ProgramID
	for {
		id, err := ebpf.ProgramGetNextID(start)
		if err != nil {
			return ids, names
		}
		start = id
		ids[uint32(id)] = true
		if prog, err := ebpf.NewProgramFromID(id); err == nil {
			if info, err := prog.Info(); err == nil {
				names[uint32(id)] = info.Name
			}
			prog.Close()
		}
	}
}

func mapSnapshot() (ids map[uint32]bool, names map[uint32]string) {
	ids, names = map[uint32]bool{}, map[uint32]string{}
	var start ebpf.MapID
	for {
		id, err := ebpf.MapGetNextID(start)
		if err != nil {
			return ids, names
		}
		start = id
		ids[uint32(id)] = true
		if m, err := ebpf.NewMapFromID(id); err == nil {
			if info, err := m.Info(); err == nil {
				names[uint32(id)] = info.Name
			}
			m.Close()
		}
	}
}

func pinnedSnapshot() map[string]bool {
	entries, err := os.ReadDir("/sys/fs/bpf")
	if err != nil {
		return nil // bpffs not mounted: nothing can be pinned there
	}
	out := map[string]bool{}
	for _, e := range entries {
		out[e.Name()] = true
	}
	return out
}

func newMapByName(want string, baseline map[uint32]bool) (*ebpf.Map, error) {
	var start ebpf.MapID
	for {
		id, err := ebpf.MapGetNextID(start)
		if err != nil {
			return nil, fmt.Errorf("no new map named %q found", want)
		}
		start = id
		if baseline[uint32(id)] {
			continue
		}
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err == nil && info.Name == want {
			return m, nil
		}
		m.Close()
	}
}

// linkIDsForPrograms returns bpftool link IDs attached to any of the
// given program IDs. cilium/ebpf v0.17.3 exposes no link iterator, so
// this uses bpftool (a documented requirement for the integration test).
func linkIDsForPrograms(progIDs map[uint32]bool) ([]uint32, error) {
	out, err := exec.Command("bpftool", "-j", "link", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("bpftool link show: %w", err)
	}
	var links []struct {
		ID     uint32 `json:"id"`
		ProgID uint32 `json:"prog_id"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("parse bpftool link output: %w", err)
	}
	var leaked []uint32
	for _, l := range links {
		if progIDs[l.ProgID] {
			leaked = append(leaked, l.ID)
		}
	}
	return leaked, nil
}

var agentloupeMapNames = map[string]bool{
	"tracked_session": true, "sessions": true, "agent_binaries": true,
	"candidates": true, "agent_cgroups": true, "file_infos": true,
	"syscall_counts": true, "session_counter": true, "config_map": true,
	"stats": true, "counters": true, "path_scratch_ma": true,
	"pending_file_op": true, "events": true,
}

func TestIntegrationLoaderObserveOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root: run `sudo make integration`")
	}

	// --- setup -------------------------------------------------------------
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bpfObject := filepath.Join(root, "bpf", "agentloupe.bpf.o")
	if _, err := os.Stat(bpfObject); err != nil {
		t.Fatalf("BPF object missing (%v): run `make build` as your normal user first, then `sudo make integration`\ncaptured event stream:\n%s", err, "(loader never started)")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required for the integration workload: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(python); err == nil {
		python = resolved
	}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("true binary required: %v", err)
	}
	// The kernel reports the resolved exec path: on some distros
	// /usr/bin/true is a symlink (e.g. to gnutrue), so accept either the
	// path as invoked or its symlink-resolved form.
	trueResolved := trueBin
	if resolved, err := filepath.EvalSymlinks(trueBin); err == nil {
		trueResolved = resolved
	}

	tmp := t.TempDir()
	targetFile := filepath.Join(tmp, "probe.txt")
	pidFile := filepath.Join(tmp, "true.pid")
	outFile := filepath.Join(tmp, "events.jsonl")
	token := fmt.Sprintf("al-itg-%d", time.Now().UnixNano())
	const agentName = "itg-agent"

	configPath := filepath.Join(tmp, "agents.yaml")
	configYAML := fmt.Sprintf("agents:\n  - name: %s\n    kind: tool\n    match:\n      interpreter: %s\n      argv_contains: %s\n",
		agentName, python, token)
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Listener the workload connects to.
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
	listenPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	// Baseline kernel-object state, for the post-shutdown leak check.
	baseProgs, _ := programSnapshot()
	baseMaps, _ := mapSnapshot()
	basePinned := pinnedSnapshot()

	// --- start the loader ----------------------------------------------------
	ctx, cancel := context.WithCancel(context.Background())
	var runResult error
	loaderDone := make(chan struct{})
	go func() {
		runResult = Run(ctx, Options{
			BPFObject:     bpfObject,
			ConfigPath:    configPath,
			Output:        outFile,
			StatsInterval: 0,
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

	// --- workload --------------------------------------------------------------
	script := fmt.Sprintf(`
import socket, subprocess
marker = %q
with open(%q, "w") as f:
    f.write("agentloupe")
p = subprocess.Popen([%q])
p.wait()
with open(%q, "w") as f:
    f.write(str(p.pid))
s = socket.create_connection(("127.0.0.1", %d), timeout=5)
s.close()
`, token, targetFile, trueBin, pidFile, listenPort)

	type workloadResult struct {
		pyPID, truePID int
	}
	runWorkload := func() (workloadResult, error) {
		_ = os.Remove(pidFile)
		cmd := exec.Command(python, "-c", script)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return workloadResult{}, fmt.Errorf("workload %s -c ...: %w\nstdout: %s\nstderr: %s", python, err, stdout.String(), stderr.String())
		}
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return workloadResult{}, fmt.Errorf("read true pidfile: %w", err)
		}
		truePID, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return workloadResult{}, fmt.Errorf("parse true pid %q: %w", data, err)
		}
		return workloadResult{pyPID: cmd.Process.Pid, truePID: truePID}, nil
	}

	find := func(events []capturedEvent, w workloadResult) (pyExec, trueExec, fileOpen, connect *capturedEvent) {
		for i := range events {
			ev := &events[i]
			switch {
			case ev.Type == "exec" && ev.PID == uint32(w.pyPID):
				pyExec = ev
			case ev.Type == "exec" && ev.PID == uint32(w.truePID):
				trueExec = ev
			case ev.Type == "file_open" && ev.PID == uint32(w.pyPID) && ev.Path == targetFile:
				fileOpen = ev
			case ev.Type == "net_connect" && ev.PID == uint32(w.pyPID):
				connect = ev
			}
		}
		return pyExec, trueExec, fileOpen, connect
	}

	// Run the workload until every expected event for that run's PIDs has
	// arrived (this also covers the loader's load->attach window), or the
	// overall deadline passes and the assertions below report exactly
	// which events are missing.
	deadline := time.Now().Add(60 * time.Second)
	var lastWorkload workloadResult
	var events []capturedEvent
	for {
		select {
		case <-loaderDone:
			t.Fatalf("loader exited early: %v\ncaptured event stream:\n%s", runResult, dumpEvents(readEvents(outFile)))
		default:
		}
		w, err := runWorkload()
		if err != nil {
			t.Fatalf("%v\ncaptured event stream:\n%s", err, dumpEvents(readEvents(outFile)))
		}
		lastWorkload = w
		pollUntil := time.Now().Add(5 * time.Second)
		for {
			events = readEvents(outFile)
			pyExec, trueExec, fileOpen, connect := find(events, w)
			if pyExec != nil && trueExec != nil && fileOpen != nil && connect != nil {
				goto FOUND
			}
			if time.Now().After(pollUntil) || time.Now().After(deadline) {
				break
			}
			select {
			case <-loaderDone:
				t.Fatalf("loader exited while waiting for events: %v\ncaptured event stream:\n%s", runResult, dumpEvents(events))
			case <-time.After(150 * time.Millisecond):
			}
		}
		if time.Now().After(deadline) {
			break
		}
	}
FOUND:
	events = readEvents(outFile)
	pyExec, trueExec, fileOpen, connect := find(events, lastWorkload)
	fail := func(format string, args ...any) {
		t.Fatalf(format+"\ncaptured event stream (%d events):\n%s", append(args, len(events), dumpEvents(events))...)
	}

	// --- event assertions ------------------------------------------------------
	if pyExec == nil {
		fail("missing exec event for workload interpreter (pid %d)", lastWorkload.pyPID)
	}
	if !strings.HasPrefix(filepath.Base(pyExec.Filename), "python3") {
		fail("interpreter exec filename = %q, want python3 binary (pid %d)", pyExec.Filename, lastWorkload.pyPID)
	}
	if !strings.HasPrefix(pyExec.Comm, "python3") {
		fail("interpreter exec comm = %q, want python3*", pyExec.Comm)
	}
	if pyExec.AgentName != agentName {
		fail("interpreter exec agent_name = %q, want %q (session not confirmed?)", pyExec.AgentName, agentName)
	}

	if trueExec == nil {
		fail("missing exec event for %s workload (pid %d)", trueBin, lastWorkload.truePID)
	}
	if !strings.HasSuffix(trueExec.Filename, "/true") && trueExec.Filename != trueResolved {
		fail("exec filename = %q, want */true or resolved %q", trueExec.Filename, trueResolved)
	}
	if trueExec.Comm != "true" {
		fail("exec comm = %q, want %q", trueExec.Comm, "true")
	}
	if trueExec.AgentName != agentName {
		fail("exec agent_name = %q, want %q (session not inherited by child?)", trueExec.AgentName, agentName)
	}

	if fileOpen == nil {
		fail("missing file_open event for %s (pid %d)", targetFile, lastWorkload.pyPID)
	}
	if fileOpen.AgentName != agentName {
		fail("file_open agent_name = %q, want %q", fileOpen.AgentName, agentName)
	}

	if connect == nil {
		fail("missing net_connect event to 127.0.0.1:%d (pid %d)", listenPort, lastWorkload.pyPID)
	}
	if connect.Daddr != "127.0.0.1" || connect.Dport != listenPort {
		fail("net_connect = %s:%d, want 127.0.0.1:%d", connect.Daddr, connect.Dport, listenPort)
	}
	if connect.AgentName != agentName {
		fail("net_connect agent_name = %q, want %q", connect.AgentName, agentName)
	}

	if pyExec.SessionID == 0 || fileOpen.SessionID != pyExec.SessionID ||
		connect.SessionID != pyExec.SessionID || trueExec.SessionID == 0 {
		fail("session IDs disagree: exec=%d file_open=%d connect=%d child_exec=%d",
			pyExec.SessionID, fileOpen.SessionID, connect.SessionID, trueExec.SessionID)
	}

	// Our programs, for the post-shutdown link cross-reference.
	_, progNames := programSnapshot()
	ourProgs := map[uint32]bool{}
	for id, name := range progNames {
		if !baseProgs[id] && strings.HasPrefix(name, "handle_") {
			ourProgs[id] = true
		}
	}
	if len(ourProgs) == 0 {
		fail("found events but no new handle_* BPF programs in the kernel (loader state inconsistent)")
	}

	// --- drop / lost-visibility counters must be zero -------------------------
	statsMap, err := newMapByName("stats", baseMaps)
	if err != nil {
		fail("reading stats map: %v", err)
	}
	var totalDrops, totalEmitted uint64
	for typ := uint32(1); typ <= 12; typ++ {
		vals := make([]statVal, possibleCPUs())
		key := typ
		if err := statsMap.Lookup(&key, &vals); err != nil {
			fail("stats lookup type %d: %v", typ, err)
		}
		for _, v := range vals {
			totalEmitted += v.Emitted
			totalDrops += v.Drops
		}
	}
	// Close our own map handles before the leak check: an open fd from
	// NewMapFromID keeps the map alive in the kernel, which would look
	// exactly like a loader leak.
	statsMap.Close()
	countersMap, err := newMapByName("counters", baseMaps)
	if err != nil {
		fail("reading counters map: %v", err)
	}
	cvals := make([]agentCounters, possibleCPUs())
	ckey := uint32(0)
	if err := countersMap.Lookup(&ckey, &cvals); err != nil {
		fail("counters lookup: %v", err)
	}
	var lost agentCounters
	for _, v := range cvals {
		lost.TrackedFailed += v.TrackedFailed
		lost.SessionsFailed += v.SessionsFailed
		lost.FileInfoFailed += v.FileInfoFailed
		lost.SyscallFailed += v.SyscallFailed
		lost.AllocFailed += v.AllocFailed
	}
	countersMap.Close() // see statsMap.Close above: don't self-leak into the leak check
	lostTotal := lost.TrackedFailed + lost.SessionsFailed + lost.FileInfoFailed + lost.SyscallFailed + lost.AllocFailed
	if totalDrops != 0 || lostTotal != 0 {
		fail("dropped/lost events: ringbuf_drops=%d (emitted=%d) map_full_failures=%+v (total %d), want all zero",
			totalDrops, totalEmitted, lost, lostTotal)
	}
	if totalEmitted == 0 {
		fail("stats map reports zero emitted events despite captured events (counter readback broken?)")
	}

	// --- shutdown and leak check -------------------------------------------------
	cancel()
	select {
	case <-loaderDone:
		if runResult != nil {
			fail("loader returned error on shutdown: %v", runResult)
		}
	case <-time.After(15 * time.Second):
		fail("loader did not stop within 15s of cancel")
	}
	// The deferred cancel/drain above is now a no-op (loader already done).

	leakDeadline := time.Now().Add(5 * time.Second)
	for {
		progIDs, progNameByID := programSnapshot()
		var leakedProgs []string
		for id := range progIDs {
			if !baseProgs[id] && strings.HasPrefix(progNameByID[id], "handle_") {
				leakedProgs = append(leakedProgs, fmt.Sprintf("%s(%d)", progNameByID[id], id))
			}
		}
		mapIDs, mapNameByID := mapSnapshot()
		var leakedMaps []string
		for id := range mapIDs {
			if !baseMaps[id] && agentloupeMapNames[mapNameByID[id]] {
				leakedMaps = append(leakedMaps, fmt.Sprintf("%s(%d)", mapNameByID[id], id))
			}
		}
		leakedLinks, linkErr := linkIDsForPrograms(ourProgs)
		var leakedPins []string
		if basePinned != nil {
			for name := range pinnedSnapshot() {
				if !basePinned[name] {
					leakedPins = append(leakedPins, name)
				}
			}
		}
		if len(leakedProgs) == 0 && len(leakedMaps) == 0 && len(leakedLinks) == 0 && len(leakedPins) == 0 {
			if linkErr != nil {
				t.Fatalf("link leak check could not run: %v\ncaptured event stream (%d events):\n%s", linkErr, len(events), dumpEvents(events))
			}
			break // clean shutdown: nothing attached, pinned, or left in the kernel
		}
		if time.Now().After(leakDeadline) {
			t.Fatalf("BPF objects leaked after shutdown: programs=%v maps=%v links=%v pinned=%v (link check error: %v)\ncaptured event stream (%d events):\n%s",
				leakedProgs, leakedMaps, leakedLinks, leakedPins, linkErr, len(events), dumpEvents(events))
		}
		time.Sleep(200 * time.Millisecond)
	}
}
