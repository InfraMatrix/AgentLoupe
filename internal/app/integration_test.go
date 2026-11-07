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
	"encoding/binary"
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
	Raw          string
	Type         string                       `json:"type"`
	SessionID    uint64                       `json:"session_id"`
	AgentName    string                       `json:"agent_name"`
	PID          uint32                       `json:"pid"`
	PPID         uint32                       `json:"ppid"`
	ChildPID     uint32                       `json:"child_pid"`
	Comm         string                       `json:"comm"`
	Filename     string                       `json:"filename"`
	Path         string                       `json:"path"`
	Daddr        string                       `json:"daddr"`
	Dport        uint16                       `json:"dport"`
	Protocol     uint8                        `json:"protocol"`
	DNS          bool                         `json:"dns"`
	Hostname     string                       `json:"hostname"`
	Duration     *uint64                      `json:"duration_ms"`
	Bytes        *uint64                      `json:"bytes"`
	LatencyUs    *uint64                      `json:"latency_us"`
	ExitCode     int32                        `json:"exit_code"`
	Reason       string                       `json:"reason"`
	StillRunning []uint32                     `json:"still_running"`
	Counts       map[string]uint64            `json:"counts"`
	PerProcess   map[string]map[string]uint64 `json:"per_process_counts"`
	IntervalMS   *int64                       `json:"interval_ms"`
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
	"pending_file_op": true, "rw_inflight": true, "snd_hostnames": true,
	"send_inflight": true, "events": true, "agent_comms": true,
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
	// Slice 5: echo back everything so the workload's recvs exercise
	// the tcp_recvmsg fexit (request->response pairing). Reads then
	// writes back each chunk; the workload reads exactly what it sent,
	// so one 5-byte recv pairs with the one 5-byte send.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2048)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						return
					}
				}
			}(conn)
		}
	}()
	listenPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	// UDP listener: the workload connects (SOCK_DGRAM) to it; Loupe must
	// report it via sys_enter_connect even with TCP fexit attached.
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	// Slice 5: echo UDP datagrams back so the workload's recv exercises
	// the udp_recvmsg fexit. The DNS query sendto also lands here and is
	// echoed to a socket that never reads — harmless, no recv event.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := udpConn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	udpPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)

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
			BPFObject:            bpfObject,
			ConfigPath:           configPath,
			Output:               outFile,
			StatsInterval:        0,
			EnableSyscallSummary: true,
			// Slice 2a: per-call read/write events are opt-in; the
			// workload's 10-byte write to probe.txt must surface as a
			// file_write with bytes=10. Byte accounting stays off to
			// prove rw events work without it.
			EnableFileRWEvents: true,
			// Slice 3: per-call send events are opt-in; the
			// workload's TCP/UDP sends below must surface as
			// net_send events with this call's bytes.
			EnableNetSendEvents: true,
			SyscallInterval:     100 * time.Millisecond,
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
	// Slice 4: the same run also emits one unconnected UDP sendto
	// carrying a hand-built DNS query (exercises the sys_enter DNS
	// parser on the sendto buf/len path) and one TCP send carrying a
	// hand-built ClientHello with an SNI extension (exercises the SNI
	// parser). Both names use .invalid so nothing ever resolves.
	const dnsName = "agentloupe-probe.invalid"
	const sniName = "agentloupe-tls.invalid"
	script := fmt.Sprintf(`
import socket, struct, subprocess, time
marker = %q
with open(%q, "w") as f:
    f.write("agentloupe")
p = subprocess.Popen([%q])
p.wait()
with open(%q, "w") as f:
    f.write(str(p.pid))
s = socket.create_connection(("127.0.0.1", %d), timeout=5)
s.send(b"hello")
time.sleep(0.01)
data = b""
while len(data) < 5:
    chunk = s.recv(5 - len(data))
    if not chunk:
        break
    data += chunk
s.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect(("127.0.0.1", %d))
u.send(b"x")
time.sleep(0.01)
u.recv(1)
u.close()
def qname(name):
    return b"".join(bytes([len(p)]) + p for p in name.split(b".")) + b"\x00"
dnsquery = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname(%q.encode()) + struct.pack(">HH", 1, 1)
u2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u2.sendto(dnsquery, ("127.0.0.1", %d))
u2.close()
sni = %q.encode()
entry = b"\x00" + struct.pack(">H", len(sni)) + sni
extdata = struct.pack(">H", len(entry)) + entry
ext = struct.pack(">HH", 0, len(extdata)) + extdata
extensions = struct.pack(">H", len(ext)) + ext
body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack(">H", 2) + b"\x00\x2f" + bytes([1, 0]) + extensions
hs = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
s2 = socket.create_connection(("127.0.0.1", %d), timeout=5)
s2.send(hello)
s2.close()
`, token, targetFile, trueBin, pidFile, listenPort, udpPort, dnsName, udpPort, sniName, listenPort)

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
			case ev.Type == "net_connect" && ev.PID == uint32(w.pyPID) && ev.Protocol != 17:
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

	// UDP connect must be visible (protocol 17) alongside TCP.
	var udpEv *capturedEvent
	var closeEv *capturedEvent
	var writeEv *capturedEvent
	var readEv *capturedEvent
	var tcpSendEv *capturedEvent
	var udpSendEv *capturedEvent
	var sniSendEv *capturedEvent
	var dnsSendEv *capturedEvent
	var tcpRecvEv *capturedEvent
	var udpRecvEv *capturedEvent
	for i := range events {
		ev := &events[i]
		if ev.Type == "net_connect" && ev.PID == uint32(lastWorkload.pyPID) && ev.Protocol == 17 {
			udpEv = ev
		}
		if ev.Type == "file_close" && ev.PID == uint32(lastWorkload.pyPID) {
			closeEv = ev
		}
		// Slice 2a: the workload's 10-byte write to probe.txt must
		// surface as a discrete file_write with this call's bytes.
		if ev.Type == "file_write" && ev.PID == uint32(lastWorkload.pyPID) && ev.Path == targetFile {
			writeEv = ev
		}
		if ev.Type == "file_read" && ev.PID == uint32(lastWorkload.pyPID) {
			readEv = ev
		}
		// Slice 3: the workload's 5-byte TCP send and 1-byte UDP
		// send must surface as discrete net_send events with this
		// call's bytes. Slice 4: the raw-payload sends carry no
		// hostname, while the DNS query and ClientHello sends carry
		// the parsed names — matched by hostname so each finds
		// exactly its own event.
		if ev.Type == "net_send" && ev.PID == uint32(lastWorkload.pyPID) && ev.Protocol == 6 && ev.Dport == listenPort && ev.Hostname == "" {
			tcpSendEv = ev
		}
		if ev.Type == "net_send" && ev.PID == uint32(lastWorkload.pyPID) && ev.Protocol == 17 && ev.Dport == udpPort && ev.Hostname == "" {
			udpSendEv = ev
		}
		if ev.Type == "net_send" && ev.PID == uint32(lastWorkload.pyPID) && ev.Protocol == 6 && ev.Dport == listenPort && ev.Hostname == sniName {
			sniSendEv = ev
		}
		if ev.Type == "net_send" && ev.PID == uint32(lastWorkload.pyPID) && ev.Protocol == 17 && ev.Dport == udpPort && ev.Hostname == dnsName {
			dnsSendEv = ev
		}
		// Slice 5: the echo replies must surface as discrete net_recv
		// events pairing with the sends above (first match wins: the
		// 10ms sleep guarantees the whole reply is buffered, so one
		// recv consumes the whole pairing).
		if ev.Type == "net_recv" && ev.PID == uint32(lastWorkload.pyPID) && ev.Protocol == 6 && ev.Dport == listenPort && tcpRecvEv == nil {
			tcpRecvEv = ev
		}
		if ev.Type == "net_recv" && ev.PID == uint32(lastWorkload.pyPID) && ev.Protocol == 17 && ev.Dport == udpPort && udpRecvEv == nil {
			udpRecvEv = ev
		}
	}
	if udpEv == nil {
		fail("missing UDP net_connect (protocol=17) to 127.0.0.1:%d", udpPort)
	}
	if udpEv.Dport != udpPort {
		fail("UDP net_connect dport = %d, want %d", udpEv.Dport, udpPort)
	}
	// file_close with duration_ms is LSM-mode only; on the tracepoint
	// fallback there is no close hook, so only assert when present.
	if closeEv != nil && closeEv.Duration == nil {
		fail("file_close present but duration_ms missing: %s", closeEv.Raw)
	}
	if writeEv == nil {
		fail("missing file_write for %s (pid %d) despite --enable-file-rw-events", targetFile, lastWorkload.pyPID)
	}
	if writeEv.Bytes == nil || *writeEv.Bytes != 10 {
		fail("file_write bytes = %d, want 10 (one 10-byte write call): %s", *writeEv.Bytes, writeEv.Raw)
	}
	if writeEv.AgentName != agentName {
		fail("file_write agent_name = %q, want %q", writeEv.AgentName, agentName)
	}
	if readEv == nil {
		fail("missing file_read for workload interpreter (pid %d) despite --enable-file-rw-events", lastWorkload.pyPID)
	}
	if tcpSendEv == nil {
		fail("missing TCP net_send to 127.0.0.1:%d (pid %d) despite --enable-net-send-events", listenPort, lastWorkload.pyPID)
	}
	if tcpSendEv.Bytes == nil || *tcpSendEv.Bytes != 5 {
		fail("TCP net_send bytes = %d, want 5 (one 5-byte send call): %s", *tcpSendEv.Bytes, tcpSendEv.Raw)
	}
	if tcpSendEv.Daddr != "127.0.0.1" {
		fail("TCP net_send daddr = %q, want 127.0.0.1: %s", tcpSendEv.Daddr, tcpSendEv.Raw)
	}
	if tcpSendEv.AgentName != agentName {
		fail("TCP net_send agent_name = %q, want %q", tcpSendEv.AgentName, agentName)
	}
	if tcpSendEv.Hostname != "" {
		fail("TCP net_send hostname = %q, want empty (raw payload holds no name): %s", tcpSendEv.Hostname, tcpSendEv.Raw)
	}
	if udpSendEv == nil {
		fail("missing UDP net_send to 127.0.0.1:%d (pid %d) despite --enable-net-send-events", udpPort, lastWorkload.pyPID)
	}
	if udpSendEv.Bytes == nil || *udpSendEv.Bytes != 1 {
		fail("UDP net_send bytes = %d, want 1 (one 1-byte send call): %s", *udpSendEv.Bytes, udpSendEv.Raw)
	}
	if udpSendEv.Hostname != "" {
		fail("UDP net_send hostname = %q, want empty (raw payload holds no name): %s", udpSendEv.Hostname, udpSendEv.Raw)
	}
	// Slice 4: the DNS query sendto must surface the parsed qname, and
	// the ClientHello send the parsed SNI, with this call's bytes.
	// Expected sizes mirror the workload's packet construction above:
	// DNS = 12B header + qname (len-prefixed labels + root) + qtype/qclass;
	// ClientHello = record(5) + hs hdr(4) + version(2) + random(32) +
	// session_id(1) + cipher_suites(2+2) + compression(1+1) +
	// extensions_len(2) + ext(type 2 + len 2 + list_len 2 + entry 1+2+len).
	wantDNSBytes := uint64(12 + 4)
	for _, label := range strings.Split(dnsName, ".") {
		wantDNSBytes += uint64(1 + len(label))
	}
	wantDNSBytes++ // root terminator
	wantSNIBytes := uint64(5 + 4 + 2 + 32 + 1 + (2 + 2) + (1 + 1) + 2 + (2 + 2 + 2 + (1 + 2 + len(sniName))))
	if dnsSendEv == nil {
		fail("missing DNS net_send to 127.0.0.1:%d with hostname %q (pid %d) despite --enable-net-send-events", udpPort, dnsName, lastWorkload.pyPID)
	}
	if dnsSendEv.Bytes == nil || *dnsSendEv.Bytes != wantDNSBytes {
		fail("DNS net_send bytes = %d, want %d (one query sendto): %s", *dnsSendEv.Bytes, wantDNSBytes, dnsSendEv.Raw)
	}
	if sniSendEv == nil {
		fail("missing SNI net_send to 127.0.0.1:%d with hostname %q (pid %d) despite --enable-net-send-events", listenPort, sniName, lastWorkload.pyPID)
	}
	if sniSendEv.Bytes == nil || *sniSendEv.Bytes != wantSNIBytes {
		fail("SNI net_send bytes = %d, want %d (one ClientHello send): %s", *sniSendEv.Bytes, wantSNIBytes, sniSendEv.Raw)
	}
	if sniSendEv.AgentName != agentName {
		fail("SNI net_send agent_name = %q, want %q", sniSendEv.AgentName, agentName)
	}
	// Slice 5: the echo replies must pair with the sends above. The
	// workload sleeps 10ms between each send and its recv, so the
	// paired latency is ~10ms — the floor of 5ms leaves 2x margin for
	// scheduling noise while still proving the pairing (an unpaired
	// recv would report latency_us = 0).
	if tcpRecvEv == nil {
		fail("missing TCP net_recv to 127.0.0.1:%d (pid %d) despite --enable-net-send-events", listenPort, lastWorkload.pyPID)
	}
	if tcpRecvEv.Bytes == nil || *tcpRecvEv.Bytes != 5 {
		fail("TCP net_recv bytes = %v, want 5 (one 5-byte echo read): %s", tcpRecvEv.Bytes, tcpRecvEv.Raw)
	}
	if tcpRecvEv.Daddr != "127.0.0.1" {
		fail("TCP net_recv daddr = %q, want 127.0.0.1: %s", tcpRecvEv.Daddr, tcpRecvEv.Raw)
	}
	if tcpRecvEv.Hostname != "" {
		fail("TCP net_recv hostname = %q, want empty (paired with the raw-payload send): %s", tcpRecvEv.Hostname, tcpRecvEv.Raw)
	}
	if tcpRecvEv.LatencyUs == nil || *tcpRecvEv.LatencyUs < 5000 {
		fail("TCP net_recv latency_us = %v, want >= 5000 (10ms send->recv sleep): %s", tcpRecvEv.LatencyUs, tcpRecvEv.Raw)
	}
	if udpRecvEv == nil {
		fail("missing UDP net_recv to 127.0.0.1:%d (pid %d) despite --enable-net-send-events", udpPort, lastWorkload.pyPID)
	}
	if udpRecvEv.Bytes == nil || *udpRecvEv.Bytes != 1 {
		fail("UDP net_recv bytes = %v, want 1 (one 1-byte echo read): %s", udpRecvEv.Bytes, udpRecvEv.Raw)
	}
	if udpRecvEv.Daddr != "127.0.0.1" {
		fail("UDP net_recv daddr = %q, want 127.0.0.1: %s", udpRecvEv.Daddr, udpRecvEv.Raw)
	}
	if udpRecvEv.Hostname != "" {
		fail("UDP net_recv hostname = %q, want empty (paired with the raw-payload send): %s", udpRecvEv.Hostname, udpRecvEv.Raw)
	}
	if udpRecvEv.LatencyUs == nil || *udpRecvEv.LatencyUs < 5000 {
		fail("UDP net_recv latency_us = %v, want >= 5000 (10ms send->recv sleep): %s", udpRecvEv.LatencyUs, udpRecvEv.Raw)
	}

	if pyExec.SessionID == 0 || fileOpen.SessionID != pyExec.SessionID ||
		connect.SessionID != pyExec.SessionID || trueExec.SessionID == 0 ||
		writeEv.SessionID != pyExec.SessionID || tcpSendEv.SessionID != pyExec.SessionID ||
		sniSendEv.SessionID != pyExec.SessionID || dnsSendEv.SessionID != pyExec.SessionID ||
		tcpRecvEv.SessionID != pyExec.SessionID || udpRecvEv.SessionID != pyExec.SessionID {
		fail("session IDs disagree: exec=%d file_open=%d connect=%d child_exec=%d file_write=%d net_send=%d sni_send=%d dns_send=%d tcp_recv=%d udp_recv=%d",
			pyExec.SessionID, fileOpen.SessionID, connect.SessionID, trueExec.SessionID, writeEv.SessionID, tcpSendEv.SessionID, sniSendEv.SessionID, dnsSendEv.SessionID, tcpRecvEv.SessionID, udpRecvEv.SessionID)
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
	for typ := uint32(1); typ <= 16; typ++ {
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

	// Syscall summary (--enable-syscall-summary) must have counted
	// something for the workload session. Record the kernel's cumulative
	// totals for that session now (the workload has finished, so they
	// can no longer change) to compare against the JSONL deltas below.
	kernelSyscallTotals := map[string]uint64{}
	kernelPerProcess := map[string]map[string]uint64{}
	if scMap, err := newMapByName("syscall_counts", baseMaps); err == nil {
		it := scMap.Iterate()
		var k [16]byte
		var v uint64
		n := 0
		for it.Next(&k, &v) {
			n++
			// struct syscall_key (tgid since ABI v3): sid [0:8], tgid [8:12], nr [12:16].
			if binary.LittleEndian.Uint64(k[0:8]) == pyExec.SessionID {
				name := syscallSummaryName(binary.LittleEndian.Uint32(k[12:16]))
				kernelSyscallTotals[name] += v
				pid := fmt.Sprintf("%d", binary.LittleEndian.Uint32(k[8:12]))
				pp, ok := kernelPerProcess[pid]
				if !ok {
					pp = map[string]uint64{}
					kernelPerProcess[pid] = pp
				}
				pp[name] += v
			}
		}
		scMap.Close()
		if n == 0 {
			fail("syscall_counts map empty despite --enable-syscall-summary")
		}
		if len(kernelSyscallTotals) == 0 {
			fail("syscall_counts has no entries for workload session %d", pyExec.SessionID)
		}
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

	// syscall_summary JSONL: at least one event for the workload session,
	// a final one before its session_end, and deltas that add up exactly
	// to the kernel's cumulative totals recorded above.
	{
		final := readEvents(outFile)
		jsonTotals := map[string]uint64{}
		jsonPerProcess := map[string]map[string]uint64{}
		summaries := 0
		lastSummaryIdx, sessionEndIdx := -1, -1
		for i, ev := range final {
			if ev.SessionID != pyExec.SessionID {
				continue
			}
			switch ev.Type {
			case "syscall_summary":
				summaries++
				lastSummaryIdx = i
				if ev.AgentName != agentName {
					fail("syscall_summary agent_name = %q, want %q", ev.AgentName, agentName)
				}
				if ev.IntervalMS == nil {
					fail("syscall_summary missing interval_ms: %s", ev.Raw)
				}
				if len(ev.Counts) == 0 {
					fail("syscall_summary with empty counts: %s", ev.Raw)
				}
				for name, c := range ev.Counts {
					jsonTotals[name] += c
				}
				if len(ev.PerProcess) == 0 {
					fail("syscall_summary missing per_process_counts: %s", ev.Raw)
				}
				for pid, pc := range ev.PerProcess {
					pp, ok := jsonPerProcess[pid]
					if !ok {
						pp = map[string]uint64{}
						jsonPerProcess[pid] = pp
					}
					for name, c := range pc {
						pp[name] += c
					}
				}
			case "session_end":
				sessionEndIdx = i
			}
		}
		if summaries == 0 {
			fail("no syscall_summary events in JSONL for workload session %d\ncaptured event stream (%d events):\n%s", pyExec.SessionID, len(final), dumpEvents(final))
		}
		if sessionEndIdx >= 0 && (lastSummaryIdx < 0 || lastSummaryIdx > sessionEndIdx) {
			fail("last syscall_summary (line %d) is not before session_end (line %d)", lastSummaryIdx, sessionEndIdx)
		}
		if len(jsonTotals) != len(kernelSyscallTotals) {
			fail("syscall_summary totals %v != kernel totals %v", jsonTotals, kernelSyscallTotals)
		}
		for name, kv := range kernelSyscallTotals {
			if jsonTotals[name] != kv {
				fail("syscall_summary delta sum for %s = %d, want kernel total %d (all: json=%v kernel=%v)", name, jsonTotals[name], kv, jsonTotals, kernelSyscallTotals)
			}
		}
		// Per-process attribution must add up to the same kernel totals,
		// split by TGID.
		if len(jsonPerProcess) != len(kernelPerProcess) {
			fail("per_process_counts pids %v != kernel (sid,tgid,nr) pids %v", jsonPerProcess, kernelPerProcess)
		}
		for pid, pc := range kernelPerProcess {
			for name, kv := range pc {
				if jsonPerProcess[pid][name] != kv {
					fail("per_process_counts[%s][%s] = %d, want kernel total %d (json=%v kernel=%v)", pid, name, jsonPerProcess[pid][name], kv, jsonPerProcess, kernelPerProcess)
				}
			}
		}
		if _, ok := kernelPerProcess[fmt.Sprintf("%d", lastWorkload.pyPID)]; !ok {
			fail("kernel syscall_counts has no entries for workload pid %d (per-process attribution broken): %v", lastWorkload.pyPID, kernelPerProcess)
		}
	}

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
