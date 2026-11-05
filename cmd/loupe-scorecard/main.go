// loupe-scorecard reduces a Loupe JSONL capture to a per-session
// performance scorecard: duration, exec/fork/exit counts, file activity,
// bytes moved, network connects, and session CPU (when present).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type event struct {
	Ts           string   `json:"ts"`
	Type         string   `json:"type"`
	SessionID    uint64   `json:"session_id"`
	AgentName    string   `json:"agent_name"`
	PID          uint32   `json:"pid"`
	Comm         string   `json:"comm"`
	Filename     string   `json:"filename"`
	Path         string   `json:"path"`
	OldPath      string   `json:"old_path"`
	NewPath      string   `json:"new_path"`
	Daddr        string   `json:"daddr"`
	Dport        uint16   `json:"dport"`
	DNS          bool     `json:"dns"`
	Hostname     string   `json:"hostname"`
	Protocol     uint8    `json:"protocol"`
	ReadB        uint64   `json:"read_bytes"`
	WriteB       uint64   `json:"write_bytes"`
	Bytes        uint64   `json:"bytes"`
	LatencyUs    uint64   `json:"latency_us,omitempty"`
	Partial      bool     `json:"partial"`
	CPUUserMS    uint64   `json:"cpu_user_ms"`
	CPUSysMS     uint64   `json:"cpu_sys_ms"`
	Duration     uint64   `json:"duration_ms"`
	Reason       string   `json:"reason"`
	StillRunning []uint32 `json:"still_running"`
	// hasCPU: this exit/root_exit line carried cpu_user_ms (ABI v4+);
	// older captures omit it and their CPU is unknown, not 0.
	hasCPU bool
}

// cpuPresence detects whether an exit line carries resource fields.
type cpuPresence struct {
	CPUUserMS *uint64 `json:"cpu_user_ms"`
}

type scorecard struct {
	SessionID  uint64  `json:"session_id"`
	Agent      string  `json:"agent"`
	Start      string  `json:"start,omitempty"`
	End        string  `json:"end,omitempty"`
	DurationS  float64 `json:"duration_s"`
	Events     int     `json:"events"`
	Execs      int     `json:"execs"`
	Forks      int     `json:"forks"`
	Exits      int     `json:"exits"`
	Opens      int     `json:"file_opens"`
	UniqPaths  int     `json:"unique_paths"`
	Mutations  int     `json:"mutations"`
	Reads      int     `json:"file_reads"`
	Writes     int     `json:"file_writes"`
	ReadBytes  uint64  `json:"read_bytes"`
	WriteBytes uint64  `json:"write_bytes"`
	Connects   int     `json:"net_connects"`
	DNS        int     `json:"dns_connects"`
	Sends      int     `json:"net_sends"`
	SentBytes  uint64  `json:"net_sent_bytes"`
	Recvs      int     `json:"net_recvs"`
	RecvBytes  uint64  `json:"net_recv_bytes"`
	FirstResp  uint64  `json:"first_response_us,omitempty"`
	// Hostnames seen on this session's sends and recvs (DNS qnames,
	// TLS SNIs), sorted, unique: which names the agent looked up or
	// connected to by name. Empty when no send or recv carried a
	// parseable name.
	Hostnames []string `json:"hostnames,omitempty"`
	CPUUserMS uint64   `json:"cpu_user_ms,omitempty"`
	CPUSysMS  uint64   `json:"cpu_sys_ms,omitempty"`
	// CPUSource says where cpu_user_ms/cpu_sys_ms came from:
	// "session_end" (the root's /proc sample at session end) or, when
	// the capture has no session_end CPU (e.g. it stopped before the
	// session closed), "exits": the sum of every exited process's own
	// CPU from its exit event (ABI v4). Empty when neither exists.
	CPUSource string `json:"cpu_source,omitempty"`
	RootExit  string `json:"root_exit,omitempty"`
	// OrphanGapS is session_end minus root_exit, in seconds: how
	// long the session outlived its root. Set only when both exist.
	OrphanGapS       float64        `json:"orphan_gap_s,omitempty"`
	SessionEndReason string         `json:"session_end_reason,omitempty"`
	StillRunning     []uint32       `json:"still_running,omitempty"`
	TopComms         map[string]int `json:"top_comms"`
	TopDirs          map[string]int `json:"top_dirs"`
	Net              map[string]int `json:"net_by_dest"`
	first, last      time.Time
	rootExitT        time.Time
	sessionEndT      time.Time
	paths            map[string]bool
	hosts            map[string]bool
	comms, dirs, net map[string]int
	exitCPUU         uint64
	exitCPUS         uint64
	exitCPUKnown     bool
	exitPIDs         map[uint32]bool
	rootExitCPU      []event // root_exit lines, used only if their pid had no exit
}

func top(m map[string]int, n int) map[string]int {
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	out := map[string]int{}
	for i, e := range list {
		if i >= n {
			break
		}
		out[e.k] = e.v
	}
	return out
}

func summarize(events []event) []*scorecard {
	byID := map[uint64]*scorecard{}
	var order []*scorecard
	get := func(ev event) *scorecard {
		s, ok := byID[ev.SessionID]
		if !ok {
			s = &scorecard{SessionID: ev.SessionID, Agent: ev.AgentName,
				paths: map[string]bool{}, hosts: map[string]bool{}, exitPIDs: map[uint32]bool{},
				comms: map[string]int{},
				dirs:  map[string]int{}, net: map[string]int{}}
			byID[ev.SessionID] = s
			order = append(order, s)
		}
		if s.Agent == "" {
			s.Agent = ev.AgentName
		}
		return s
	}
	for _, ev := range events {
		s := get(ev)
		s.Events++
		var ts time.Time
		if t, err := time.Parse(time.RFC3339Nano, ev.Ts); err == nil {
			ts = t
			if s.first.IsZero() || t.Before(s.first) {
				s.first = t
			}
			if t.After(s.last) {
				s.last = t
			}
		}
		if ev.Comm != "" {
			s.comms[ev.Comm]++
		}
		switch ev.Type {
		case "exec":
			s.Execs++
		case "fork":
			s.Forks++
		case "exit":
			s.Exits++
			s.exitPIDs[ev.PID] = true
			if ev.hasCPU {
				s.exitCPUU += ev.CPUUserMS
				s.exitCPUS += ev.CPUSysMS
				s.exitCPUKnown = true
			}
		case "file_open":
			s.Opens++
			if ev.Path != "" {
				s.paths[ev.Path] = true
				s.dirs[filepath.Dir(ev.Path)]++
			}
		case "file_unlink", "file_rename", "file_chmod":
			s.Mutations++
		case "file_read", "file_write":
			// Count calls only: byte totals come from file_close,
			// so adding ev.Bytes here would double-count.
			if ev.Type == "file_read" {
				s.Reads++
			} else {
				s.Writes++
			}
		case "file_close":
			// Final close carries cumulative totals; file_io partials
			// are deltas already, so summing both would double-count.
			s.ReadBytes += ev.ReadB
			s.WriteBytes += ev.WriteB
		case "net_connect":
			s.Connects++
			if ev.DNS {
				s.DNS++
			}
			s.net[fmt.Sprintf("%s:%d", ev.Daddr, ev.Dport)]++
		case "net_send":
			// Count calls and bytes; per-dest send volume stays in
			// the timeline's net entries, not here. Hostnames feed
			// the session's sorted unique list below.
			s.Sends++
			s.SentBytes += ev.Bytes
			if ev.Hostname != "" {
				s.hosts[ev.Hostname] = true
			}
		case "net_recv":
			// Count recvs and bytes like sends. FirstResp keeps the
			// first paired send->recv latency: the session's TTFT
			// proxy. latency_us 0 means unpaired (no send seen on
			// this thread/socket), so it never sets FirstResp.
			s.Recvs++
			s.RecvBytes += ev.Bytes
			if ev.LatencyUs > 0 && s.FirstResp == 0 {
				s.FirstResp = ev.LatencyUs
			}
			if ev.Hostname != "" {
				s.hosts[ev.Hostname] = true
			}
		case "root_exit":
			if s.rootExitT.IsZero() {
				s.rootExitT = ts
			}
			if ev.hasCPU {
				s.rootExitCPU = append(s.rootExitCPU, ev)
			}
		case "session_end":
			s.sessionEndT = ts
			s.SessionEndReason = ev.Reason
			s.StillRunning = ev.StillRunning
			s.CPUUserMS, s.CPUSysMS = ev.CPUUserMS, ev.CPUSysMS
		}
	}
	for _, s := range order {
		// root_exit mirrors the root's exit event; count it only when
		// that exit itself was missed, so nothing is counted twice.
		for _, re := range s.rootExitCPU {
			if !s.exitPIDs[re.PID] {
				s.exitCPUU += re.CPUUserMS
				s.exitCPUS += re.CPUSysMS
				s.exitCPUKnown = true
			}
		}
		switch {
		case s.CPUUserMS != 0 || s.CPUSysMS != 0:
			s.CPUSource = "session_end"
		case s.exitCPUKnown:
			s.CPUUserMS, s.CPUSysMS, s.CPUSource = s.exitCPUU, s.exitCPUS, "exits"
		}
		if !s.first.IsZero() {
			s.Start = s.first.Format(time.RFC3339)
		}
		if !s.last.IsZero() {
			s.End = s.last.Format(time.RFC3339)
			s.DurationS = s.last.Sub(s.first).Seconds()
		}
		if !s.rootExitT.IsZero() {
			s.RootExit = s.rootExitT.Format(time.RFC3339)
			if !s.sessionEndT.IsZero() {
				s.OrphanGapS = s.sessionEndT.Sub(s.rootExitT).Seconds()
			}
		}
		s.UniqPaths = len(s.paths)
		for h := range s.hosts {
			s.Hostnames = append(s.Hostnames, h)
		}
		sort.Strings(s.Hostnames)
		s.TopComms = top(s.comms, 5)
		s.TopDirs = top(s.dirs, 5)
		s.Net = top(s.net, 10)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].DurationS > order[j].DurationS })
	return order
}

func main() {
	asJSON := flag.Bool("json", false, "machine-readable output")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: loupe-scorecard [--json] capture.jsonl")
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	var events []event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			// capture_meta (clock anchor + probe set) belongs to no
			// session; counting it would add a phantom session 0.
			if ev.Type == "capture_meta" {
				continue
			}
			if ev.Type == "exit" || ev.Type == "root_exit" {
				var pres cpuPresence
				if json.Unmarshal([]byte(line), &pres) == nil {
					ev.hasCPU = pres.CPUUserMS != nil
				}
			}
			events = append(events, ev)
		}
	}
	cards := summarize(events)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cards)
		return
	}
	fmt.Printf("%-22s %-10s %8s %6s %6s %7s %7s %9s %9s %5s %s\n",
		"agent", "session", "dur", "exec", "fork", "opens", "uniq", "read", "write", "net", "cpu(user+sys ms)")
	for _, s := range cards {
		cpu := "-"
		switch s.CPUSource {
		case "session_end":
			cpu = fmt.Sprintf("%d+%d", s.CPUUserMS, s.CPUSysMS)
		case "exits":
			cpu = fmt.Sprintf("%d+%d (all processes, from exits)", s.CPUUserMS, s.CPUSysMS)
		}
		fmt.Printf("%-22s %-10d %7.1fs %6d %6d %7d %7d %9d %9d %5d %s\n",
			trunc(s.Agent, 22), s.SessionID%10000000000, s.DurationS, s.Execs, s.Forks,
			s.Opens, s.UniqPaths, s.ReadBytes, s.WriteBytes, s.Connects, cpu)
		fmt.Printf("    comms=%v dirs=%v net=%v dns=%d sends=%d sent_bytes=%d recvs=%d recv_bytes=%d hosts=%v mutations=%d reads=%d writes=%d\n",
			s.TopComms, s.TopDirs, s.Net, s.DNS, s.Sends, s.SentBytes, s.Recvs, s.RecvBytes, s.Hostnames, s.Mutations, s.Reads, s.Writes)
		if s.FirstResp > 0 {
			fmt.Printf("    first_response_us=%d\n", s.FirstResp)
		}
		if s.RootExit != "" {
			fmt.Printf("    root_exit=%s orphan_gap=%.1fs end_reason=%s still_running=%v\n",
				s.RootExit, s.OrphanGapS, s.SessionEndReason, s.StillRunning)
		}
	}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
