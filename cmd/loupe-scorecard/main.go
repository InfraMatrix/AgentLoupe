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
	Comm         string   `json:"comm"`
	Filename     string   `json:"filename"`
	Path         string   `json:"path"`
	OldPath      string   `json:"old_path"`
	NewPath      string   `json:"new_path"`
	Daddr        string   `json:"daddr"`
	Dport        uint16   `json:"dport"`
	DNS          bool     `json:"dns"`
	Protocol     uint8    `json:"protocol"`
	ReadB        uint64   `json:"read_bytes"`
	WriteB       uint64   `json:"write_bytes"`
	Partial      bool     `json:"partial"`
	CPUUserMS    uint64   `json:"cpu_user_ms"`
	CPUSysMS     uint64   `json:"cpu_sys_ms"`
	Duration     uint64   `json:"duration_ms"`
	Reason       string   `json:"reason"`
	StillRunning []uint32 `json:"still_running"`
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
	ReadBytes  uint64  `json:"read_bytes"`
	WriteBytes uint64  `json:"write_bytes"`
	Connects   int     `json:"net_connects"`
	DNS        int     `json:"dns_connects"`
	CPUUserMS  uint64  `json:"cpu_user_ms,omitempty"`
	CPUSysMS   uint64  `json:"cpu_sys_ms,omitempty"`
	RootExit   string  `json:"root_exit,omitempty"`
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
	comms, dirs, net map[string]int
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
				paths: map[string]bool{}, comms: map[string]int{},
				dirs: map[string]int{}, net: map[string]int{}}
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
		case "file_open":
			s.Opens++
			if ev.Path != "" {
				s.paths[ev.Path] = true
				s.dirs[filepath.Dir(ev.Path)]++
			}
		case "file_unlink", "file_rename", "file_chmod":
			s.Mutations++
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
		case "root_exit":
			if s.rootExitT.IsZero() {
				s.rootExitT = ts
			}
		case "session_end":
			s.sessionEndT = ts
			s.SessionEndReason = ev.Reason
			s.StillRunning = ev.StillRunning
			s.CPUUserMS, s.CPUSysMS = ev.CPUUserMS, ev.CPUSysMS
		}
	}
	for _, s := range order {
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
		fmt.Printf("%-22s %-10d %7.1fs %6d %6d %7d %7d %9d %9d %5d %d+%d\n",
			trunc(s.Agent, 22), s.SessionID%10000000000, s.DurationS, s.Execs, s.Forks,
			s.Opens, s.UniqPaths, s.ReadBytes, s.WriteBytes, s.Connects, s.CPUUserMS, s.CPUSysMS)
		fmt.Printf("    comms=%v dirs=%v net=%v dns=%d mutations=%d\n",
			s.TopComms, s.TopDirs, s.Net, s.DNS, s.Mutations)
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
