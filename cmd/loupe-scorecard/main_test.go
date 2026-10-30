package main

import "testing"

func TestSummarize(t *testing.T) {
	events := []event{
		{Ts: "2026-01-01T00:00:00Z", Type: "session_start", SessionID: 1, AgentName: "a"},
		{Ts: "2026-01-01T00:00:01Z", Type: "exec", SessionID: 1, AgentName: "a", Comm: "python3"},
		{Ts: "2026-01-01T00:00:02Z", Type: "file_open", SessionID: 1, AgentName: "a", Path: "/tmp/x"},
		{Ts: "2026-01-01T00:00:03Z", Type: "file_close", SessionID: 1, AgentName: "a", ReadB: 10, WriteB: 20},
		{Ts: "2026-01-01T00:00:04Z", Type: "net_connect", SessionID: 1, AgentName: "a", Daddr: "1.2.3.4", Dport: 53, DNS: true},
		{Ts: "2026-01-01T00:00:05Z", Type: "session_end", SessionID: 1, AgentName: "a", CPUUserMS: 100, CPUSysMS: 50},
	}
	cards := summarize(events)
	if len(cards) != 1 {
		t.Fatalf("cards = %d", len(cards))
	}
	c := cards[0]
	if c.Execs != 1 || c.Opens != 1 || c.UniqPaths != 1 || c.ReadBytes != 10 || c.WriteBytes != 20 ||
		c.Connects != 1 || c.DNS != 1 || c.CPUUserMS != 100 || c.DurationS != 5 {
		t.Errorf("card = %+v", c)
	}
}

func TestSummarizeOrphan(t *testing.T) {
	events := []event{
		{Ts: "2026-01-01T00:00:00Z", Type: "session_start", SessionID: 1, AgentName: "a"},
		{Ts: "2026-01-01T00:00:01Z", Type: "exec", SessionID: 1, AgentName: "a", Comm: "python3"},
		{Ts: "2026-01-01T00:00:02Z", Type: "exit", SessionID: 1, AgentName: "a", Comm: "python3"},
		{Ts: "2026-01-01T00:00:02Z", Type: "root_exit", SessionID: 1, AgentName: "a", Comm: "python3"},
		{Ts: "2026-01-01T00:00:03Z", Type: "file_open", SessionID: 1, AgentName: "a", Comm: "helper", Path: "/tmp/orphan.txt"},
		{Ts: "2026-01-01T00:00:06Z", Type: "session_end", SessionID: 1, AgentName: "a", Reason: "orphan_timeout", StillRunning: []uint32{101}},
		{Ts: "2026-01-01T00:00:00Z", Type: "session_start", SessionID: 2, AgentName: "a"},
		{Ts: "2026-01-01T00:00:01Z", Type: "root_exit", SessionID: 2, AgentName: "a", Comm: "python3"},
		{Ts: "2026-01-01T00:00:04Z", Type: "session_end", SessionID: 2, AgentName: "a", Reason: "all_exited"},
	}
	cards := summarize(events)
	if len(cards) != 2 {
		t.Fatalf("cards = %d", len(cards))
	}
	byID := map[uint64]*scorecard{}
	for _, c := range cards {
		byID[c.SessionID] = c
	}
	c1 := byID[1]
	if c1 == nil || c1.RootExit != "2026-01-01T00:00:02Z" || c1.OrphanGapS != 4 ||
		c1.SessionEndReason != "orphan_timeout" || len(c1.StillRunning) != 1 || c1.StillRunning[0] != 101 {
		t.Errorf("orphan_timeout card = %+v", c1)
	}
	if c1 == nil || c1.Opens != 1 || c1.Exits != 1 { // orphan activity after root exit is counted
		t.Errorf("orphan activity card = %+v", c1)
	}
	c2 := byID[2]
	if c2 == nil || c2.RootExit != "2026-01-01T00:00:01Z" || c2.OrphanGapS != 3 ||
		c2.SessionEndReason != "all_exited" || len(c2.StillRunning) != 0 {
		t.Errorf("all_exited card = %+v", c2)
	}
	// A session with no root_exit/session_end (still open) reports neither.
	events = append(events, event{Ts: "2026-01-01T00:00:07Z", Type: "exec", SessionID: 3, AgentName: "a"})
	c3 := summarize(events)
	found := false
	for _, c := range c3 {
		if c.SessionID == 3 {
			found = true
			if c.RootExit != "" || c.OrphanGapS != 0 || c.SessionEndReason != "" {
				t.Errorf("open-session card = %+v, want no root/gap/reason", c)
			}
		}
	}
	if !found {
		t.Error("session 3 missing")
	}
}
