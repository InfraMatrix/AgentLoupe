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
