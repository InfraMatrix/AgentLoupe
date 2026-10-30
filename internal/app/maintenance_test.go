package app

import (
	"testing"
	"time"
)

func TestNoSessionDue(t *testing.T) {
	start := time.Unix(1700000000, 0)
	zero := time.Time{}
	cases := []struct {
		name     string
		now      time.Time
		lastWarn time.Time
		seen     uint64
		rules    int
		want     bool
	}{
		{"within grace", start.Add(10 * time.Second), zero, 0, 2, false},
		{"after grace, never warned", start.Add(31 * time.Second), zero, 0, 2, true},
		{"repeat suppressed", start.Add(60 * time.Second), start.Add(31 * time.Second), 0, 2, false},
		{"repeat after a minute", start.Add(92 * time.Second), start.Add(31 * time.Second), 0, 2, true},
		{"session seen", start.Add(5 * time.Minute), zero, 1, 2, false},
		{"no rules configured", start.Add(5 * time.Minute), zero, 0, 0, false},
	}
	for _, tc := range cases {
		if got := noSessionDue(start, tc.lastWarn, tc.now, tc.seen, tc.rules); got != tc.want {
			t.Errorf("%s: noSessionDue = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSessionsSeenCountsDistinctSessionsOnce(t *testing.T) {
	proc := NewProcessor(
		fakeCtrl{meta: SessionMeta{AgentName: "test-agent", RootTGID: 100}},
		time.Unix(1700000000, 0).UTC(),
		func(Output) error { return nil })
	proc.markStarted(42)
	proc.markStarted(42) // re-mark (e.g. duplicate synthesis path): still one
	proc.markStarted(43)
	proc.markEnded(42) // ending must not rewind the ever-seen count
	if got := proc.SessionsSeen(); got != 2 {
		t.Errorf("SessionsSeen = %d, want 2", got)
	}
}

func TestBuildRequestsModes(t *testing.T) {
	names := func(reqs []progReq) map[string]bool {
		out := map[string]bool{}
		for _, r := range reqs {
			out[r.Name] = true
		}
		return out
	}
	lsm := names(buildRequests(true, Options{}))
	if !lsm["handle_file_open"] || !lsm["handle_bprm_committed_creds"] {
		t.Errorf("LSM set missing LSM hooks: %v", lsm)
	}
	if lsm["handle_exec_tp"] || lsm["handle_file_sys_enter"] {
		t.Errorf("LSM set must not contain tracepoint fallback hooks: %v", lsm)
	}
	tp := names(buildRequests(false, Options{}))
	if !tp["handle_exec_tp"] || !tp["handle_file_sys_enter"] || !tp["handle_file_sys_exit"] {
		t.Errorf("tracepoint set missing fallback hooks: %v", tp)
	}
	if tp["handle_file_open"] || tp["handle_bprm_committed_creds"] {
		t.Errorf("tracepoint set must not contain LSM hooks: %v", tp)
	}
	// Core process/network hooks are present in both modes.
	for _, core := range []string{"handle_fork", "handle_exit", "handle_tcp_v4_connect", "handle_tcp_v6_connect"} {
		if !lsm[core] || !tp[core] {
			t.Errorf("core hook %s missing from a mode (lsm=%v tp=%v)", core, lsm[core], tp[core])
		}
	}
}
