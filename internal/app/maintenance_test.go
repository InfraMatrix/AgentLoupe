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
	// File mutations are core since slice 1: always attached in LSM mode,
	// no flag required.
	for _, m := range []string{"handle_path_unlink", "handle_path_rename", "handle_path_chmod"} {
		if !lsm[m] {
			t.Errorf("LSM set missing core mutation hook %s: %v", m, lsm)
		}
	}
	// Core process/network hooks are present in both modes.
	for _, core := range []string{"handle_fork", "handle_exit", "handle_tcp_v4_connect", "handle_tcp_v6_connect"} {
		if !lsm[core] || !tp[core] {
			t.Errorf("core hook %s missing from a mode (lsm=%v tp=%v)", core, lsm[core], tp[core])
		}
	}
	// The vfs fexit probes attach when byte accounting OR per-call
	// read/write events are enabled (slice 2a); rw events work without
	// the cumulative counters.
	rwOnly := names(buildRequests(true, Options{EnableFileRWEvents: true}))
	for _, p := range []string{"handle_vfs_read", "handle_vfs_write", "handle_vfs_readv", "handle_vfs_writev"} {
		if !rwOnly[p] {
			t.Errorf("rw-only set missing vfs probe %s: %v", p, rwOnly)
		}
	}
	// Slice 2b: the fentry latency probes ride the same flag with their
	// own tag, so a bad fentry prototype degrades to zero durations
	// instead of losing the fexit events.
	rwTags := func(reqs []progReq) map[string]string {
		out := map[string]string{}
		for _, r := range reqs {
			out[r.Name] = r.Tag
		}
		return out
	}(buildRequests(true, Options{EnableFileRWEvents: true}))
	for _, p := range []string{"handle_vfs_read_entry", "handle_vfs_write_entry", "handle_vfs_readv_entry", "handle_vfs_writev_entry"} {
		if !rwOnly[p] {
			t.Errorf("rw-only set missing fentry latency probe %s: %v", p, rwOnly)
		}
		if rwTags[p] != "lat" {
			t.Errorf("fentry latency probe %s has tag %q, want %q", p, rwTags[p], "lat")
		}
	}
	if names(buildRequests(true, Options{}))["handle_vfs_read"] {
		t.Errorf("default set must not attach vfs probes: per-call I/O is opt-in")
	}
	if names(buildRequests(true, Options{}))["handle_vfs_read_entry"] {
		t.Errorf("default set must not attach fentry latency probes: per-call I/O is opt-in")
	}
	// Slice 3: the sendmsg fexit probes ride their own flag with their
	// own tag, so a bad sendmsg prototype degrades to no send events
	// instead of losing connects.
	sendOnly := names(buildRequests(true, Options{EnableNetSendEvents: true}))
	for _, p := range []string{"handle_tcp_sendmsg", "handle_udp_sendmsg"} {
		if !sendOnly[p] {
			t.Errorf("send-only set missing send probe %s: %v", p, sendOnly)
		}
	}
	sendTags := func(reqs []progReq) map[string]string {
		out := map[string]string{}
		for _, r := range reqs {
			out[r.Name] = r.Tag
		}
		return out
	}(buildRequests(true, Options{EnableNetSendEvents: true}))
	for _, p := range []string{"handle_tcp_sendmsg", "handle_udp_sendmsg"} {
		if sendTags[p] != "netsend" {
			t.Errorf("send probe %s has tag %q, want %q", p, sendTags[p], "netsend")
		}
	}
	if names(buildRequests(true, Options{}))["handle_tcp_sendmsg"] {
		t.Errorf("default set must not attach send probes: per-call sends are opt-in")
	}
	// Slice 4: the sys_enter hostname parser rides the same flag with
	// its own tag, so a verifier rejection degrades to empty hostnames
	// instead of losing the send events.
	if names(buildRequests(true, Options{EnableNetSendEvents: true}))["handle_send_enter"] != true {
		t.Errorf("send-only set missing hostname parser handle_send_enter")
	}
	hostTags := func(reqs []progReq) map[string]string {
		out := map[string]string{}
		for _, r := range reqs {
			out[r.Name] = r.Tag
		}
		return out
	}(buildRequests(true, Options{EnableNetSendEvents: true}))
	if hostTags["handle_send_enter"] != "sndhost" {
		t.Errorf("hostname parser has tag %q, want %q", hostTags["handle_send_enter"], "sndhost")
	}
	if names(buildRequests(true, Options{}))["handle_send_enter"] {
		t.Errorf("default set must not attach the hostname parser: per-call sends are opt-in")
	}
}
