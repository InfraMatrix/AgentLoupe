package app

import (
	"reflect"
	"testing"
	"time"
)

// Orphan handling: a session is a process tree, not just its root.
// root_exit marks the root's death; session_end waits for the last
// tracked process (reason all_exited) or the orphan timeout
// (reason orphan_timeout, with the still-running TGIDs listed).

func orphanTestProcessor(out *[]Output, flushes *int) *Processor {
	proc := NewProcessor(
		fakeCtrl{meta: SessionMeta{AgentName: "test-agent", RootTGID: 100}},
		time.Unix(1700000000, 0).UTC(),
		func(o Output) error { *out = append(*out, o); return nil })
	proc.BeforeSessionEnd = func(uint64) { *flushes++ }
	return proc
}

func orphanEvent(typ uint16, tgid uint32, fields map[string]any) *Decoded {
	if fields == nil {
		fields = map[string]any{}
	}
	return &Decoded{Type: typ, SessionID: 42, Tgid: tgid, Comm: "agent", Fields: fields}
}

func outputTypes(out []Output) []string {
	types := make([]string, 0, len(out))
	for _, o := range out {
		types = append(types, o.Type)
	}
	return types
}

func countType(out []Output, typ string) int {
	n := 0
	for _, o := range out {
		if o.Type == typ {
			n++
		}
	}
	return n
}

func findType(out []Output, typ string) *Output {
	for i := range out {
		if out[i].Type == typ {
			return &out[i]
		}
	}
	return nil
}

// spawnOrphan drives a session to the state: root 100 forked child 101,
// child exec'd, root exited (code 3) while the child lives.
func spawnOrphan(proc *Processor) {
	proc.Process(orphanEvent(1, 100, map[string]any{"filename": "/usr/bin/agent"}))
	proc.Process(orphanEvent(2, 100, map[string]any{"child_pid": uint32(101)}))
	proc.Process(orphanEvent(1, 101, map[string]any{"filename": "/usr/bin/helper"}))
	proc.Process(orphanEvent(3, 100, map[string]any{
		"exit_code": int32(3), "cpu_user_ms": uint64(12), "cpu_sys_ms": uint64(3), "max_rss_kb": uint64(45678),
	}))
}

func TestOrphanChildExitsOnItsOwn(t *testing.T) {
	var out []Output
	flushes := 0
	proc := orphanTestProcessor(&out, &flushes)

	spawnOrphan(proc)
	want := []string{"session_start", "exec", "fork", "exec", "exit", "root_exit"}
	if got := outputTypes(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("after root exit: types = %v, want %v", got, want)
	}
	if flushes != 0 {
		t.Errorf("syscall flush ran at root exit (%d), want deferred until session end", flushes)
	}
	rootExit := findType(out, "root_exit")
	if rootExit == nil || rootExit.PID != 100 || rootExit.Fields["exit_code"] != int32(3) {
		t.Errorf("root_exit = %+v, want pid 100 exit_code 3", rootExit)
	}
	// root_exit mirrors the root exit's per-process CPU / peak RSS.
	if rootExit != nil {
		for k, want := range map[string]uint64{"cpu_user_ms": 12, "cpu_sys_ms": 3, "max_rss_kb": 45678} {
			if got := rootExit.Fields[k]; got != want {
				t.Errorf("root_exit %s = %v, want %d", k, got, want)
			}
		}
	}
	if !proc.HasStarted(42) {
		t.Error("session marked ended while orphan still alive")
	}

	// Orphan activity continues under the same session, with no second
	// session_start.
	out = nil
	proc.Process(orphanEvent(4, 101, map[string]any{"path": "/tmp/orphan.txt"}))
	if got := outputTypes(out); !reflect.DeepEqual(got, []string{"file_open"}) {
		t.Fatalf("orphan activity: types = %v, want [file_open]", got)
	}

	// The orphan exits: only now does the session end.
	out = nil
	proc.Process(orphanEvent(3, 101, map[string]any{"exit_code": int32(0)}))
	if got := outputTypes(out); !reflect.DeepEqual(got, []string{"exit", "session_end"}) {
		t.Fatalf("orphan exit: types = %v, want [exit session_end]", got)
	}
	end := findType(out, "session_end")
	if end == nil || end.Fields["reason"] != "all_exited" {
		t.Errorf("session_end = %+v, want reason all_exited", end)
	}
	if _, ok := end.Fields["still_running"]; ok {
		t.Errorf("all_exited session_end must not list still_running: %v", end.Fields)
	}
	if flushes != 1 {
		t.Errorf("flushes = %d, want exactly 1 (at session end)", flushes)
	}
	if proc.HasStarted(42) {
		t.Error("session still marked started after session_end")
	}
}

func TestPostExitEventsDoNotResurrect(t *testing.T) {
	var out []Output
	flushes := 0
	proc := orphanTestProcessor(&out, &flushes)

	spawnOrphan(proc)
	out = nil

	// Teardown events for the dead root (file_close from deferred file
	// freeing arrives after its exit in real captures) are emitted but
	// must not resurrect the root into the alive set — otherwise the
	// session could never end. Same for the child after its exit.
	proc.Process(orphanEvent(8, 100, map[string]any{"path": "/usr/lib/libc.so"}))
	if got := outputTypes(out); !reflect.DeepEqual(got, []string{"file_close"}) {
		t.Fatalf("post-exit root event: types = %v, want [file_close]", got)
	}
	if proc.live[42].alive[100] {
		t.Error("dead root resurrected into alive set by post-exit file_close")
	}

	out = nil
	proc.Process(orphanEvent(3, 101, map[string]any{"exit_code": int32(0)}))
	proc.Process(orphanEvent(8, 101, map[string]any{"path": "/usr/lib/libc.so"}))
	if got := outputTypes(out); !reflect.DeepEqual(got, []string{"exit", "session_end"}) {
		t.Fatalf("orphan exit + teardown: types = %v, want [exit session_end] (teardown dropped after end)", got)
	}
	if end := findType(out, "session_end"); end == nil || end.Fields["reason"] != "all_exited" {
		t.Errorf("session_end = %+v, want reason all_exited", end)
	}
}

func TestOrphanTimeout(t *testing.T) {
	var out []Output
	flushes := 0
	proc := orphanTestProcessor(&out, &flushes)
	proc.OrphanTimeout = time.Minute

	spawnOrphan(proc)
	out = nil

	// Not yet expired: no session_end.
	proc.ExpireOrphans()
	if len(out) != 0 {
		t.Fatalf("ExpireOrphans before deadline emitted %v", outputTypes(out))
	}

	// Expire it: session ends with the orphan listed as still running.
	proc.live[42].rootExitAt = time.Now().Add(-2 * time.Minute)
	proc.ExpireOrphans()
	if got := outputTypes(out); !reflect.DeepEqual(got, []string{"session_end"}) {
		t.Fatalf("after timeout: types = %v, want [session_end]", got)
	}
	end := findType(out, "session_end")
	if end == nil || end.Fields["reason"] != "orphan_timeout" {
		t.Fatalf("session_end = %+v, want reason orphan_timeout", end)
	}
	if end.PID != 100 {
		t.Errorf("orphan_timeout session_end pid = %d, want root 100", end.PID)
	}
	if got := end.Fields["still_running"]; !reflect.DeepEqual(got, []uint32{101}) {
		t.Errorf("still_running = %v, want [101]", got)
	}
	if flushes != 1 {
		t.Errorf("flushes = %d, want 1 (final flush at timeout end)", flushes)
	}

	// The session is closed: the orphan's later events are stragglers
	// and must not reopen it (no second session_start/session_end).
	out = nil
	proc.Process(orphanEvent(4, 101, map[string]any{"path": "/tmp/late.txt"}))
	proc.Process(orphanEvent(3, 101, map[string]any{"exit_code": int32(0)}))
	if len(out) != 0 {
		t.Errorf("post-timeout orphan events emitted %v, want dropped", outputTypes(out))
	}
}

func TestOrphanTimeoutZeroWaitsIndefinitely(t *testing.T) {
	var out []Output
	flushes := 0
	proc := orphanTestProcessor(&out, &flushes)
	// OrphanTimeout left 0.
	spawnOrphan(proc)
	out = nil
	proc.live[42].rootExitAt = time.Now().Add(-24 * time.Hour)
	proc.ExpireOrphans()
	if len(out) != 0 {
		t.Errorf("timeout=0 emitted %v, want indefinite wait", outputTypes(out))
	}
	if countType(out, "session_end") != 0 || flushes != 0 {
		t.Errorf("session ended under indefinite timeout: out=%v flushes=%d", outputTypes(out), flushes)
	}
}
