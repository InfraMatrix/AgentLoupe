package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestComputeDeltas(t *testing.T) {
	key := func(nr uint32) syscallKey { return syscallKey{sid: 1, tgid: 100, nr: nr} }
	tests := []struct {
		name      string
		prev, cur map[syscallKey]uint64
		wantDelta map[syscallKey]uint64
		wantNext  map[syscallKey]uint64
	}{
		{
			name:      "first snapshot counts in full",
			cur:       map[syscallKey]uint64{key(0): 10, key(1): 3},
			wantDelta: map[syscallKey]uint64{key(0): 10, key(1): 3},
			wantNext:  map[syscallKey]uint64{key(0): 10, key(1): 3},
		},
		{
			name:      "delta since previous",
			prev:      map[syscallKey]uint64{key(0): 10, key(1): 3},
			cur:       map[syscallKey]uint64{key(0): 15, key(1): 3},
			wantDelta: map[syscallKey]uint64{key(0): 5},
			wantNext:  map[syscallKey]uint64{key(0): 15, key(1): 3},
		},
		{
			name:      "counter reset never negative",
			prev:      map[syscallKey]uint64{key(0): 100},
			cur:       map[syscallKey]uint64{key(0): 7},
			wantDelta: map[syscallKey]uint64{key(0): 7},
			wantNext:  map[syscallKey]uint64{key(0): 7},
		},
		{
			name:      "deleted entry dropped, reappearing counts in full",
			prev:      map[syscallKey]uint64{key(0): 10, key(1): 5},
			cur:       map[syscallKey]uint64{key(0): 12},
			wantDelta: map[syscallKey]uint64{key(0): 2},
			wantNext:  map[syscallKey]uint64{key(0): 12},
		},
		{
			name:      "per-tgid keys are independent",
			prev:      map[syscallKey]uint64{key(0): 10},
			cur:       map[syscallKey]uint64{key(0): 12, {sid: 1, tgid: 200, nr: 0}: 4},
			wantDelta: map[syscallKey]uint64{key(0): 2, {sid: 1, tgid: 200, nr: 0}: 4},
			wantNext:  map[syscallKey]uint64{key(0): 12, {sid: 1, tgid: 200, nr: 0}: 4},
		},
		{
			name:      "no activity",
			prev:      map[syscallKey]uint64{key(0): 10},
			cur:       map[syscallKey]uint64{key(0): 10},
			wantDelta: map[syscallKey]uint64{},
			wantNext:  map[syscallKey]uint64{key(0): 10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, next := computeDeltas(tt.prev, tt.cur)
			if len(d) != len(tt.wantDelta) {
				t.Fatalf("deltas = %v, want %v", d, tt.wantDelta)
			}
			for k, v := range tt.wantDelta {
				if d[k] != v {
					t.Errorf("delta[%v] = %d, want %d (all: %v)", k, d[k], v, d)
				}
			}
			if len(next) != len(tt.wantNext) {
				t.Fatalf("next = %v, want %v", next, tt.wantNext)
			}
			for k, v := range tt.wantNext {
				if next[k] != v {
					t.Errorf("next[%v] = %d, want %d", k, next[k], v)
				}
			}
		})
	}
	// Deleted-then-recreated sequence across two calls.
	_, next := computeDeltas(map[syscallKey]uint64{key(1): 5}, map[syscallKey]uint64{})
	d, _ := computeDeltas(next, map[syscallKey]uint64{key(1): 4})
	if d[key(1)] != 4 {
		t.Errorf("recreated entry delta = %d, want 4 (not negative / not offset by stale prev)", d[key(1)])
	}
}

type fakeSummarizer struct {
	snaps []map[syscallKey]uint64
	out   []Output
	s     *SyscallSummarizer
	now   time.Time
}

func newFakeSummarizer(active func(uint64) bool) *fakeSummarizer {
	f := &fakeSummarizer{now: time.Unix(1700000000, 0)}
	f.s = newSyscallSummarizer(
		func() (map[syscallKey]uint64, error) {
			if len(f.snaps) == 0 {
				return map[syscallKey]uint64{}, nil
			}
			s := f.snaps[0]
			f.snaps = f.snaps[1:]
			return s, nil
		},
		func(o Output) error { f.out = append(f.out, o); return nil },
		func(sid uint64) string { return "agent-x" },
		active,
		func() string { return f.now.UTC().Format(time.RFC3339Nano) },
		func() time.Time { return f.now },
	)
	return f
}

func TestSyscallSummarizerEmitAllDeltasAndSkipIdle(t *testing.T) {
	f := newFakeSummarizer(func(uint64) bool { return true })
	f.snaps = []map[syscallKey]uint64{
		{{1, 100, 0}: 10, {1, 100, 9999}: 2, {1, 200, 0}: 4}, // tgid 100: read=10, unknown; tgid 200: read=4
		{{1, 100, 0}: 10, {1, 100, 9999}: 2, {1, 200, 0}: 4}, // idle: no event
		{{1, 100, 0}: 13, {1, 100, 9999}: 2, {1, 200, 0}: 4},
	}
	if n := f.s.EmitAll(); n != 1 {
		t.Fatalf("first EmitAll = %d events", n)
	}
	if len(f.out) != 1 || f.out[0].Type != "syscall_summary" || f.out[0].SessionID != 1 || f.out[0].AgentName != "agent-x" {
		t.Fatalf("out = %+v", f.out)
	}
	counts, _ := f.out[0].Fields["counts"].(map[string]uint64)
	if counts["read"] != 14 || counts["sys_9999"] != 2 {
		t.Errorf("counts = %v, want session-wide read=14 (both tgids)", counts)
	}
	perProc, _ := f.out[0].Fields["per_process_counts"].(map[string]map[string]uint64)
	if perProc["100"]["read"] != 10 || perProc["100"]["sys_9999"] != 2 || perProc["200"]["read"] != 4 {
		t.Errorf("per_process_counts = %v, want tgid 100 read=10, tgid 200 read=4", perProc)
	}
	if n := f.s.EmitAll(); n != 0 {
		t.Errorf("idle EmitAll = %d, want 0 (no flood)", n)
	}
	f.s.EmitAll()
	if len(f.out) != 2 {
		t.Fatalf("out len = %d", len(f.out))
	}
	counts, _ = f.out[1].Fields["counts"].(map[string]uint64)
	if len(counts) != 1 || counts["read"] != 3 {
		t.Errorf("second counts = %v, want read=3 only", counts)
	}
	// Totals add up: 10+3 == final cumulative 13.
}

func TestSyscallSummarizerFlushSessionDoesNotConsumeOthers(t *testing.T) {
	f := newFakeSummarizer(func(uint64) bool { return true })
	f.snaps = []map[syscallKey]uint64{
		{{1, 100, 0}: 10, {2, 200, 0}: 20},
		{{1, 100, 0}: 15, {2, 200, 0}: 27}, // flush sid 1 only
		{{1, 100, 0}: 15, {2, 200, 0}: 30}, // emit all: sid1 closed, sid2 delta reaches total 30
	}
	f.s.EmitAll() // emits sid1 read=10 and sid2 read=20
	f.s.FlushSession(1)
	if len(f.out) != 3 || f.out[2].SessionID != 1 {
		t.Fatalf("after flush out = %+v", f.out)
	}
	if c, _ := f.out[2].Fields["counts"].(map[string]uint64); c["read"] != 5 {
		t.Errorf("flush counts = %v, want read=5", c)
	}
	// Sid 1 is now closed (counted 10+5=15, its final total). Sid 2's
	// pending delta must be untouched by sid 1's flush.
	f.s.EmitAll()
	var sid2Total uint64
	for _, o := range f.out {
		if o.SessionID == 2 {
			if c, _ := o.Fields["counts"].(map[string]uint64); c != nil {
				sid2Total += c["read"]
			}
		}
	}
	if sid2Total != 30 {
		t.Errorf("sid2 emitted total = %d, want 30 (flush of sid1 must not consume sid2)", sid2Total)
	}
}

func TestSyscallSummarizerInactiveNotConsumedAndForget(t *testing.T) {
	active := map[uint64]bool{1: false}
	f := newFakeSummarizer(func(sid uint64) bool { return active[sid] })
	f.snaps = []map[syscallKey]uint64{
		{{1, 100, 0}: 10},
		{{1, 100, 0}: 14},
	}
	f.s.EmitAll()
	if len(f.out) != 0 {
		t.Fatalf("inactive emitted %v", f.out)
	}
	active[1] = true
	f.s.EmitAll()
	if len(f.out) != 1 {
		t.Fatalf("after activation out = %v", f.out)
	}
	if c, _ := f.out[0].Fields["counts"].(map[string]uint64); c["read"] != 14 {
		t.Errorf("counts = %v, want accumulated read=14", c)
	}
	f.s.ForgetSession(1)
	if len(f.s.prev) != 0 {
		t.Errorf("prev after Forget = %v", f.s.prev)
	}
}

func TestSyscallSummarizerReset(t *testing.T) {
	f := newFakeSummarizer(func(uint64) bool { return true })
	f.snaps = []map[syscallKey]uint64{{{1, 100, 0}: 100}, {{1, 100, 0}: 7}}
	f.s.EmitAll()
	f.s.EmitAll()
	if len(f.out) != 2 {
		t.Fatalf("out = %v", f.out)
	}
	if c, _ := f.out[1].Fields["counts"].(map[string]uint64); c["read"] != 7 {
		t.Errorf("reset delta = %v, want read=7", c)
	}
}

func TestSyscallSummaryJSONEncoding(t *testing.T) {
	// Session IDs are (run_id<<32)|counter and exceed 2^53: the JSON
	// encoding must keep them exact, not round them via float64.
	const bigSID = uint64(2305843009213706297) // 2^61 + 12345
	out := Output{
		Ts: "2026-01-01T00:00:01Z", Type: "syscall_summary", SessionID: bigSID, AgentName: "agent-x",
		Fields: map[string]any{
			"interval_ms":        int64(1000),
			"counts":             map[string]uint64{"read": 3, "sys_9999": 1},
			"per_process_counts": map[string]map[string]uint64{"100": {"read": 3, "sys_9999": 1}},
		},
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "syscall_summary" || m["agent_name"] != "agent-x" || m["ts"] != "2026-01-01T00:00:01Z" {
		t.Errorf("header fields: %s", b)
	}
	if !strings.Contains(string(b), `"session_id":2305843009213706297`) {
		t.Errorf("session_id not exact in JSON: %s", b)
	}
	if m["interval_ms"] != float64(1000) {
		t.Errorf("numeric fields: %s", b)
	}
	counts, ok := m["counts"].(map[string]any)
	if !ok || counts["read"] != float64(3) || counts["sys_9999"] != float64(1) {
		t.Errorf("counts field: %s", b)
	}
	perProc, ok := m["per_process_counts"].(map[string]any)
	if !ok {
		t.Fatalf("per_process_counts field: %s", b)
	}
	if pp, _ := perProc["100"].(map[string]any); pp["read"] != float64(3) {
		t.Errorf("per_process_counts[100] = %v: %s", perProc["100"], b)
	}
}

// The final flush must be written before session_end so consumers see
// totals add up inside the session's lifetime.
func TestProcessorFlushBeforeSessionEnd(t *testing.T) {
	var out []Output
	wallBase := time.Unix(1700000000, 0).UTC()
	proc := NewProcessor(fakeCtrl{meta: SessionMeta{AgentName: "test-agent", RootTGID: 1234}},
		wallBase, func(o Output) error { out = append(out, o); return nil })
	proc.BeforeSessionEnd = func(sid uint64) {
		_ = proc.write(Output{Ts: wallBase.Format(time.RFC3339Nano), Type: "syscall_summary", SessionID: sid,
			AgentName: "test-agent", Fields: map[string]any{"interval_ms": int64(5), "counts": map[string]uint64{"read": 1}}})
	}
	exec, err := Decode(buildRecord(1, 0, execPayload()))
	if err != nil {
		t.Fatal(err)
	}
	proc.Process(exec)
	exit, err := Decode(buildRecord(3, 0, make([]byte, 8)))
	if err != nil {
		t.Fatal(err)
	}
	out = nil
	proc.Process(exit)
	if len(out) != 3 || out[0].Type != "exit" || out[1].Type != "syscall_summary" || out[2].Type != "session_end" {
		types := []string{}
		for _, o := range out {
			types = append(types, o.Type)
		}
		t.Fatalf("order = %v, want [exit syscall_summary session_end]", types)
	}
}
