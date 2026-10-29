package app

import (
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"
)

// syscallSummaryName is used in syscall_summary JSONL events. Known
// numbers use the arch table; unknown numbers are "sys_<nr>" per the
// documented event schema (SyscallName's "nr<N>" form stays for stderr).
func syscallSummaryName(nr uint32) string {
	if n, ok := syscallNames[nr]; ok {
		return n
	}
	return fmt.Sprintf("sys_%d", nr)
}

type syscallKey struct {
	sid  uint64
	tgid uint32
	nr   uint32
}

// computeDeltas returns (sid,tgid,nr)->delta and the state that should
// replace prev. Rules:
//   - cur >= prev: delta = cur-prev.
//   - cur < prev: counter reset / entry reuse — delta = cur, never negative.
//   - key in prev but absent from cur (entry deleted/evicted): no delta,
//     and the key is dropped from next state, so a re-created entry
//     counts in full.
//   - key in cur but absent from prev (new entry): delta = cur.
func computeDeltas(prev, cur map[syscallKey]uint64) (deltas map[syscallKey]uint64, next map[syscallKey]uint64) {
	deltas = map[syscallKey]uint64{}
	next = make(map[syscallKey]uint64, len(cur))
	for k, c := range cur {
		next[k] = c
		p, ok := prev[k]
		switch {
		case !ok:
			if c > 0 {
				deltas[k] = c
			}
		case c >= p:
			if c > p {
				deltas[k] = c - p
			}
		default: // c < p: reset/reuse
			if c > 0 {
				deltas[k] = c
			}
		}
	}
	return deltas, next
}

func splitBySession(m map[syscallKey]uint64) map[uint64]map[syscallKey]uint64 {
	out := map[uint64]map[syscallKey]uint64{}
	for k, v := range m {
		s, ok := out[k.sid]
		if !ok {
			s = map[syscallKey]uint64{}
			out[k.sid] = s
		}
		s[k] = v
	}
	return out
}

func joinSession(dst map[syscallKey]uint64, m map[syscallKey]uint64) {
	for k, v := range m {
		dst[k] = v
	}
}

// aggregate turns (tgid,nr) deltas for one session into the wire form:
// session-wide counts by name, plus per-TGID counts by name (JSON object
// keys are strings, so TGIDs are rendered as decimal strings).
func aggregate(deltas map[syscallKey]uint64) (counts map[string]uint64, perProcess map[string]map[string]uint64, total uint64) {
	counts = map[string]uint64{}
	perProcess = map[string]map[string]uint64{}
	for k, d := range deltas {
		if d == 0 {
			continue
		}
		name := syscallSummaryName(k.nr)
		counts[name] += d
		total += d
		pid := fmt.Sprintf("%d", k.tgid)
		pp, ok := perProcess[pid]
		if !ok {
			pp = map[string]uint64{}
			perProcess[pid] = pp
		}
		pp[name] += d
	}
	return counts, perProcess, total
}

// SyscallSummarizer turns cumulative kernel syscall_counts snapshots
// into per-interval syscall_summary JSONL events carrying deltas.
// Previous-value state lives here, in userspace, keyed by (sid, nr).
type SyscallSummarizer struct {
	mu        sync.Mutex
	prev      map[syscallKey]uint64
	closed    map[uint64]bool // flushed at session_end: never emit again for this sid
	snapshot  func() (map[syscallKey]uint64, error)
	write     func(Output) error
	agentName func(sid uint64) string
	parentSID func(sid uint64) uint64
	active    func(sid uint64) bool // session has a session_start in the JSONL
	ts        func() string         // RFC3339Nano wall clock for emitted events
	now       func() time.Time
	lastEmit  time.Time
}

func newSyscallSummarizer(
	snapshot func() (map[syscallKey]uint64, error),
	write func(Output) error,
	agentName func(sid uint64) string,
	active func(sid uint64) bool,
	ts func() string,
	now func() time.Time,
) *SyscallSummarizer {
	if now == nil {
		now = time.Now
	}
	if ts == nil {
		ts = func() string { return now().UTC().Format(time.RFC3339Nano) }
	}
	return &SyscallSummarizer{
		prev: map[syscallKey]uint64{}, closed: map[uint64]bool{}, snapshot: snapshot, write: write,
		agentName: agentName, active: active, ts: ts, now: now, lastEmit: now(),
	}
}

func (s *SyscallSummarizer) intervalMSLocked() int64 {
	if s.lastEmit.IsZero() {
		return 0
	}
	ms := s.now().Sub(s.lastEmit).Milliseconds()
	if ms < 0 {
		return 0
	}
	return ms
}

func (s *SyscallSummarizer) emitLocked(sid uint64, counts map[string]uint64, perProcess map[string]map[string]uint64, intervalMS int64) {
	if s.write == nil {
		return
	}
	out := Output{
		Ts: s.ts(), Type: "syscall_summary", SessionID: sid,
		Fields: map[string]any{
			"interval_ms":        intervalMS,
			"counts":             counts,
			"per_process_counts": perProcess,
		},
	}
	if s.agentName != nil {
		out.AgentName = s.agentName(sid)
	}
	if s.parentSID != nil {
		out.ParentSessionID = s.parentSID(sid)
	}
	_ = s.write(out)
}

// EmitAll snapshots the counters and emits one event per active session
// with non-zero activity since the previous emission. Inactive sessions
// (no session_start yet, e.g. still-provisional) keep their previous
// state untouched, so their counts are not consumed before they can be
// attributed. Returns the number of events emitted.
func (s *SyscallSummarizer) EmitAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot == nil {
		return 0
	}
	cur, err := s.snapshot()
	if err != nil {
		return 0
	}
	intervalMS := s.intervalMSLocked()
	s.lastEmit = s.now()
	curBy := splitBySession(cur)
	prevBy := splitBySession(s.prev)
	sids := map[uint64]bool{}
	for sid := range curBy {
		sids[sid] = true
	}
	for sid := range prevBy {
		sids[sid] = true
	}
	sorted := make([]uint64, 0, len(sids))
	for sid := range sids {
		sorted = append(sorted, sid)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	newPrev := map[syscallKey]uint64{}
	emitted := 0
	for _, sid := range sorted {
		if s.closed[sid] {
			joinSession(newPrev, prevBy[sid])
			continue
		}
		if s.active != nil && !s.active(sid) {
			// Don't consume: retain prior state for this session.
			joinSession(newPrev, prevBy[sid])
			continue
		}
		deltas, next := computeDeltas(prevBy[sid], curBy[sid])
		joinSession(newPrev, next)
		counts, perProcess, total := aggregate(deltas)
		if total == 0 {
			continue
		}
		s.emitLocked(sid, counts, perProcess, intervalMS)
		emitted++
	}
	s.prev = newPrev
	return emitted
}

// FlushSession emits the pending delta for one session (used just before
// its session_end) and closes the session: no further summaries are
// emitted for this sid, so its emitted deltas sum to the kernel totals
// at session end without double-counting.
func (s *SyscallSummarizer) FlushSession(sid uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed[sid] {
		return
	}
	s.closed[sid] = true
	if s.snapshot == nil {
		s.forgetLocked(sid)
		return
	}
	cur, err := s.snapshot()
	if err != nil {
		return
	}
	curBy := splitBySession(cur)
	prevBy := splitBySession(s.prev)
	deltas, next := computeDeltas(prevBy[sid], curBy[sid])
	// Keep post-flush counters as the baseline, so a periodic EmitAll
	// racing the session_end write sees zero delta for this sid.
	s.clearPrevLocked(sid)
	joinSession(s.prev, next)
	counts, perProcess, total := aggregate(deltas)
	if total > 0 {
		s.emitLocked(sid, counts, perProcess, s.intervalMSLocked())
	}
}

// ForgetSession drops previous-value state for a session without emitting
// (rejected/retired sessions).
func (s *SyscallSummarizer) ForgetSession(sid uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgetLocked(sid)
}

func (s *SyscallSummarizer) clearPrevLocked(sid uint64) {
	for k := range s.prev {
		if k.sid == sid {
			delete(s.prev, k)
		}
	}
}

func (s *SyscallSummarizer) forgetLocked(sid uint64) {
	delete(s.closed, sid)
	s.clearPrevLocked(sid)
}

// snapshotSyscallCounts reads the kernel syscall_counts map into a
// (sid, tgid, nr) -> cumulative count map. Shared by the stderr dump and
// the JSONL summarizer. Key layout mirrors struct syscall_key (ABI v3):
// session_id [0:8], tgid [8:12], syscall_nr [12:16].
func snapshotSyscallCounts(l *Loader) (map[syscallKey]uint64, error) {
	out := map[syscallKey]uint64{}
	if l == nil || l.coll == nil {
		return out, nil
	}
	m := l.coll.Maps["syscall_counts"]
	if m == nil {
		return out, nil
	}
	it := m.Iterate()
	var key [16]byte
	var val uint64
	for it.Next(&key, &val) {
		sid := binary.LittleEndian.Uint64(key[0:8])
		tgid := binary.LittleEndian.Uint32(key[8:12])
		nr := binary.LittleEndian.Uint32(key[12:16])
		out[syscallKey{sid, tgid, nr}] = val
	}
	return out, it.Err()
}

func newLoaderSyscallSummarizer(l *Loader, proc *Processor, write func(Output) error) *SyscallSummarizer {
	s := newSyscallSummarizer(
		func() (map[syscallKey]uint64, error) { return snapshotSyscallCounts(l) },
		write,
		func(sid uint64) string {
			if meta, ok := l.LookupMeta(sid); ok {
				return meta.AgentName
			}
			return ""
		},
		func(sid uint64) bool { return proc.HasStarted(sid) },
		func() string { return proc.WallClockNow() },
		time.Now,
	)
	s.parentSID = func(sid uint64) uint64 {
		if meta, ok := l.LookupMeta(sid); ok {
			return meta.ParentSID
		}
		return 0
	}
	return s
}
