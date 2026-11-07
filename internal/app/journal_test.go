package app

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// journalRec builds a record as the kernel emits it in the startup window.
func journalRec(typ uint16, tgid, child uint32, journal bool) []byte {
	payload := make([]byte, 8)
	if typ == 1 {
		payload = make([]byte, 1560)
	}
	if typ == 2 {
		binary.LittleEndian.PutUint32(payload[0:4], child)
	}
	var flags uint16
	if journal {
		flags = eventFJournal
	}
	raw := buildRecord(typ, flags, payload)
	sid := uint64(0)
	if !journal {
		sid = 42
	}
	binary.LittleEndian.PutUint64(raw[16:24], sid)
	binary.LittleEndian.PutUint32(raw[40:44], tgid)
	return raw
}

func sidOfRec(raw []byte) uint64   { return binary.LittleEndian.Uint64(raw[16:24]) }
func flagsOfRec(raw []byte) uint16 { return binary.LittleEndian.Uint16(raw[6:8]) }

func TestReconcileJournalLinksThroughAnExitedIntermediate(t *testing.T) {
	const adopted = uint64(0x8000_0001)
	// 100 is an adopted agent. During the walk it forked 101, which forked
	// 102 and exited (double fork): /proc shows 102 re-parented to init,
	// so only the recorded forks link it to the agent.
	member := func(tgid uint32) (uint64, bool) {
		if tgid == 100 {
			return adopted, true
		}
		return 0, false
	}
	recs := [][]byte{
		journalRec(2, 100, 101, true), // agent forks 101
		journalRec(3, 7, 0, false),    // unrelated, already-scoped record: kept as-is
		journalRec(1, 101, 0, true),   // 101 execs
		journalRec(2, 101, 102, true), // 101 forks 102, then exits
		journalRec(2, 500, 501, true), // unrelated host process: discarded
		journalRec(1, 501, 0, true),   // unrelated exec: discarded
	}
	res := reconcileJournal(recs, member)

	if want := map[uint32]uint64{101: adopted, 102: adopted}; !reflect.DeepEqual(res.Joined, want) {
		t.Fatalf("joined = %v, want %v", res.Joined, want)
	}
	if res.Relabeled != 3 || res.Dropped != 2 || len(res.Records) != 4 {
		t.Fatalf("relabeled=%d dropped=%d records=%d, want 3, 2, 4", res.Relabeled, res.Dropped, len(res.Records))
	}
	// Ring order is kept, and kept journal records now belong to the session.
	wantTgids := []uint32{100, 7, 101, 101}
	for i, raw := range res.Records {
		if got := binary.LittleEndian.Uint32(raw[40:44]); got != wantTgids[i] {
			t.Fatalf("record %d tgid %d, want %d", i, got, wantTgids[i])
		}
		if flagsOfRec(raw)&eventFJournal != 0 {
			t.Fatalf("record %d still marked journal", i)
		}
	}
	if sidOfRec(res.Records[0]) != adopted || sidOfRec(res.Records[2]) != adopted || sidOfRec(res.Records[1]) != 42 {
		t.Fatalf("session ids not relabeled correctly")
	}
}

func TestReconcileJournalDoesNotReassignExistingMembers(t *testing.T) {
	member := func(tgid uint32) (uint64, bool) {
		switch tgid {
		case 100:
			return 1, true
		case 101:
			return 2, true // already in another adopted session
		}
		return 0, false
	}
	res := reconcileJournal([][]byte{journalRec(2, 100, 101, true)}, member)
	if len(res.Joined) != 0 {
		t.Fatalf("re-assigned a process that already has a session: %v", res.Joined)
	}
}

func TestReconcileJournalWithNoAdoptionDropsEverythingJournaled(t *testing.T) {
	none := func(uint32) (uint64, bool) { return 0, false }
	res := reconcileJournal([][]byte{
		journalRec(2, 1, 2, true), journalRec(1, 2, 0, true), journalRec(3, 9, 0, false),
	}, none)
	if res.Dropped != 2 || len(res.Records) != 1 || len(res.Joined) != 0 {
		t.Fatalf("dropped=%d records=%d joined=%v", res.Dropped, len(res.Records), res.Joined)
	}
}

func TestDecodeMarksJournalAndProcessorIgnoresIt(t *testing.T) {
	raw := journalRec(1, 501, 0, true)
	d, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Journal {
		t.Fatal("Decode did not mark the journal flag")
	}
	var wrote int
	proc := NewProcessor(fakeCtrl{meta: SessionMeta{AgentName: "a", RootTGID: 501}},
		time.Unix(0, 0), func(Output) error { wrote++; return nil })
	proc.Process(d)
	if wrote != 0 {
		t.Fatalf("an unreconciled journal record reached the capture (%d records written)", wrote)
	}
}

func TestCommKey(t *testing.T) {
	k, ok := commKey("claude")
	if !ok || string(k[:6]) != "claude" || k[6] != 0 || len(k) != commKeyLen {
		t.Fatalf("commKey(claude) = %q, %v", k, ok)
	}
	if _, ok := commKey(""); ok {
		t.Fatal("empty name accepted")
	}
	long := "abcdefghijklmnopqrstuvwxyz01234" // 31 > commKeyMaxName
	if _, ok := commKey(long); ok {
		t.Fatal("name the kernel cannot match exactly was accepted")
	}
	if _, ok := commKey(long[:commKeyMaxName]); !ok {
		t.Fatal("longest kernel-matchable name rejected")
	}
}

func TestExpandExeGlob(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("agent-b", 0o755)
	write("agent-a", 0o755)
	write("agent-notes.txt", 0o644) // not executable
	if err := os.Mkdir(filepath.Join(dir, "agent-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths, capped := expandExeGlob(filepath.Join(dir, "agent-*"))
	want := []string{filepath.Join(dir, "agent-a"), filepath.Join(dir, "agent-b")}
	if capped || !reflect.DeepEqual(paths, want) {
		t.Fatalf("expandExeGlob = %v (capped %v), want %v", paths, capped, want)
	}
	if paths, _ := expandExeGlob("[bad"); paths != nil {
		t.Fatalf("bad pattern matched %v", paths)
	}
}

func TestExpandExeGlobIsCapped(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < maxExeGlobMatches+5; i++ {
		if err := os.WriteFile(filepath.Join(dir, "bin"+itoa(uint32(i))), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths, capped := expandExeGlob(filepath.Join(dir, "bin*"))
	if !capped || len(paths) != maxExeGlobMatches {
		t.Fatalf("got %d paths (capped %v), want %d and capped", len(paths), capped, maxExeGlobMatches)
	}
}

// fakeRing models ringbuf.Reader: Read blocks until a record is pushed,
// Flush is called, or the reader is closed — and it never wakes up on
// its own (the situation that hung the loader on a quiet host).
type fakeRing struct {
	ch      chan []byte
	flush   chan struct{}
	pending [][]byte
}

func newFakeRing() *fakeRing {
	return &fakeRing{ch: make(chan []byte, 16), flush: make(chan struct{}, 1)}
}

func (f *fakeRing) Read() (ringbuf.Record, error) {
	select {
	case b := <-f.ch:
		return ringbuf.Record{RawSample: b}, nil
	case <-f.flush:
		for { // drain what is buffered, then report the flush
			select {
			case b := <-f.ch:
				f.pending = append(f.pending, b)
			default:
				if len(f.pending) > 0 {
					b := f.pending[0]
					f.pending = f.pending[1:]
					f.flush <- struct{}{} // still flushing
					return ringbuf.Record{RawSample: b}, nil
				}
				return ringbuf.Record{}, ringbuf.ErrFlushed
			}
		}
	}
}

func (f *fakeRing) Flush() error { f.flush <- struct{}{}; return nil }

func TestJournalPumpStopsOnAQuietRing(t *testing.T) {
	ring := newFakeRing()
	pump := startJournalPump(ring, t.Logf)
	time.Sleep(10 * time.Millisecond) // the pump is now blocked in Read with nothing coming
	done := make(chan [][]byte, 1)
	go func() {
		recs, _ := pump.stop(ring)
		done <- recs
	}()
	select {
	case recs := <-done:
		if len(recs) != 0 {
			t.Fatalf("got %d records from an empty ring", len(recs))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pump.stop hung on a quiet ring (the startup deadlock)")
	}
}

func TestJournalPumpKeepsEverythingBeforeTheStop(t *testing.T) {
	ring := newFakeRing()
	pump := startJournalPump(ring, t.Logf)
	for i := 0; i < 5; i++ {
		ring.ch <- []byte{byte(i)}
	}
	recs, err := pump.stop(ring)
	if err != nil || len(recs) != 5 {
		t.Fatalf("got %d records (err %v), want all 5 in order", len(recs), err)
	}
	for i, r := range recs {
		if r[0] != byte(i) {
			t.Fatalf("record %d out of order", i)
		}
	}
}
