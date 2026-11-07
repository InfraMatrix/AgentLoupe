package app

import "testing"

// fakeTracked models tracked_sessions for adoptLateChildren.
type fakeTracked map[uint32]uint64

func (f fakeTracked) lookup(tgid uint32) (uint64, bool) { s, ok := f[tgid]; return s, ok }
func (f fakeTracked) insert(tgid uint32, sid uint64) bool {
	if _, ok := f[tgid]; ok {
		return false // UpdateNoExist
	}
	f[tgid] = sid
	return true
}

func TestAdoptLateChildrenCatchesForksDuringTheScan(t *testing.T) {
	const adoptedSID, kernelSID = uint64(7), uint64(9)
	// 100 was adopted by this scan; 200 belongs to a kernel-created session.
	tr := fakeTracked{100: adoptedSID, 200: kernelSID}
	// What /proc shows after the inserts: 101 was forked by 100 after the
	// snapshot but before 100 was tracked (so the fork hook missed it), and
	// 101 has already forked 102 the same way.
	// 102 is listed before its parent, so it can only be found on the pass
	// after 101 joins (exercises the repeat).
	procs := []procEntry{
		{PID: 102, PPID: 101}, {PID: 100, PPID: 1}, {PID: 101, PPID: 100},
		{PID: 200, PPID: 1}, {PID: 201, PPID: 200}, // kernel session: not ours to extend
		{PID: 300, PPID: 1}, // unrelated
	}
	scans := 0
	scan := func() []procEntry { scans++; return procs }
	n := adoptLateChildren(scan, tr.lookup, tr.insert, map[uint64]bool{adoptedSID: true}, 8)

	if n != 2 || tr[101] != adoptedSID || tr[102] != adoptedSID {
		t.Fatalf("late children not adopted: n=%d tracked=%v", n, tr)
	}
	if _, ok := tr[201]; ok {
		t.Fatalf("extended a kernel-created session (could be REJECTED): %v", tr)
	}
	if _, ok := tr[300]; ok {
		t.Fatalf("adopted an unrelated process: %v", tr)
	}
	// pass 1 adds 101, pass 2 adds 102, pass 3 adds nothing and stops.
	if scans != 3 {
		t.Fatalf("scans = %d, want 3 (stop at the first pass that adds nothing)", scans)
	}
}

func TestAdoptLateChildrenNothingToDoIsOneScan(t *testing.T) {
	tr := fakeTracked{100: 7, 101: 7}
	scans := 0
	scan := func() []procEntry { scans++; return []procEntry{{PID: 100, PPID: 1}, {PID: 101, PPID: 100}} }
	if n := adoptLateChildren(scan, tr.lookup, tr.insert, map[uint64]bool{7: true}, 8); n != 0 || scans != 1 {
		t.Fatalf("n=%d scans=%d, want 0 and 1", n, scans)
	}
}

func TestAdoptLateChildrenIsBoundedUnderAForkStorm(t *testing.T) {
	tr := fakeTracked{100: 7}
	next := 101
	scans := 0
	// Every scan reveals one more generation (a process forking faster
	// than /proc can be read): the passes must still stop.
	scan := func() []procEntry {
		scans++
		var out []procEntry
		for pid := 101; pid <= next; pid++ {
			out = append(out, procEntry{PID: pid, PPID: pid - 1})
		}
		next++
		return out
	}
	adoptLateChildren(scan, tr.lookup, tr.insert, map[uint64]bool{7: true}, 4)
	if scans != 4 {
		t.Fatalf("scans = %d, want the bound 4", scans)
	}
}

func TestAdoptionSessionIDsNeverCollideWithKernelIDs(t *testing.T) {
	const runID = uint64(0xdeadbeef)
	l := &Loader{runID: runID, nextSID: (runID << 32) | adoptSIDBit | 1}
	kernelFirst, kernelLast := (runID<<32)|1, (runID<<32)|(adoptSIDBit-1)
	for i := 0; i < 1000; i++ {
		sid := l.allocSIDForAdoption()
		if sid>>32 != runID {
			t.Fatalf("adoption sid %#x lost the run id", sid)
		}
		if sid >= kernelFirst && sid <= kernelLast {
			t.Fatalf("adoption sid %#x is inside the kernel's range", sid)
		}
	}
}
