package app

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Startup journal (ABI v9).
//
// The loader attaches its hooks before walking /proc, so anything that
// starts during the walk is either scoped by the kernel at exec or found
// by the walk. One case is left: a process forked from an already-running
// agent that itself forks and exits before the walk reaches it (double-
// fork daemonisation). Its children are re-parented away from the agent,
// so the walk cannot link them, and the fork hook could not either (the
// agent was not tracked yet).
//
// So for the startup window only (hooks attached -> adoption done) the
// kernel also emits OUT-OF-SCOPE forks and execs as EVENT_F_JOURNAL
// records with session 0. A reader drains them as they arrive (so the
// ring cannot fill during the walk); afterwards reconcileJournal follows
// the recorded fork edges from every adopted process, joins the
// descendants to that session (even through exited intermediates), and
// relabels their recorded fork/exec events into the capture. All other
// journal records are discarded. Nothing blocks: the kernel side only
// writes ring-buffer records, which it drops (and counts) when full.

// eventFJournal mirrors EVENT_F_JOURNAL in bpf/agentloupe.h.
const eventFJournal = 1 << 5

// journalPump drains the ring buffer into memory during the startup
// window, before the Processor exists.
type journalPump struct {
	mu      sync.Mutex
	records [][]byte
	done    chan struct{}
	err     error
}

// recordReader is the part of *ringbuf.Reader the pump uses (an interface
// so the stop path can be tested without a kernel).
type recordReader interface {
	Read() (ringbuf.Record, error)
	Flush() error
}

func startJournalPump(rd recordReader, logf func(string, ...any)) *journalPump {
	p := &journalPump{done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrFlushed) {
					return // stop requested; ring drained up to the flush
				}
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
					p.err = err
					return
				}
				logf("warn: ring buffer read (startup): %v", err)
				continue
			}
			raw := make([]byte, len(rec.RawSample))
			copy(raw, rec.RawSample)
			p.mu.Lock()
			p.records = append(p.records, raw)
			p.mu.Unlock()
		}
	}()
	return p
}

// stop drains everything already in the ring and returns it. Call after
// the journal flag is cleared: the grace covers programs that read the
// flag just before it flipped and commit a moment later.
//
// Flush, not SetDeadline: a Read blocked in epoll_wait holds the reader's
// lock (SetDeadline would wait for it, i.e. for the next event, which on
// a quiet host may never come) and only reads the deadline when it starts
// waiting. Flush wakes it; Read then returns the buffered records followed
// by ErrFlushed, and the wakeup is consumed, so the reader keeps working.
func (p *journalPump) stop(rd recordReader) ([][]byte, error) {
	time.Sleep(journalGrace)
	_ = rd.Flush() // fails only on a closed reader, where the pump exits on ErrClosed
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.records, p.err
}

const journalGrace = 20 * time.Millisecond

// journalResult is what reconcileJournal decided.
type journalResult struct {
	Records   [][]byte          // every non-journal record, plus relabeled journal ones, in ring order
	Joined    map[uint32]uint64 // tgid -> session, linked only through recorded forks
	Relabeled int               // journal records kept (now part of an adopted session)
	Dropped   int               // journal records discarded (not an agent's activity)
}

// reconcileJournal follows recorded fork edges from adopted sessions.
// member(tgid) reports the session a process belongs to now, if that
// session was created by this adoption (newSIDs); processes linked by a
// recorded fork from a member become members too. Ring order is causal
// for fork chains (a child cannot run, let alone fork, before its
// parent's fork record is reserved), so one pass in order suffices.
func reconcileJournal(records [][]byte, member func(uint32) (uint64, bool)) journalResult {
	res := journalResult{Joined: map[uint32]uint64{}}
	sidOf := func(tgid uint32) (uint64, bool) {
		if sid, ok := res.Joined[tgid]; ok {
			return sid, true
		}
		return member(tgid)
	}
	for _, raw := range records {
		if len(raw) < 72 {
			continue
		}
		flags := binary.LittleEndian.Uint16(raw[6:8])
		if flags&eventFJournal == 0 {
			res.Records = append(res.Records, raw)
			continue
		}
		typ := binary.LittleEndian.Uint16(raw[0:2])
		tgid := binary.LittleEndian.Uint32(raw[40:44])
		sid, ok := sidOf(tgid)
		if !ok || (typ != 1 && typ != 2) {
			res.Dropped++
			continue
		}
		if typ == 2 { // fork: payload starts with child_tgid
			if len(raw) < 76 {
				res.Dropped++
				continue
			}
			child := binary.LittleEndian.Uint32(raw[72:76])
			if _, already := sidOf(child); !already {
				res.Joined[child] = sid
			}
		}
		binary.LittleEndian.PutUint64(raw[16:24], sid)
		binary.LittleEndian.PutUint16(raw[6:8], flags&^eventFJournal)
		res.Records = append(res.Records, raw)
		res.Relabeled++
	}
	return res
}

// finishStartupJournal stops the journal and reconciles it against the
// sessions adoption created: joins linked, still-running descendants in
// the kernel (so their future activity is captured) and returns the
// startup records to process, in order.
func (l *Loader) finishStartupJournal(rd recordReader, pump *journalPump, newSIDs map[uint64]bool,
	logf func(string, ...any)) ([][]byte, error) {
	if err := l.setJournal(false); err != nil {
		logf("warn: turn off startup journal: %v", err)
	}
	records, err := pump.stop(rd)
	tracked := l.coll.Maps["tracked_sessions"]
	lookup := func(tgid uint32) (uint64, bool) {
		var v [8]byte
		if tracked == nil || tracked.Lookup(&tgid, &v) != nil {
			return 0, false
		}
		return binary.LittleEndian.Uint64(v[:]), true
	}
	res := reconcileJournal(records, func(tgid uint32) (uint64, bool) {
		sid, ok := lookup(tgid)
		return sid, ok && newSIDs[sid]
	})
	joined := 0
	if tracked != nil && len(res.Joined) > 0 {
		l.mu.Lock()
		for tgid, sid := range res.Joined {
			if _, ok := lookup(tgid); ok {
				continue // the kernel or the late re-scan already has it
			}
			if _, err := os.Stat("/proc/" + itoa(tgid)); err != nil {
				continue // exited: its recorded events are kept, nothing to track
			}
			var v [8]byte
			binary.LittleEndian.PutUint64(v[:], sid)
			if tracked.Update(&tgid, &v, ebpf.UpdateNoExist) == nil {
				l.adopted[tgid] = sid
				joined++
			}
		}
		l.mu.Unlock()
		// Processes those just-joined ones forked after the journal went
		// off but before they were tracked: same re-scan as adoption.
		l.mu.Lock()
		joined += adoptLateChildren(scanProc, lookup, func(tgid uint32, sid uint64) bool {
			var v [8]byte
			binary.LittleEndian.PutUint64(v[:], sid)
			if tracked.Update(&tgid, &v, ebpf.UpdateNoExist) != nil {
				return false
			}
			l.adopted[tgid] = sid
			return true
		}, newSIDs, adoptLatePasses)
		l.mu.Unlock()
	}
	logf("startup journal: %d records, %d kept for adopted sessions, %d discarded, %d processes joined via recorded forks",
		len(records), res.Relabeled, res.Dropped, joined)
	return res.Records, err
}

func itoa(v uint32) string {
	var b [10]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			return string(b[i:])
		}
	}
}
