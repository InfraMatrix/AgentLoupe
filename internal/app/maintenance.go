package app

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

// Periodic housekeeping: provisional expiry, stats surfacing, the /proc
// sweeper for stale tracked entries and REJECTED tombstones, and the
// long-lived file flush (io accounting only).

type flushKey struct {
	filePtr  uint64
	openTSNS uint64
}

type flushVal struct {
	read, write uint64
}

type statVal struct{ Emitted, Drops uint64 }

type agentCounters struct {
	TrackedFailed, SessionsFailed, FileInfoFailed, SyscallFailed, AllocFailed uint64
	ExecHookRuns, ExecOutOfScope                                              uint64
	ExecNoFile, ExecBinaryMiss, ExecLastDev, ExecLastIno                      uint64
	FilePendingStored, FilePendingMatched                                     uint64
}

func possibleCPUs() int {
	n, err := ebpf.PossibleCPU()
	if err != nil || n <= 0 {
		return 1
	}
	return n
}

func maintenance(ctx context.Context, l *Loader, proc *Processor, o Options, logf func(string, ...any), summarizer *SyscallSummarizer) {
	tick := time.Second
	if summarizer != nil && o.SyscallInterval > 0 && o.SyscallInterval < tick {
		tick = o.SyscallInterval
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	var lastStats, lastSweep, lastFlush, lastAdopt time.Time
	lastSyscall := time.Now()
	for {
		select {
		case <-ctx.Done():
			// Final stats snapshot on shutdown so dev runs always
			// report whether anything was dropped.
			printStats(l, logf)
			dumpSyscallCounts(l, logf)
			if n := proc.DroppedFiltered(); n > 0 {
				logf("filter: dropped %d file events via --drop-path-prefix", n)
			}
			return
		case now := <-ticker.C:
			proc.Expire()
			l.sampleTrackedCPU()
			if now.Sub(lastAdopt) >= 5*time.Second {
				lastAdopt = now
				if cfg := l.Rules(); cfg != nil {
					l.adoptRunning(cfg, logf)
				}
			}
			if o.StatsInterval > 0 && now.Sub(lastStats) >= o.StatsInterval {
				lastStats = now
				printStats(l, logf)
				dumpSyscallCounts(l, logf)
			}
			if summarizer != nil && o.SyscallInterval > 0 && now.Sub(lastSyscall) >= o.SyscallInterval {
				lastSyscall = now
				summarizer.EmitAll()
			}
			if now.Sub(lastSweep) >= 30*time.Second {
				lastSweep = now
				sweep(l, proc, logf)
			}
			if o.EnableIOAccounting && o.StatsInterval > 0 && now.Sub(lastFlush) >= o.StatsInterval {
				lastFlush = now
				flushLongLived(l, proc)
			}
		}
	}
}

func printStats(l *Loader, logf func(string, ...any)) {
	stats := l.coll.Maps["stats"]
	if stats == nil {
		return
	}
	names := map[uint32]string{}
	for t, n := range typeNames {
		names[uint32(t)] = n
	}
	for typ := uint32(1); typ < 13; typ++ {
		vals := make([]statVal, possibleCPUs())
		key := typ
		if err := stats.Lookup(&key, &vals); err != nil {
			continue
		}
		var emitted, drops uint64
		for _, v := range vals {
			emitted += v.Emitted
			drops += v.Drops
		}
		if emitted > 0 || drops > 0 {
			logf("stats: %-12s emitted=%d ringbuf_drops=%d", names[typ], emitted, drops)
		}
	}
	if cm := l.coll.Maps["counters"]; cm != nil {
		vals := make([]agentCounters, possibleCPUs())
		key := uint32(0)
		if err := cm.Lookup(&key, &vals); err == nil {
			var tot agentCounters
			for _, v := range vals {
				tot.TrackedFailed += v.TrackedFailed
				tot.SessionsFailed += v.SessionsFailed
				tot.FileInfoFailed += v.FileInfoFailed
				tot.SyscallFailed += v.SyscallFailed
				tot.AllocFailed += v.AllocFailed
				tot.ExecHookRuns += v.ExecHookRuns
				tot.ExecOutOfScope += v.ExecOutOfScope
				tot.ExecNoFile += v.ExecNoFile
				tot.ExecBinaryMiss += v.ExecBinaryMiss
				if v.ExecLastIno != 0 {
					tot.ExecLastDev = v.ExecLastDev
					tot.ExecLastIno = v.ExecLastIno
				}
				tot.FilePendingStored += v.FilePendingStored
				tot.FilePendingMatched += v.FilePendingMatched
			}
			if tot != (agentCounters{}) {
				logf("stats: MAP-FULL/LOST-VISIBILITY tracked_updates_failed=%d sessions_updates_failed=%d file_info_updates_failed=%d syscall_updates_failed=%d session_allocs_failed=%d exec_hook_runs=%d exec_out_of_scope=%d exec_no_file=%d exec_binary_miss=%d exec_last_dev=%#x exec_last_ino=%d file_pending_stored=%d file_pending_matched=%d",
					tot.TrackedFailed, tot.SessionsFailed, tot.FileInfoFailed, tot.SyscallFailed, tot.AllocFailed, tot.ExecHookRuns, tot.ExecOutOfScope, tot.ExecNoFile, tot.ExecBinaryMiss, tot.ExecLastDev, tot.ExecLastIno, tot.FilePendingStored, tot.FilePendingMatched)
			}
		}
	}
}

func sweep(l *Loader, proc *Processor, logf func(string, ...any)) {
	tracked := l.coll.Maps["tracked_sessions"]
	sessions := l.coll.Maps["sessions"]
	if tracked == nil || sessions == nil {
		return
	}
	referenced := map[uint64]bool{}
	var stale []uint32
	it := tracked.Iterate()
	var tgid uint32
	var sidVal [8]byte
	for it.Next(&tgid, &sidVal) {
		sid := binary.LittleEndian.Uint64(sidVal[:])
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", tgid)); err != nil {
			stale = append(stale, tgid)
			continue
		}
		referenced[sid] = true
	}
	for _, t := range stale {
		key := t
		_ = tracked.Delete(&key)
	}
	if len(stale) > 0 {
		logf("sweeper: removed %d stale tracked entries", len(stale))
	}
	// Retire REJECTED tombstones (and orphan session state) once no
	// tracked process references the session any more.
	sit := sessions.Iterate()
	var sid uint64
	var raw [88]byte
	var retire []uint64
	for sit.Next(&sid, &raw) {
		meta := decodeSessionInfo(raw)
		if !referenced[sid] && (meta.State == 3 || meta.State == 0) {
			retire = append(retire, sid)
		}
	}
	for _, s := range retire {
		key := s
		_ = sessions.Delete(&key)
		l.mu.Lock()
		delete(l.metaCache, s)
		delete(l.cpuCache, s)
		l.mu.Unlock()
		proc.Forget(s)
	}
	if len(retire) > 0 {
		logf("sweeper: retired %d unreferenced rejected/orphan sessions", len(retire))
	}
}

func flushLongLived(l *Loader, proc *Processor) {
	m := l.coll.Maps["file_infos"]
	if m == nil {
		return
	}
	it := m.Iterate()
	var filePtr uint64
	var raw [568]byte
	for it.Next(&filePtr, &raw) {
		sid := binary.LittleEndian.Uint64(raw[512:520])
		readB := binary.LittleEndian.Uint64(raw[520:528])
		writeB := binary.LittleEndian.Uint64(raw[528:536])
		openTS := binary.LittleEndian.Uint64(raw[536:544])
		key := flushKey{filePtr: filePtr, openTSNS: openTS}
		last := l.flushState[key]
		if readB == last.read && writeB == last.write && last != (flushVal{}) {
			continue
		}
		d := &Decoded{
			Type: 9, TsNS: monotonicNS(), SessionID: sid,
			Tgid: binary.LittleEndian.Uint32(raw[552:556]),
			Fields: map[string]any{
				"path":        cstr(raw[0:512]),
				"file_ptr":    fmt.Sprintf("%#x", filePtr),
				"read_bytes":  readB - last.read,
				"write_bytes": writeB - last.write,
				"read_total":  readB,
				"write_total": writeB,
				"path_src":    pathSrcNames[raw[564]],
				"partial":     true,
			},
		}
		l.flushState[key] = flushVal{read: readB, write: writeB}
		proc.Process(d)
	}
	// Drop flush state for files that have since closed.
	// (Entries are keyed by open time; closed files simply stop appearing.
	// A full reconciliation pass is unnecessary at dev scale.)
}
