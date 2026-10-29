package app

import (
	"fmt"
	"sort"
)

// SyscallName resolves a syscall number to a name for the build arch.
// Unknown numbers fall back to nr<N> so dumps never lose the key.
func SyscallName(nr uint32) string {
	if n, ok := syscallNames[nr]; ok {
		return n
	}
	return fmt.Sprintf("nr%d", nr)
}

// dumpSyscallCounts surfaces the kernel syscall_counts map (populated
// only with --enable-syscall-summary) in the periodic stats log.
func dumpSyscallCounts(l *Loader, logf func(string, ...any)) {
	if l == nil || l.coll == nil || l.coll.Maps["syscall_counts"] == nil {
		return
	}
	snap, err := snapshotSyscallCounts(l)
	if err != nil {
		return
	}
	type cnt struct {
		nr    uint32
		count uint64
	}
	bySessionNR := map[uint64]map[uint32]uint64{}
	for k, v := range snap {
		m, ok := bySessionNR[k.sid]
		if !ok {
			m = map[uint32]uint64{}
			bySessionNR[k.sid] = m
		}
		m[k.nr] += v // sum across TGIDs: the stderr dump stays per-session
	}
	bySession := map[uint64][]cnt{}
	for sid, m := range bySessionNR {
		for nr, v := range m {
			bySession[sid] = append(bySession[sid], cnt{nr, v})
		}
	}
	sids := make([]uint64, 0, len(bySession))
	for sid := range bySession {
		sids = append(sids, sid)
	}
	sort.Slice(sids, func(i, j int) bool { return sids[i] < sids[j] })
	for _, sid := range sids {
		counts := bySession[sid]
		sort.Slice(counts, func(i, j int) bool { return counts[i].count > counts[j].count })
		name := fmt.Sprintf("%d", sid)
		if meta, ok := l.LookupMeta(sid); ok && meta.AgentName != "" {
			name = meta.AgentName
		}
		shown := counts
		if len(shown) > 25 {
			shown = shown[:25]
		}
		parts := ""
		for i, c := range shown {
			if i > 0 {
				parts += " "
			}
			parts += fmt.Sprintf("%s=%d", SyscallName(c.nr), c.count)
		}
		logf("syscalls: session=%s total_kinds=%d top: %s", name, len(counts), parts)
	}
}
