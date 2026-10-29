package app

import (
	"encoding/binary"
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
	m := l.coll.Maps["syscall_counts"]
	if m == nil {
		return
	}
	type cnt struct {
		nr    uint32
		count uint64
	}
	bySession := map[uint64][]cnt{}
	it := m.Iterate()
	var key [16]byte
	var val uint64
	for it.Next(&key, &val) {
		sid := binary.LittleEndian.Uint64(key[0:8])
		nr := binary.LittleEndian.Uint32(key[8:12])
		bySession[sid] = append(bySession[sid], cnt{nr, val})
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
