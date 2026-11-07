package app

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/InfraMatrix/AgentLoupe/internal/config"
)

// ---- kernel ABI byte encodings (must mirror bpf/agentloupe.h) ----

func binaryKey(dev uint32, ino uint64) (key [16]byte) {
	binary.LittleEndian.PutUint32(key[0:4], dev)
	binary.LittleEndian.PutUint64(key[8:16], ino)
	return key
}

func agentRefValue(ruleID int, name string) (v [36]byte) {
	binary.LittleEndian.PutUint32(v[0:4], uint32(ruleID))
	copy(v[4:36], name)
	return v
}

// Linux dev_t handling. stat(2) returns st_dev in the glibc encoding;
// the kernel stores inode->i_sb->s_dev in the kernel encoding. Convert
// st_dev -> (major, minor) -> kernel dev_t. Getting this wrong makes
// every binary lookup silently miss, hence the startup self-test below.
func devMajorMinor(stDev uint64) (major, minor uint32) {
	major = uint32((stDev>>8)&0xfff) | uint32((stDev>>32)&0xfffff000)
	minor = uint32(stDev&0xff) | uint32((stDev>>12)&0xffffff00)
	return major, minor
}

func kernelDevT(major, minor uint32) uint32 {
	// Kernel dev_t (include/linux/kdev_t.h): MKDEV(ma, mi) packs the
	// major above MINORBITS=20. inode->i_sb->s_dev uses this encoding,
	// NOT the glibc st_dev layout decoded by devMajorMinor above.
	return (major << 20) | minor
}

func resolveBinaryID(path string) (key [16]byte, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return key, err
	}
	fi, err := os.Stat(abs) // follows symlinks: exec matches the target inode
	if err != nil {
		return key, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return key, fmt.Errorf("%s: no stat_t", path)
	}
	maj, min := devMajorMinor(uint64(st.Dev))
	return binaryKey(kernelDevT(maj, min), st.Ino), nil
}

// selfTestBinaryKey validates the dev_t conversion against ground truth
// from /proc/self/maps, whose device column the kernel prints as
// separate hex major:minor for the running executable's mappings.
func selfTestBinaryKey() (bool, string) {
	exe, err := os.Executable()
	if err != nil {
		return false, err.Error()
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	key, err := resolveBinaryID(exe)
	if err != nil {
		return false, err.Error()
	}
	wantIno := binary.LittleEndian.Uint64(key[8:16])
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return false, err.Error()
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[5] != exe {
			continue
		}
		// /proc/<pid>/maps columns: addr perms offset dev inode path
		devParts := strings.Split(fields[3], ":")
		if len(devParts) != 2 {
			continue
		}
		maj, e1 := strconv.ParseUint(devParts[0], 16, 32)
		min, e2 := strconv.ParseUint(devParts[1], 16, 32)
		ino, e3 := strconv.ParseUint(fields[4], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		if ino != wantIno {
			return false, fmt.Sprintf("inode mismatch: maps=%d stat=%d", ino, wantIno)
		}
		gotDev := binary.LittleEndian.Uint32(key[0:4])
		if want := kernelDevT(uint32(maj), uint32(min)); gotDev != want {
			return false, fmt.Sprintf("dev mismatch: maps makedev=%#x computed=%#x", want, gotDev)
		}
		return true, fmt.Sprintf("%s dev=%#x ino=%d", exe, gotDev, ino)
	}
	return false, "own executable not found in /proc/self/maps"
}

// cgroupIDForPath returns the ID bpf_get_current_cgroup_id() reports for
// a cgroup v2 directory: its kernfs inode number.
func cgroupIDForPath(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: no stat_t", path)
	}
	return st.Ino, nil
}

func cgroupV2Available() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// findCgroupDirsByToken scans cgroupfs for directories whose path contains
// the token (k8s pod UIDs appear with '-' replaced by '_' in cgroup names).
func findCgroupDirsByToken(token string) []string {
	variants := map[string]bool{
		token: true, strings.ReplaceAll(token, "-", "_"): true,
	}
	var found []string
	root := "/sys/fs/cgroup"
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for v := range variants {
			if v != "" && strings.Contains(rel, v) {
				found = append(found, path)
				break
			}
		}
		if strings.Count(rel, string(filepath.Separator)) > 6 {
			return filepath.SkipDir // pods live at bounded depth
		}
		return nil
	})
	return found
}

// ---- Loader: owns the collection's maps (never pinned) ----

type Loader struct {
	coll *ebpf.Collection
	cfg  *config.File

	mu        sync.Mutex
	runID     uint64
	nextSID   uint64
	metaCache map[uint64]SessionMeta
	cpuCache  map[uint64][2]uint64 // session -> {user_ms, sys_ms} last sample
	adopted   map[uint32]uint64    // tgid -> session adopted from /proc

	prevBinaryKeys    map[[16]byte]bool
	prevCandidateKeys map[[16]byte]bool
	prevCgroupKeys    map[uint64]bool
	prevCommKeys      map[[commKeyLen]byte]bool

	flushState map[flushKey]flushVal
}

type SessionMeta struct {
	State     uint32
	AgentID   uint32
	ParentSID uint64
	CgroupID  uint64
	Flags     uint32
	RootTGID  uint32
	AgentName string
	RootComm  string
}

func monotonicNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func newLoader(coll *ebpf.Collection) (*Loader, error) {
	l := &Loader{
		coll:       coll,
		metaCache:  make(map[uint64]SessionMeta),
		cpuCache:   make(map[uint64][2]uint64),
		adopted:    make(map[uint32]uint64),
		flushState: make(map[flushKey]flushVal),
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	l.runID = uint64(binary.LittleEndian.Uint32(rnd[:]))
	// Seed session counter: kernel allocates (run_id << 32) | counter.
	seed := (l.runID << 32) | 1
	l.nextSID = (l.runID << 32) | adoptSIDBit | 1 // adoption's own range
	key0 := uint32(0)
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, seed-1)
	if m := coll.Maps["session_counter"]; m != nil {
		if err := m.Update(&key0, &val, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("seed session_counter: %w", err)
		}
	}
	return l, nil
}

func (l *Loader) setConfig(ioAccounting, syscallSummary, fileMutations, fileRWEvents, netSendEvents bool) error {
	m := l.coll.Maps["config_map"]
	if m == nil {
		return fmt.Errorf("config_map missing from object")
	}
	key0 := uint32(0)
	val := make([]byte, configSize)
	binary.LittleEndian.PutUint64(val[0:8], l.runID)
	// struct agentloupe_config: run_id, enable_syscall_summary,
	// enable_file_io_accounting, enable_file_mutations, net_udp_only,
	// enable_file_rw_events, enable_net_send_events (header order).
	// 32 bytes, fully used since ABI v6 (slot 6 took the tail pad;
	// slice 4 reuses slot 6 for the hostname parser, unchanged in v7;
	// slice 5 reuses slot 6 for recv pairing, unchanged in v8).
	binary.LittleEndian.PutUint32(val[8:12], boolToU32(syscallSummary))
	binary.LittleEndian.PutUint32(val[12:16], boolToU32(ioAccounting))
	binary.LittleEndian.PutUint32(val[16:20], boolToU32(fileMutations))
	binary.LittleEndian.PutUint32(val[20:24], 0) // net_udp_only: set post-attach
	binary.LittleEndian.PutUint32(val[24:28], boolToU32(fileRWEvents))
	binary.LittleEndian.PutUint32(val[28:32], boolToU32(netSendEvents))
	// ABI v9: enable_comm_rules (set by populateRules), journal_untracked
	// (set around the startup adoption): both start off.
	binary.LittleEndian.PutUint32(val[32:36], 0)
	binary.LittleEndian.PutUint32(val[36:40], 0)
	return m.Update(&key0, &val, ebpf.UpdateAny)
}

// struct agentloupe_config: 40 bytes since ABI v9. Field offsets used by
// setConfigFlag.
const (
	configSize             = 40
	cfgOffNetUDPOnly       = 20
	cfgOffCommRules        = 32
	cfgOffJournalUntracked = 36
)

// setConfigFlag flips one u32 toggle in place (read-modify-write; the
// loader is the only writer).
func (l *Loader) setConfigFlag(off int, on bool) error {
	m := l.coll.Maps["config_map"]
	if m == nil {
		return fmt.Errorf("config_map missing from object")
	}
	key0 := uint32(0)
	val := make([]byte, configSize)
	if err := m.Lookup(&key0, &val); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(val[off:off+4], boolToU32(on))
	return m.Update(&key0, &val, ebpf.UpdateAny)
}

// setJournal turns the startup journal on or off: while on, the kernel
// emits out-of-scope forks/execs as EVENT_F_JOURNAL records.
func (l *Loader) setJournal(on bool) error { return l.setConfigFlag(cfgOffJournalUntracked, on) }

// setNetUDPOnly flips the enter_connect mode once attach results are
// known: true means the TCP fexit probes are live, so the syscall probe
// must emit SOCK_DGRAM only.
func (l *Loader) setNetUDPOnly(udpOnly bool) error {
	return l.setConfigFlag(cfgOffNetUDPOnly, udpOnly)
}

func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// SetConfig swaps the active rule set (live reload). Rules() is the
// SessionControl view used by the event processor.
func (l *Loader) SetConfig(cfg *config.File) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cfg = cfg
}
func (l *Loader) Rules() *config.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cfg
}

// populateRules (re)resolves the config into agent_binaries / candidates /
// agent_cgroups, deleting keys that disappeared since the last call so
// live reload and binary upgrades take effect in place.
func (l *Loader) populateRules(cfg *config.File, logf func(string, ...any)) error {
	binMap := l.coll.Maps["agent_binaries"]
	candMap := l.coll.Maps["candidates"]
	cgMap := l.coll.Maps["agent_cgroups"]
	commMap := l.coll.Maps["agent_comms"]
	if binMap == nil || candMap == nil || cgMap == nil || commMap == nil {
		return fmt.Errorf("rule maps missing from object")
	}
	wantBin := make(map[[16]byte][36]byte)
	wantCand := make(map[[16]byte][36]byte)
	wantCG := make(map[uint64][36]byte)
	wantComm := make(map[[commKeyLen]byte][36]byte)

	for _, a := range cfg.Agents {
		ref := agentRefValue(a.Index, a.Name)
		m := a.Match
		// --attach-comm / --attach-exe: decided in the kernel at exec
		// (agent_comms / agent_binaries), not only by the /proc scans.
		switch m.K8SLabel {
		case "__attach_comm__":
			if key, ok := commKey(m.Cgroup); ok {
				wantComm[key] = ref
			} else {
				logf("warn: --attach-comm %q: longer than %d characters, matched by the periodic /proc scan only", m.Cgroup, commKeyMaxName)
			}
			continue
		case "__attach_exe__":
			paths, capped := expandExeGlob(m.Cgroup)
			if capped {
				logf("warn: --attach-exe %q matches more than %d files; only the first %d are matched at exec (the rest by the periodic /proc scan)", m.Cgroup, maxExeGlobMatches, maxExeGlobMatches)
			}
			for _, p := range paths {
				if key, err := resolveBinaryID(p); err == nil {
					wantBin[key] = ref
				}
			}
			continue
		case "__attach_pid__":
			continue // an existing process: the /proc scan is the right tool
		}
		if m.ExecPath != "" {
			key, err := resolveBinaryID(m.ExecPath)
			if err != nil {
				logf("warn: agent %q exec_path %s: %v (rule inactive)", a.Name, m.ExecPath, err)
			} else {
				wantBin[key] = ref
			}
		}
		if m.Interpreter != "" {
			key, err := resolveBinaryID(m.Interpreter)
			if err != nil {
				logf("warn: agent %q interpreter %s: %v (rule inactive)", a.Name, m.Interpreter, err)
			} else {
				wantCand[key] = ref
			}
		}
		cgroupPaths := []string{}
		if m.Cgroup != "" {
			p := m.Cgroup
			if !filepath.IsAbs(p) {
				p = filepath.Join("/sys/fs/cgroup", p)
			}
			cgroupPaths = append(cgroupPaths, p)
		}
		if m.K8SLabel != "" && !strings.HasPrefix(m.K8SLabel, "__attach_") {
			token := m.K8SLabel
			if i := strings.Index(token, "="); i >= 0 {
				token = token[i+1:]
			}
			cgroupPaths = append(cgroupPaths, findCgroupDirsByToken(token)...)
		}
		for _, p := range cgroupPaths {
			id, err := cgroupIDForPath(p)
			if err != nil {
				logf("warn: agent %q cgroup %s: %v (rule inactive)", a.Name, p, err)
				continue
			}
			wantCG[id] = ref
		}
	}

	apply := func(m *ebpf.Map, want map[[16]byte][36]byte, prev map[[16]byte]bool) map[[16]byte]bool {
		next := make(map[[16]byte]bool)
		for k := range prev {
			if _, ok := want[k]; !ok {
				key := k
				_ = m.Delete(&key)
			}
		}
		for k, v := range want {
			key, val := k, v
			if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
				logf("warn: rule map update: %v", err)
			}
			next[k] = true
		}
		return next
	}
	applyCG := func(want map[uint64][36]byte, prev map[uint64]bool) map[uint64]bool {
		next := make(map[uint64]bool)
		for k := range prev {
			if _, ok := want[k]; !ok {
				key := k
				_ = cgMap.Delete(&key)
			}
		}
		for k, v := range want {
			key, val := k, v
			if err := cgMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
				logf("warn: cgroup map update: %v", err)
			}
			next[k] = true
		}
		return next
	}

	l.prevBinaryKeys = apply(binMap, wantBin, l.prevBinaryKeys)
	l.prevCandidateKeys = apply(candMap, wantCand, l.prevCandidateKeys)
	l.prevCgroupKeys = applyCG(wantCG, l.prevCgroupKeys)
	next := make(map[[commKeyLen]byte]bool)
	for k := range l.prevCommKeys {
		if _, ok := wantComm[k]; !ok {
			key := k
			_ = commMap.Delete(&key)
		}
	}
	for k, v := range wantComm {
		key, val := k, v
		if err := commMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			logf("warn: comm rule map update: %v", err)
			continue
		}
		next[k] = true
	}
	l.prevCommKeys = next
	// Gate the per-exec name lookup: zero cost unless --attach-comm is used.
	if err := l.setConfigFlag(cfgOffCommRules, len(next) > 0); err != nil {
		logf("warn: set enable_comm_rules: %v", err)
	}
	logf("rules: %d binaries, %d interpreter candidates, %d cgroups, %d process names",
		len(wantBin), len(wantCand), len(wantCG), len(next))
	return nil
}

// struct comm_key (ABI v9): a NUL-padded name. The kernel matches it
// against the task comm (<= 15 chars) and the exe's file name; it only
// matches file names it can read whole, i.e. <= commKeyMaxName chars.
const (
	commKeyLen     = 32
	commKeyMaxName = commKeyLen - 2
)

func commKey(name string) ([commKeyLen]byte, bool) {
	var k [commKeyLen]byte
	if name == "" || len(name) > commKeyMaxName {
		return k, false
	}
	copy(k[:], name)
	return k, true
}

// maxExeGlobMatches caps one --attach-exe pattern's kernel entries
// (agent_binaries holds MAX_AGENT_BINARIES = 1024 for all rules): an
// over-broad glob must not fill the map or scope half the system.
const maxExeGlobMatches = 256

// expandExeGlob returns the regular, executable files a pattern matches
// now (sorted, capped). Re-run on config reload and when a watched
// directory changes, so binaries installed later are picked up.
func expandExeGlob(pattern string) (paths []string, capped bool) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, false
	}
	sort.Strings(matches)
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			continue
		}
		if len(paths) == maxExeGlobMatches {
			return paths, true
		}
		paths = append(paths, m)
	}
	return paths, false
}

// ---- session map access (raw 88-byte session_info) ----

func decodeSessionInfo(raw [88]byte) SessionMeta {
	name := raw[40:72]
	if i := indexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	comm := raw[72:88]
	if i := indexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	return SessionMeta{
		State:     binary.LittleEndian.Uint32(raw[0:4]),
		AgentID:   binary.LittleEndian.Uint32(raw[4:8]),
		ParentSID: binary.LittleEndian.Uint64(raw[8:16]),
		CgroupID:  binary.LittleEndian.Uint64(raw[16:24]),
		Flags:     binary.LittleEndian.Uint32(raw[32:36]),
		RootTGID:  binary.LittleEndian.Uint32(raw[36:40]),
		AgentName: string(name),
		RootComm:  string(comm),
	}
}

func indexByte(b []byte, target byte) int {
	for i, c := range b {
		if c == target {
			return i
		}
	}
	return -1
}

func (l *Loader) LookupMeta(sid uint64) (SessionMeta, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lookupMetaLocked(sid)
}

func (l *Loader) lookupMetaLocked(sid uint64) (SessionMeta, bool) {
	if m, ok := l.metaCache[sid]; ok {
		return m, true
	}
	m := l.coll.Maps["sessions"]
	if m == nil {
		return SessionMeta{}, false
	}
	var raw [88]byte
	if err := m.Lookup(&sid, &raw); err != nil {
		return SessionMeta{}, false
	}
	meta := decodeSessionInfo(raw)
	l.metaCache[sid] = meta
	return meta, true
}

func (l *Loader) mutateSession(sid uint64, fn func(raw *[88]byte)) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := l.coll.Maps["sessions"]
	if m == nil {
		return fmt.Errorf("sessions map missing")
	}
	var raw [88]byte
	if err := m.Lookup(&sid, &raw); err != nil {
		return err
	}
	fn(&raw)
	if err := m.Update(&sid, &raw, ebpf.UpdateAny); err != nil {
		return err
	}
	delete(l.metaCache, sid)
	return nil
}

// Confirm transitions a provisional session to CONFIRMED (single map
// update; the kernel enforces state from this point on).
func (l *Loader) Confirm(sid uint64, rule config.Agent) error {
	return l.mutateSession(sid, func(raw *[88]byte) {
		binary.LittleEndian.PutUint32(raw[0:4], 2) // CONFIRMED
		binary.LittleEndian.PutUint32(raw[4:8], uint32(rule.Index))
		flags := binary.LittleEndian.Uint32(raw[32:36])
		flags |= 16 // SESSION_F_INTERPRETER; state field is authoritative
		binary.LittleEndian.PutUint32(raw[32:36], flags)
		for i := 40; i < 72; i++ {
			raw[i] = 0
		}
		copy(raw[40:72], rule.Name)
	})
}

// Reject tombstones a provisional session. One write: fork stops
// propagating it and every probe treats it as out of scope immediately.
// Timeout with no decision goes through this same path.
func (l *Loader) Reject(sid uint64) error {
	return l.mutateSession(sid, func(raw *[88]byte) {
		binary.LittleEndian.PutUint32(raw[0:4], 3) // REJECTED
	})
}

// ---- CPU sampling (/proc/<tgid>/stat) ----

// parseProcStat extracts (utime+cutime, stime+cstime) in milliseconds.
// /proc stat fields 14-17 are in USER_HZ ticks; USER_HZ is fixed at 100
// by the kernel ABI regardless of CONFIG_HZ.
func parseProcStat(data []byte) (userMS, sysMS uint64, ok bool) {
	// comm (field 2) is parenthesised and may contain spaces/parens.
	i := -1
	for j := len(data) - 1; j >= 0; j-- {
		if data[j] == ')' {
			i = j
			break
		}
	}
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(string(data[i+1:]))
	// f[0] is field 3 (state); utime=14 -> f[11], stime=15 -> f[12],
	// cutime=16 -> f[13], cstime=17 -> f[14].
	if len(f) < 15 {
		return 0, 0, false
	}
	parse := func(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }
	userTicks := parse(f[11]) + parse(f[13])
	sysTicks := parse(f[12]) + parse(f[14])
	return userTicks * 10, sysTicks * 10, true
}

// SessionCPU returns the last sampled CPU for a session root (the process
// is gone by the time its exit event is processed, so last-sample-wins).
func (l *Loader) SessionCPU(sid uint64) (uint64, uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.cpuCache[sid]
	return v[0], v[1], ok
}

func (l *Loader) sampleTrackedCPU() {
	tracked := l.coll.Maps["tracked_sessions"]
	if tracked == nil {
		return
	}
	type pair struct {
		tgid uint32
		sid  uint64
	}
	var pairs []pair
	it := tracked.Iterate()
	var tgid uint32
	var sidVal [8]byte
	for it.Next(&tgid, &sidVal) {
		pairs = append(pairs, pair{tgid, binary.LittleEndian.Uint64(sidVal[:])})
	}
	for _, pr := range pairs {
		meta, ok := l.LookupMeta(pr.sid)
		if !ok || meta.RootTGID != pr.tgid {
			continue // root processes only
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pr.tgid))
		if err != nil {
			continue
		}
		if u, s, ok := parseProcStat(data); ok {
			l.mu.Lock()
			l.cpuCache[pr.sid] = [2]uint64{u, s}
			l.mu.Unlock()
		}
	}
}

// ---- /proc adoption: startup + periodic, whole process trees ----

type procEntry struct {
	PID, PPID int
	Exe       string
	Cmdline   string
	Comm      string
	CgPath    string
	CgID      uint64
}

func readProcEntry(pid int) (procEntry, bool) {
	e := procEntry{PID: pid}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return e, false
	}
	if i := strings.LastIndex(string(data), ")"); i >= 0 {
		f := strings.Fields(string(data)[i+1:])
		if len(f) >= 2 {
			e.PPID, _ = strconv.Atoi(f[1]) // f[0]=state, f[1]=ppid
		}
	}
	e.Exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		e.Cmdline = strings.ReplaceAll(string(b), "\x00", " ")
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		e.Comm = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if parts := strings.SplitN(line, ":", 3); len(parts) == 3 && parts[1] == "" {
				e.CgPath = parts[2]
			}
		}
	}
	if e.CgPath != "" {
		if id, err := cgroupIDForPath(filepath.Join("/sys/fs/cgroup", e.CgPath)); err == nil {
			e.CgID = id
		}
	}
	return e, true
}

func scanProc() []procEntry {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var out []procEntry
	for _, en := range entries {
		pid, err := strconv.Atoi(en.Name())
		if err != nil || pid == self {
			continue
		}
		if e, ok := readProcEntry(pid); ok {
			out = append(out, e)
		}
	}
	return out
}

func matchProcEntry(cfg *config.File, e procEntry) (config.Agent, bool) {
	for _, a := range cfg.Agents {
		m := a.Match
		if m.ExecPath != "" && e.Exe != "" {
			if rp, err := filepath.EvalSymlinks(m.ExecPath); err == nil && rp == e.Exe {
				return a, true
			}
		}
		if m.Interpreter != "" && m.ArgvContains != "" && e.Exe != "" {
			if rp, err := filepath.EvalSymlinks(m.Interpreter); err == nil && rp == e.Exe &&
				strings.Contains(e.Cmdline, m.ArgvContains) {
				return a, true
			}
		}
		if m.Cgroup != "" && e.CgPath != "" {
			want := m.Cgroup
			if !strings.HasPrefix(want, "/") {
				want = "/" + want
			}
			if e.CgPath == want || strings.HasPrefix(e.CgPath, want+"/") {
				return a, true
			}
		}
		// Ad-hoc / catalog synthetic rules (not expressible in YAML):
		if m.K8SLabel == "__attach_pid__" && m.Cgroup == fmt.Sprintf("%d", e.PID) {
			return a, true
		}
		if m.K8SLabel == "__attach_comm__" && (e.Comm == m.Cgroup || baseName(e.Exe) == m.Cgroup) {
			return a, true
		}
		if m.K8SLabel == "__attach_exe__" {
			if ok, _ := filepath.Match(m.Cgroup, e.Exe); ok {
				return a, true
			}
		}
	}
	return config.Agent{}, false
}

// adoptRunning attaches already-running agents AND their existing
// descendants. Safe to call periodically: inserts use UpdateNoExist and
// a lost race deletes the just-created session rather than orphaning a
// kernel-created one.
//
// Returns the sessions this call created (the startup journal extends
// exactly these).
func (l *Loader) adoptRunning(cfg *config.File, logf func(string, ...any)) map[uint64]bool {
	sessions := l.coll.Maps["sessions"]
	tracked := l.coll.Maps["tracked_sessions"]
	if sessions == nil || tracked == nil {
		return nil
	}
	snap := scanProc()
	alive := map[int]bool{}
	children := map[int][]int{}
	for _, e := range snap {
		alive[e.PID] = true
		children[e.PPID] = append(children[e.PPID], e.PID)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.adopted == nil {
		l.adopted = make(map[uint32]uint64)
	}
	for tgid := range l.adopted {
		if !alive[int(tgid)] {
			delete(l.adopted, tgid)
		}
	}
	adopted := 0
	newSIDs := map[uint64]bool{} // sessions created by this call
	for _, e := range snap {
		rule, ok := matchProcEntry(cfg, e)
		if !ok {
			continue
		}
		tgid := uint32(e.PID)
		if _, done := l.adopted[tgid]; done {
			continue
		}
		var existing [8]byte
		if err := tracked.Lookup(&tgid, &existing); err == nil {
			l.adopted[tgid] = binary.LittleEndian.Uint64(existing[:])
			continue
		}
		sid := l.allocSIDForAdoption()
		raw := makeSessionInfo(2, uint32(rule.Index), 8 /*SESSION_F_FROM_PROC*/, tgid, 0, e.CgID, rule.Name, e.Comm)
		key := sid
		// NoExist: adoption ids live in their own range, so this never
		// collides with a kernel session; if it ever did, skip rather
		// than overwrite a live session.
		if err := sessions.Update(&key, &raw, ebpf.UpdateNoExist); err != nil {
			continue
		}
		var sidVal [8]byte
		binary.LittleEndian.PutUint64(sidVal[:], sid)
		if err := tracked.Update(&tgid, &sidVal, ebpf.UpdateNoExist); err != nil {
			_ = sessions.Delete(&key) // kernel-created session won the race
			continue
		}
		delete(l.metaCache, sid)
		l.adopted[tgid] = sid
		newSIDs[sid] = true
		adopted++
		// BFS: pre-existing descendants join the root's session.
		queue := append([]int{}, children[e.PID]...)
		for len(queue) > 0 {
			child := queue[0]
			queue = queue[1:]
			queue = append(queue, children[child]...)
			ct := uint32(child)
			if _, done := l.adopted[ct]; done {
				continue
			}
			if err := tracked.Lookup(&ct, &existing); err == nil {
				l.adopted[ct] = binary.LittleEndian.Uint64(existing[:])
				continue
			}
			if err := tracked.Update(&ct, &sidVal, ebpf.UpdateNoExist); err == nil {
				l.adopted[ct] = sid
			}
		}
	}
	late := 0
	if len(newSIDs) > 0 {
		// Children forked after the snapshot but before their parent was
		// inserted: the fork hook saw an untracked parent and the
		// snapshot predates them. Re-scan until a pass finds none.
		late = adoptLateChildren(scanProc,
			func(tgid uint32) (uint64, bool) {
				var v [8]byte
				if err := tracked.Lookup(&tgid, &v); err != nil {
					return 0, false
				}
				return binary.LittleEndian.Uint64(v[:]), true
			},
			func(tgid uint32, sid uint64) bool {
				var v [8]byte
				binary.LittleEndian.PutUint64(v[:], sid)
				if tracked.Update(&tgid, &v, ebpf.UpdateNoExist) != nil {
					return false
				}
				l.adopted[tgid] = sid
				return true
			},
			newSIDs, adoptLatePasses)
	}
	if adopted > 0 {
		logf("adoption scan: adopted %d already-running agent processes (with existing children; %d forked during the scan)", adopted, late)
	}
	return newSIDs
}

// adoptLatePasses bounds the re-scans; each pass only has to catch forks
// that happened during the previous one, so a few always suffice in
// practice (a fork storm faster than a /proc scan is the only way to
// need more, and those forks are caught by the kernel once their parent
// is tracked).
const adoptLatePasses = 8

// adoptLateChildren closes the fork race of an adoption scan. Once a
// process is in tracked_sessions the kernel fork hook propagates its
// session to every later child; a child forked BEFORE that insert (but
// after the /proc snapshot) is invisible to both. Such children still
// exist in /proc, so: scan, and add every untracked process whose parent
// is tracked in a session this adoption created; repeat until a pass
// adds nothing. Only sessions created by this adoption are extended:
// kernel-created sessions are the fork hook's job (and REJECTED ones
// must not grow). Returns the number of processes added.
//
// Residual gap: a child that forked and exited during the window leaves
// its own children re-parented away from the session (double-fork
// daemonisation inside one scan); they are not found.
func adoptLateChildren(scan func() []procEntry, lookup func(uint32) (uint64, bool),
	insert func(uint32, uint64) bool, newSIDs map[uint64]bool, maxPasses int) int {
	total := 0
	for pass := 0; pass < maxPasses; pass++ {
		added := 0
		for _, e := range scan() {
			child := uint32(e.PID)
			if _, ok := lookup(child); ok {
				continue
			}
			psid, ok := lookup(uint32(e.PPID))
			if !ok || !newSIDs[psid] {
				continue
			}
			if insert(child, psid) {
				added++
			}
		}
		total += added
		if added == 0 {
			break
		}
	}
	return total
}

// adoptSIDBit splits the per-run id space: the kernel allocates
// (run_id << 32) | n with an atomic counter, adoption allocates
// (run_id << 32) | adoptSIDBit | n from its own counter. Adoption runs
// while hooks are live, so sharing the kernel counter from userspace
// (which cannot fetch-and-add on it) could hand out an id the kernel
// already used; disjoint ranges make that impossible.
const adoptSIDBit = uint64(1) << 31

func (l *Loader) allocSIDForAdoption() uint64 {
	sid := l.nextSID
	l.nextSID++
	return sid
}

func makeSessionInfo(state, agentID, flags, rootTGID uint32, parent, cgid uint64, name, comm string) (raw [88]byte) {
	binary.LittleEndian.PutUint32(raw[0:4], state)
	binary.LittleEndian.PutUint32(raw[4:8], agentID)
	binary.LittleEndian.PutUint64(raw[8:16], parent)
	binary.LittleEndian.PutUint64(raw[16:24], cgid)
	binary.LittleEndian.PutUint64(raw[24:32], monotonicNS())
	binary.LittleEndian.PutUint32(raw[32:36], flags)
	binary.LittleEndian.PutUint32(raw[36:40], rootTGID)
	copy(raw[40:72], name)
	copy(raw[72:88], comm)
	return raw
}

var _ = time.Now
