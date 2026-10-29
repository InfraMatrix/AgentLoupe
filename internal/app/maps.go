package app

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
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
	l.nextSID = seed
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

func (l *Loader) setConfig(ioAccounting, syscallSummary, fileMutations bool) error {
	m := l.coll.Maps["config_map"]
	if m == nil {
		return fmt.Errorf("config_map missing from object")
	}
	key0 := uint32(0)
	val := make([]byte, 24)
	binary.LittleEndian.PutUint64(val[0:8], l.runID)
	// struct agentloupe_config: run_id, enable_syscall_summary,
	// enable_file_io_accounting, enable_file_mutations (header order).
	binary.LittleEndian.PutUint32(val[8:12], boolToU32(syscallSummary))
	binary.LittleEndian.PutUint32(val[12:16], boolToU32(ioAccounting))
	binary.LittleEndian.PutUint32(val[16:20], boolToU32(fileMutations))
	binary.LittleEndian.PutUint32(val[20:24], 0) // net_udp_only: set post-attach
	return m.Update(&key0, &val, ebpf.UpdateAny)
}

// setNetUDPOnly flips the enter_connect mode once attach results are
// known: true means the TCP fexit probes are live, so the syscall probe
// must emit SOCK_DGRAM only.
func (l *Loader) setNetUDPOnly(udpOnly bool) error {
	m := l.coll.Maps["config_map"]
	if m == nil {
		return fmt.Errorf("config_map missing from object")
	}
	key0 := uint32(0)
	val := make([]byte, 24)
	if err := m.Lookup(&key0, &val); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(val[20:24], boolToU32(udpOnly))
	return m.Update(&key0, &val, ebpf.UpdateAny)
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
	if binMap == nil || candMap == nil || cgMap == nil {
		return fmt.Errorf("rule maps missing from object")
	}
	wantBin := make(map[[16]byte][36]byte)
	wantCand := make(map[[16]byte][36]byte)
	wantCG := make(map[uint64][36]byte)

	for _, a := range cfg.Agents {
		ref := agentRefValue(a.Index, a.Name)
		m := a.Match
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
	logf("rules: %d binaries, %d interpreter candidates, %d cgroups",
		len(wantBin), len(wantCand), len(wantCG))
	return nil
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
func (l *Loader) adoptRunning(cfg *config.File, logf func(string, ...any)) {
	sessions := l.coll.Maps["sessions"]
	tracked := l.coll.Maps["tracked_sessions"]
	if sessions == nil || tracked == nil {
		return
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
		if err := sessions.Update(&key, &raw, ebpf.UpdateAny); err != nil {
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
	if adopted > 0 {
		logf("adoption scan: adopted %d already-running agent processes (with existing children)", adopted)
	}
}

func (l *Loader) allocSIDForAdoption() uint64 {
	sid := l.nextSID
	l.nextSID++
	if m := l.coll.Maps["session_counter"]; m != nil {
		key0 := uint32(0)
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, l.nextSID-1)
		_ = m.Update(&key0, &val, ebpf.UpdateAny)
	}
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
