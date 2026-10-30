package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/InfraMatrix/AgentLoupe/internal/config"
)

// Event type numbers mirror enum event_type in bpf/agentloupe.h.
var typeNames = map[uint16]string{
	1: "exec", 2: "fork", 3: "exit", 4: "file_open", 5: "file_unlink",
	6: "file_rename", 7: "file_chmod", 8: "file_close", 9: "file_io",
	10: "net_connect", 11: "session_start", 12: "session_end",
}

var pathSrcNames = map[uint8]string{
	0: "none", 1: "d_path", 2: "dentry_walk", 3: "raw_arg",
}

type Decoded struct {
	Type        uint16
	Flags       uint16
	TsNS        uint64
	SessionID   uint64
	ParentSID   uint64
	Tgid        uint32
	PIDInNS     uint32
	PPID        uint32
	UID         uint32
	Comm        string
	Fields      map[string]any
	Provisional bool
}

func cstr(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func parseArgv(b []byte) []string {
	var out []string
	for _, part := range strings.Split(string(b), "\x00") {
		if part == "" {
			break
		}
		out = append(out, part)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// Decode parses one ring-buffer record: event_hdr (72 B) + payload.
// Malformed records are an error the caller counts; never a panic.
func Decode(raw []byte) (*Decoded, error) {
	if len(raw) < 72 {
		return nil, fmt.Errorf("short record: %d bytes", len(raw))
	}
	d := &Decoded{
		Type:      binary.LittleEndian.Uint16(raw[0:2]),
		Flags:     binary.LittleEndian.Uint16(raw[6:8]),
		TsNS:      binary.LittleEndian.Uint64(raw[8:16]),
		SessionID: binary.LittleEndian.Uint64(raw[16:24]),
		ParentSID: binary.LittleEndian.Uint64(raw[24:32]),
		Tgid:      binary.LittleEndian.Uint32(raw[40:44]),
		PIDInNS:   binary.LittleEndian.Uint32(raw[44:48]),
		PPID:      binary.LittleEndian.Uint32(raw[48:52]),
		UID:       binary.LittleEndian.Uint32(raw[52:56]),
		Comm:      cstr(raw[56:72]),
		Fields:    map[string]any{},
	}
	size := int(binary.LittleEndian.Uint16(raw[2:4]))
	version := binary.LittleEndian.Uint16(raw[4:6])
	if version != 4 {
		return nil, fmt.Errorf("abi version %d, want 4", version)
	}
	if size < 72 || size > len(raw) {
		return nil, fmt.Errorf("bad record size %d (have %d)", size, len(raw))
	}
	d.Provisional = d.Flags&2 != 0
	p := raw[72:size]
	need := func(n int) bool { return len(p) >= n }

	switch d.Type {
	case 1: // exec: filename[512] cwd[512] argv[512] ...
		if !need(1560) {
			return nil, fmt.Errorf("exec payload %d bytes", len(p))
		}
		d.Fields["filename"] = cstr(p[0:512])
		d.Fields["cwd"] = cstr(p[512:1024])
		d.Fields["argv"] = parseArgv(p[1024:1536])
		// Kernel leaves argv argc (p[1536:1540]) at 0 — counting is done
		// here, exactly, from the parsed argv.
		if argv, ok := d.Fields["argv"].([]string); ok {
			d.Fields["argc"] = len(argv)
		} else {
			d.Fields["argc"] = 0
		}
		loginuid := binary.LittleEndian.Uint32(p[1540:1544])
		if loginuid != 4294967295 {
			d.Fields["loginuid"] = loginuid
		} // else: unset — JSON falls back to common "uid" field
		d.Fields["filename_src"] = pathSrcNames[p[1552]]
		d.Fields["cwd_src"] = pathSrcNames[p[1553]]
	case 2: // fork
		if !need(8) {
			return nil, fmt.Errorf("fork payload short")
		}
		d.Fields["child_pid"] = binary.LittleEndian.Uint32(p[0:4]) // host TGID
		d.Fields["child_pid_in_ns"] = binary.LittleEndian.Uint32(p[4:8])
	case 3: // exit: exit_code + thread-group CPU (ns) + peak RSS (KiB)
		if !need(32) {
			return nil, fmt.Errorf("exit payload short")
		}
		d.Fields["exit_code"] = int32(binary.LittleEndian.Uint32(p[0:4]))
		// Kernel reports nanoseconds; JSONL carries milliseconds
		// (floor), matching the session_end cpu_*_ms fields.
		d.Fields["cpu_user_ms"] = binary.LittleEndian.Uint64(p[8:16]) / 1_000_000
		d.Fields["cpu_sys_ms"] = binary.LittleEndian.Uint64(p[16:24]) / 1_000_000
		d.Fields["max_rss_kb"] = binary.LittleEndian.Uint64(p[24:32])
	case 4: // file_open
		if !need(536) {
			return nil, fmt.Errorf("file_open payload short")
		}
		d.Fields["path"] = cstr(p[0:512])
		d.Fields["file_ptr"] = fmt.Sprintf("%#x", binary.LittleEndian.Uint64(p[512:520]))
		d.Fields["open_flags"] = binary.LittleEndian.Uint32(p[520:524])
		d.Fields["result"] = int32(binary.LittleEndian.Uint32(p[524:528]))
		d.Fields["path_src"] = pathSrcNames[p[528]]
	case 5: // unlink
		if !need(520) {
			return nil, fmt.Errorf("unlink payload short")
		}
		d.Fields["path"] = cstr(p[0:512])
		d.Fields["result"] = int32(binary.LittleEndian.Uint32(p[512:516]))
		d.Fields["path_src"] = pathSrcNames[p[516]]
	case 6: // rename
		if !need(1032) {
			return nil, fmt.Errorf("rename payload short")
		}
		d.Fields["old_path"] = cstr(p[0:512])
		d.Fields["new_path"] = cstr(p[512:1024])
		d.Fields["result"] = int32(binary.LittleEndian.Uint32(p[1024:1028]))
		d.Fields["old_path_src"] = pathSrcNames[p[1028]]
		d.Fields["new_path_src"] = pathSrcNames[p[1029]]
	case 7: // chmod
		if !need(528) {
			return nil, fmt.Errorf("chmod payload short")
		}
		d.Fields["path"] = cstr(p[0:512])
		d.Fields["mode"] = fmt.Sprintf("%#o", binary.LittleEndian.Uint32(p[512:516]))
		d.Fields["result"] = int32(binary.LittleEndian.Uint32(p[516:520]))
		d.Fields["path_src"] = pathSrcNames[p[520]]
	case 8, 9: // file_close / file_io (flush)
		if !need(552) {
			return nil, fmt.Errorf("file_close payload short")
		}
		d.Fields["path"] = cstr(p[0:512])
		d.Fields["file_ptr"] = fmt.Sprintf("%#x", binary.LittleEndian.Uint64(p[512:520]))
		d.Fields["read_bytes"] = binary.LittleEndian.Uint64(p[520:528])
		d.Fields["write_bytes"] = binary.LittleEndian.Uint64(p[528:536])
		if openTS := binary.LittleEndian.Uint64(p[536:544]); openTS > 0 && d.TsNS >= openTS {
			d.Fields["duration_ms"] = (d.TsNS - openTS) / 1_000_000
		}
		d.Fields["path_src"] = pathSrcNames[p[544]]
		if d.Type == 9 {
			d.Fields["partial"] = true
		}
	case 10: // net_connect
		if !need(48) {
			return nil, fmt.Errorf("net payload short")
		}
		family := binary.LittleEndian.Uint16(p[36:38])
		d.Fields["family"] = family
		d.Fields["dport"] = binary.LittleEndian.Uint16(p[32:34])
		d.Fields["sport"] = binary.LittleEndian.Uint16(p[34:36])
		d.Fields["protocol"] = p[38]
		if p[39]&1 != 0 {
			d.Fields["dns"] = true
		}
		d.Fields["result"] = int32(binary.LittleEndian.Uint32(p[40:44]))
		if family == 2 {
			d.Fields["daddr"] = net.IP(p[0:4]).String()
			d.Fields["saddr"] = net.IP(p[16:20]).String()
		} else {
			d.Fields["daddr"] = net.IP(p[0:16]).String()
			d.Fields["saddr"] = net.IP(p[16:32]).String()
		}
	}
	if d.Flags&1 != 0 {
		d.Fields["truncated"] = true
	}
	if d.Flags&16 != 0 {
		d.Fields["path_partial"] = true
	}
	return d, nil
}

// ---- JSONL output ----

type Output struct {
	Ts              string         `json:"ts"`
	Type            string         `json:"type"`
	SessionID       uint64         `json:"session_id"`
	ParentSessionID uint64         `json:"parent_session_id"`
	AgentName       string         `json:"agent_name"`
	PID             uint32         `json:"pid"`
	PIDInNS         uint32         `json:"pid_in_ns"`
	PPID            uint32         `json:"ppid"`
	UID             uint32         `json:"uid"`
	Comm            string         `json:"comm"`
	Provisional     bool           `json:"provisional,omitempty"`
	Fields          map[string]any `json:"-"`
}

func (o Output) MarshalJSON() ([]byte, error) {
	type Alias Output
	m := map[string]any{}
	base, err := json.Marshal(Alias(o))
	if err != nil {
		return nil, err
	}
	// UseNumber: session_id is (run_id<<32)|counter and exceeds 2^53, so
	// decoding into float64 would silently round it and the JSONL session
	// IDs would no longer match the kernel's (or each other's exact value
	// when compared against map keys).
	dec := json.NewDecoder(bytes.NewReader(base))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	for k, v := range o.Fields {
		m[k] = v
	}
	return json.Marshal(m)
}

type SessionControl interface {
	LookupMeta(sid uint64) (SessionMeta, bool)
	Confirm(sid uint64, rule config.Agent) error
	Reject(sid uint64) error
	Rules() *config.File
}

const provisionalTimeout = 2 * time.Second
const provisionalMaxBuffered = 1024

type pendingSession struct {
	deadline time.Time
	buffered []*Decoded
}

// liveSession tracks which TGIDs of a session have been seen and not
// yet exited. A session ends when its root has exited AND this set is
// empty ("all_exited"), or when the orphan timeout expires with
// processes still in the set ("orphan_timeout"). exited remembers
// TGIDs whose exit was already processed: teardown events for them
// (file_close from deferred file freeing arrives after the exit event)
// must not resurrect them into the alive set.
type liveSession struct {
	alive      map[uint32]bool
	exited     map[uint32]bool
	rootExited bool
	rootExitAt time.Time // processing time of the root exit (timeout clock)
	ended      bool
}

// Processor owns output ordering, provisional buffering and session
// start/end synthesis. Buffering is userspace-side and bounded; on
// reject or timeout the buffer is discarded and the kernel session is
// tombstoned REJECTED via the SessionControl.
type Processor struct {
	mu       sync.Mutex
	ctrl     SessionControl
	write    func(Output) error
	wallBase time.Time // wall clock corresponding to monotonic 0
	pending  map[uint64]*pendingSession
	live     map[uint64]*liveSession
	decided  map[uint64]bool // session -> confirmed(true)/rejected(false)
	started  map[uint64]bool
	// startedMu guards only `started` (and seenCount), separately from
	// mu: the syscall summarizer checks HasStarted while holding its
	// own lock and runs under mu via BeforeSessionEnd, so HasStarted
	// must not take mu.
	startedMu       sync.RWMutex
	seenCount       uint64 // sessions that have ever emitted session_start
	droppedBuf      int
	DropPrefixes    []string // file paths with any of these prefixes are dropped
	droppedFiltered int
	// BeforeSessionEnd, if set, runs (synchronously, before the
	// session_end line is written) when a session actually ends: its
	// root has exited and its last tracked process has exited, or the
	// orphan timeout expired. Used to flush a final syscall_summary
	// for the session. The hook must write via the same writer
	// directly; it runs under p.mu.
	BeforeSessionEnd func(sid uint64)
	// ForgetHook, if set, runs when Forget drops local session state.
	ForgetHook func(sid uint64)
	// OrphanTimeout bounds how long a session stays open after its
	// root exits while tracked processes remain alive. On expiry the
	// session ends with reason "orphan_timeout". Zero means wait
	// indefinitely. Set by Run from Options; the zero value of a bare
	// Processor is indefinite.
	OrphanTimeout time.Duration
}

// DroppedFiltered reports how many events --drop-path-prefix suppressed.
func (p *Processor) DroppedFiltered() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.droppedFiltered
}

func (p *Processor) shouldDrop(d *Decoded) bool {
	if len(p.DropPrefixes) == 0 {
		return false
	}
	var paths []string
	switch d.Type {
	case 4, 5, 7, 8, 9:
		if s, ok := d.Fields["path"].(string); ok {
			paths = append(paths, s)
		}
	case 6:
		for _, k := range []string{"old_path", "new_path"} {
			if s, ok := d.Fields[k].(string); ok {
				paths = append(paths, s)
			}
		}
	default:
		return false
	}
	for _, path := range paths {
		for _, pre := range p.DropPrefixes {
			if pre != "" && strings.HasPrefix(path, pre) {
				return true
			}
		}
	}
	return false
}

func NewProcessor(ctrl SessionControl, wallBase time.Time, write func(Output) error) *Processor {
	return &Processor{
		ctrl: ctrl, write: write, wallBase: wallBase,
		pending: make(map[uint64]*pendingSession),
		live:    make(map[uint64]*liveSession),
		decided: make(map[uint64]bool),
		started: make(map[uint64]bool),
	}
}

func (p *Processor) wallClock(tsNS uint64) string {
	return p.wallBase.Add(time.Duration(tsNS)).UTC().Format(time.RFC3339Nano)
}

// WallClockNow returns the wall clock corresponding to the current
// monotonic time, in the same clock domain as event `ts` fields.
func (p *Processor) WallClockNow() string {
	return p.wallClock(monotonicNS())
}

// HasStarted reports whether a session_start has been emitted for sid.
func (p *Processor) HasStarted(sid uint64) bool {
	p.startedMu.RLock()
	defer p.startedMu.RUnlock()
	return p.started[sid]
}

func (p *Processor) markStarted(sid uint64) bool {
	p.startedMu.Lock()
	defer p.startedMu.Unlock()
	was := p.started[sid]
	if !was {
		p.seenCount++
	}
	p.started[sid] = true
	return was
}

// SessionsSeen reports how many distinct sessions have ever emitted
// session_start (including ones that have since ended). Used by the
// maintenance loop to warn when rules are configured but nothing has
// matched — the otherwise-silent "no sessions" failure.
func (p *Processor) SessionsSeen() uint64 {
	p.startedMu.RLock()
	defer p.startedMu.RUnlock()
	return p.seenCount
}

func (p *Processor) markEnded(sid uint64) {
	p.startedMu.Lock()
	defer p.startedMu.Unlock()
	delete(p.started, sid)
}

func (p *Processor) toOutput(d *Decoded, provisional bool) Output {
	out := Output{
		Ts: p.wallClock(d.TsNS), Type: typeNames[d.Type],
		SessionID: d.SessionID, ParentSessionID: d.ParentSID,
		PID: d.Tgid, PIDInNS: d.PIDInNS, PPID: d.PPID, UID: d.UID,
		Comm: d.Comm, Provisional: provisional, Fields: d.Fields,
	}
	if meta, ok := p.ctrl.LookupMeta(d.SessionID); ok {
		out.AgentName = meta.AgentName
		if out.ParentSessionID == 0 {
			out.ParentSessionID = meta.ParentSID
		}
	}
	return out
}

func (p *Processor) liveFor(sid uint64) *liveSession {
	st, ok := p.live[sid]
	if !ok {
		st = &liveSession{alive: map[uint32]bool{}, exited: map[uint32]bool{}}
		p.live[sid] = st
	}
	return st
}

// endSessionLocked flushes (via BeforeSessionEnd) and writes the
// session_end line, exactly once per session. template supplies the
// identity fields (ts/pid/agent) of the end line: the triggering exit
// event for "all_exited", a synthesised root-identity line for
// "orphan_timeout". Runs under p.mu.
func (p *Processor) endSessionLocked(sid uint64, template Output, reason string, stillRunning []uint32) {
	st := p.liveFor(sid)
	if st.ended {
		return
	}
	st.ended = true
	if p.BeforeSessionEnd != nil {
		p.BeforeSessionEnd(sid)
	}
	end := template
	end.Type = "session_end"
	end.Fields = map[string]any{"reason": reason}
	if len(stillRunning) > 0 {
		end.Fields["still_running"] = stillRunning
	}
	if cp, ok := p.ctrl.(interface {
		SessionCPU(uint64) (uint64, uint64, bool)
	}); ok {
		if u, s, ok := cp.SessionCPU(sid); ok {
			end.Fields["cpu_user_ms"] = u
			end.Fields["cpu_sys_ms"] = s
		}
	}
	_ = p.write(end)
	p.markEnded(sid)
}

func (p *Processor) emitLocked(d *Decoded, provisional bool) {
	st := p.liveFor(d.SessionID)
	if st.ended {
		return // session already closed (e.g. orphan timeout): drop stragglers
	}
	// Track live TGIDs: any event proves its TGID alive — unless its
	// exit was already processed (post-exit teardown events, e.g.
	// file_close from deferred freeing, must not resurrect it). Fork
	// also proves the child; a forked child_pid is a new process even
	// if the TGID was seen dead before (PID reuse).
	if d.Type != 3 && d.Tgid != 0 && !st.exited[d.Tgid] {
		st.alive[d.Tgid] = true
	}
	if d.Type == 2 { // fork
		if child, ok := d.Fields["child_pid"].(uint32); ok && child != 0 {
			delete(st.exited, child)
			st.alive[child] = true
		}
	}
	if !p.markStarted(d.SessionID) {
		start := p.toOutput(d, provisional)
		start.Type = "session_start"
		start.Fields = map[string]any{}
		_ = p.write(start)
	}
	_ = p.write(p.toOutput(d, provisional))
	if d.Type != 3 { // not exit
		return
	}
	delete(st.alive, d.Tgid)
	st.exited[d.Tgid] = true
	meta, hasMeta := p.ctrl.LookupMeta(d.SessionID)
	isRoot := hasMeta && meta.RootTGID == d.Tgid
	if isRoot && !st.rootExited {
		st.rootExited = true
		st.rootExitAt = time.Now()
		// root_exit marks the root's death while the session may stay
		// open for surviving tracked processes; the gap between this
		// event and session_end is the orphan window.
		rootExit := p.toOutput(d, false)
		rootExit.Type = "root_exit"
		rootExit.Fields = map[string]any{}
		// root_exit mirrors the root's exit event identity: exit code
		// plus its per-process CPU / peak RSS (ABI v4).
		for _, k := range []string{"exit_code", "cpu_user_ms", "cpu_sys_ms", "max_rss_kb"} {
			if v, ok := d.Fields[k]; ok {
				rootExit.Fields[k] = v
			}
		}
		_ = p.write(rootExit)
	}
	if st.rootExited && len(st.alive) == 0 {
		p.endSessionLocked(d.SessionID, p.toOutput(d, false), "all_exited", nil)
	}
}

// ExpireOrphans ends sessions whose root has exited but whose tracked
// processes are still alive once OrphanTimeout has elapsed since the
// root exit. Called periodically from maintenance; a no-op when the
// timeout is zero (wait indefinitely).
func (p *Processor) ExpireOrphans() {
	if p.OrphanTimeout <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	var expired []uint64
	for sid, st := range p.live {
		if st.rootExited && !st.ended && len(st.alive) > 0 && now.Sub(st.rootExitAt) >= p.OrphanTimeout {
			expired = append(expired, sid)
		}
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i] < expired[j] })
	for _, sid := range expired {
		st := p.live[sid]
		still := make([]uint32, 0, len(st.alive))
		for tgid := range st.alive {
			still = append(still, tgid)
		}
		sort.Slice(still, func(i, j int) bool { return still[i] < still[j] })
		template := Output{Ts: p.WallClockNow(), SessionID: sid}
		if meta, ok := p.ctrl.LookupMeta(sid); ok {
			template.AgentName = meta.AgentName
			template.ParentSessionID = meta.ParentSID
			template.PID = meta.RootTGID
		}
		p.endSessionLocked(sid, template, "orphan_timeout", still)
	}
}

func matchInterpreter(cfg *config.File, d *Decoded) (config.Agent, bool) {
	argv, _ := d.Fields["argv"].([]string)
	joined := strings.Join(argv, " ")
	filename, _ := d.Fields["filename"].(string)
	for _, rule := range cfg.InterpreterRules() {
		if !strings.Contains(joined, rule.Match.ArgvContains) {
			continue
		}
		// The kernel candidate match was by interpreter inode; the
		// exec filename should be that interpreter (by path or name).
		// The walked filename is the resolved target (e.g.
		// /usr/bin/python3.14 for interpreter /usr/bin/python3), so
		// accept the symlink-resolved path and versioned basenames.
		resolved := rule.Match.Interpreter
		if r, err := filepath.EvalSymlinks(resolved); err == nil {
			resolved = r
		}
		if filename == rule.Match.Interpreter || filename == resolved ||
			strings.HasSuffix(filename, "/"+baseName(rule.Match.Interpreter)) ||
			baseName(filename) == baseName(rule.Match.Interpreter) ||
			strings.HasPrefix(baseName(filename), baseName(rule.Match.Interpreter)+".") {
			return rule, true
		}
	}
	return config.Agent{}, false
}

func baseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// Process handles one decoded record. Safe for concurrent use.
func (p *Processor) Process(d *Decoded) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.shouldDrop(d) {
		p.droppedFiltered++
		return
	}
	if confirmed, decided := p.decided[d.SessionID]; decided {
		if !confirmed {
			return // rejected session: drop stragglers
		}
		p.emitLocked(d, false)
		return
	}
	if !d.Provisional {
		p.emitLocked(d, false)
		return
	}
	// Provisional: buffer (bounded), decide on the exec event.
	pend, ok := p.pending[d.SessionID]
	if !ok {
		pend = &pendingSession{deadline: time.Now().Add(provisionalTimeout)}
		p.pending[d.SessionID] = pend
	}
	if len(pend.buffered) < provisionalMaxBuffered {
		pend.buffered = append(pend.buffered, d)
	} else {
		p.droppedBuf++
	}
	if d.Type != 1 { // wait for the exec event (or timeout)
		return
	}
	rule, matched := matchInterpreter(p.ctrl.Rules(), d)
	if !matched {
		_ = p.ctrl.Reject(d.SessionID)
		p.decided[d.SessionID] = false
		delete(p.pending, d.SessionID)
		return
	}
	if err := p.ctrl.Confirm(d.SessionID, rule); err != nil {
		_ = p.ctrl.Reject(d.SessionID)
		p.decided[d.SessionID] = false
		delete(p.pending, d.SessionID)
		return
	}
	p.decided[d.SessionID] = true
	buffered := pend.buffered
	delete(p.pending, d.SessionID)
	for _, b := range buffered {
		p.emitLocked(b, false)
	}
}

// Expire rejects provisional sessions whose decision window closed.
// Timeout counts as reject — same kernel tombstone write.
func (p *Processor) Expire() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for sid, pend := range p.pending {
		if now.After(pend.deadline) {
			_ = p.ctrl.Reject(sid)
			p.decided[sid] = false
			delete(p.pending, sid)
		}
	}
}

// Forget drops local state for a session (e.g. after sweeper cleanup).
func (p *Processor) Forget(sid uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, sid)
	delete(p.live, sid)
	p.markEnded(sid)
	if p.ForgetHook != nil {
		p.ForgetHook(sid)
	}
}
