package app

// Struct-layout drift check between the C ABI (bpf/agentloupe.h) and Go.
//
// The Go side has no event structs of its own: the decoder works on raw
// byte offsets (events.go), as do the map encoders (maps.go) and the
// fd_info reader (maintenance.go). That makes silent drift easy, so this
// test pins it from both directions:
//
//  1. Mirror Go structs below must have exactly the sizes the C header
//     annotates ("/* N bytes */") and statically asserts
//     (_Static_assert(sizeof(struct X) == N)).
//  2. Their field offsets must equal the byte offsets the Go decoder /
//     encoders actually index.
//
// If the C ABI changes, update the header asserts, the mirrors, and the
// decoder in the same commit — and bump AGENTLOUPE_ABI_VERSION.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// Mirror structs: field order/types copy bpf/agentloupe.h one-to-one.
type eventHdrMirror struct {
	Type      uint16
	Size      uint16
	Version   uint16
	Flags     uint16
	TsNS      uint64
	SessionID uint64
	ParentSID uint64
	CgroupID  uint64
	Tgid      uint32
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      [16]byte
}

type evExecMirror struct {
	Filename       [512]byte
	Cwd            [512]byte
	Argv           [512]byte
	Argc           uint32
	AuditLoginUID  uint32
	AuditSessionID uint32
	Result         int32
	FilenameSrc    uint8
	CwdSrc         uint8
	Pad            uint16
	Pad2           uint32
}

type evForkMirror struct {
	ChildTGID uint32
	ChildPID  uint32
}

type evExitMirror struct {
	ExitCode int32
	Pad      int32
}

type evFileOpenMirror struct {
	Path    [512]byte
	FilePtr uint64
	Flags   uint32
	Result  int32
	PathSrc uint8
	Pad     [3]uint8
	Pad2    uint32
}

type evFileUnlinkMirror struct {
	Path    [512]byte
	Result  int32
	PathSrc uint8
	Pad     [3]uint8
}

type evFileRenameMirror struct {
	OldPath    [512]byte
	NewPath    [512]byte
	Result     int32
	OldPathSrc uint8
	NewPathSrc uint8
	Pad        uint16
}

type evFileChmodMirror struct {
	Path    [512]byte
	Mode    uint32
	Result  int32
	PathSrc uint8
	Pad     [3]uint8
	Pad2    uint32
}

type evFileCloseMirror struct {
	Path       [512]byte
	FilePtr    uint64
	ReadBytes  uint64
	WriteBytes uint64
	OpenTSNS   uint64
	PathSrc    uint8
	Pad        [7]uint8
}

type evNetConnectMirror struct {
	Daddr    [16]byte
	Saddr    [16]byte
	Dport    uint16
	Sport    uint16
	Family   uint16
	Protocol uint8
	Pad      uint8
	Result   int32
	Pad2     int32
}

type sessionInfoMirror struct {
	State     uint32
	AgentID   uint32
	ParentSID uint64
	CgroupID  uint64
	StartTSNS uint64
	Flags     uint32
	RootTGID  uint32
	AgentName [32]byte
	RootComm  [16]byte
}

type trackedSessionMirror struct {
	SessionID uint64
}

type fdInfoMirror struct {
	Path       [512]byte
	SessionID  uint64
	ReadBytes  uint64
	WriteBytes uint64
	OpenTSNS   uint64
	Ino        uint64
	OpenerTGID uint32
	Flags      uint32
	Dev        uint32
	PathSrc    uint8
	Pad        [3]uint8
}

type binaryIDMirror struct {
	Dev uint32
	Pad uint32
	Ino uint64
}

type agentRefMirror struct {
	RuleID    uint32
	AgentName [32]byte
}

func goStructSizes() map[string]uintptr {
	return map[string]uintptr{
		"event_hdr":       unsafe.Sizeof(eventHdrMirror{}),
		"ev_exec":         unsafe.Sizeof(evExecMirror{}),
		"ev_fork":         unsafe.Sizeof(evForkMirror{}),
		"ev_exit":         unsafe.Sizeof(evExitMirror{}),
		"ev_file_open":    unsafe.Sizeof(evFileOpenMirror{}),
		"ev_file_unlink":  unsafe.Sizeof(evFileUnlinkMirror{}),
		"ev_file_rename":  unsafe.Sizeof(evFileRenameMirror{}),
		"ev_file_chmod":   unsafe.Sizeof(evFileChmodMirror{}),
		"ev_file_close":   unsafe.Sizeof(evFileCloseMirror{}),
		"ev_net_connect":  unsafe.Sizeof(evNetConnectMirror{}),
		"session_info":    unsafe.Sizeof(sessionInfoMirror{}),
		"tracked_session": unsafe.Sizeof(trackedSessionMirror{}),
		"fd_info":         unsafe.Sizeof(fdInfoMirror{}),
		"binary_id":       unsafe.Sizeof(binaryIDMirror{}),
		"agent_ref":       unsafe.Sizeof(agentRefMirror{}),
	}
}

// cStructSizes extracts the sizes bpf/agentloupe.h itself declares, from
// both the "/* N bytes */" struct annotations and the _Static_asserts.
func cStructSizes(t *testing.T) map[string]int {
	t.Helper()
	data, err := os.ReadFile("../../bpf/agentloupe.h")
	if err != nil {
		t.Fatalf("read C header: %v", err)
	}
	sizes := map[string]int{}
	// "struct name { ... };  /* N bytes */" annotations. Parsed per
	// struct (find the opening, then the first "};" after it) rather
	// than with one big regex, so a struct without an annotation can
	// never borrow the next struct's size.
	text := string(data)
	structStart := regexp.MustCompile(`struct (\w+) \{`)
	bytesAnnot := regexp.MustCompile(`^\s*/\*\s*(\d+) bytes`)
	for _, loc := range structStart.FindAllStringSubmatchIndex(text, -1) {
		name := text[loc[2]:loc[3]]
		end := strings.Index(text[loc[1]:], "};")
		if end < 0 {
			continue
		}
		m := bytesAnnot.FindStringSubmatch(text[loc[1]+end+2:])
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		sizes[name] = n
	}
	asserted := regexp.MustCompile(`_Static_assert\(sizeof\(struct (\w+)\) == (\d+),`)
	for _, m := range asserted.FindAllSubmatch(data, -1) {
		n, _ := strconv.Atoi(string(m[2]))
		name := string(m[1])
		if prev, ok := sizes[name]; ok && prev != n {
			t.Errorf("header disagreement for %s: annotation %d vs _Static_assert %d", name, prev, n)
		}
		sizes[name] = n
	}
	return sizes
}

func TestStructSizesMatchCHeader(t *testing.T) {
	cSizes := cStructSizes(t)
	goSizes := goStructSizes()

	// Structs whose sizes the decoder/encoders hard-depend on. If the C
	// header stops declaring one of these, the check itself is broken.
	for _, name := range []string{
		"event_hdr", "ev_exec", "ev_fork", "ev_exit", "ev_file_open",
		"ev_file_unlink", "ev_file_rename", "ev_file_chmod", "ev_file_close",
		"ev_net_connect", "session_info", "tracked_session", "fd_info",
	} {
		if _, ok := cSizes[name]; !ok {
			t.Errorf("C header no longer declares a size for struct %s; update this test with the ABI change", name)
		}
	}
	for name, cSize := range cSizes {
		gSize, ok := goSizes[name]
		if !ok {
			continue // C struct the Go side never touches byte-wise
		}
		if int(gSize) != cSize {
			t.Errorf("struct %s: Go mirror is %d bytes, C header says %d — ABI drift; update the decoder and bump AGENTLOUPE_ABI_VERSION", name, gSize, cSize)
		}
	}
	for name, gSize := range goSizes {
		if _, ok := cSizes[name]; !ok {
			t.Errorf("Go mirror for struct %s (%d bytes) has no size declared in bpf/agentloupe.h; add a /* N bytes */ annotation or _Static_assert", name, gSize)
		}
	}
}

func TestStructOffsetsMatchDecoder(t *testing.T) {
	// Each offset below is a byte index the Go code actually uses:
	// events.go Decode, maps.go decodeSessionInfo/binaryKey/agentRefValue,
	// maintenance.go flushLongLived.
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"event_hdr.tgid (raw[40:44])", unsafe.Offsetof(eventHdrMirror{}.Tgid), 40},
		{"event_hdr.pid (raw[44:48])", unsafe.Offsetof(eventHdrMirror{}.PID), 44},
		{"event_hdr.ppid (raw[48:52])", unsafe.Offsetof(eventHdrMirror{}.PPID), 48},
		{"event_hdr.uid (raw[52:56])", unsafe.Offsetof(eventHdrMirror{}.UID), 52},
		{"event_hdr.comm (raw[56:72])", unsafe.Offsetof(eventHdrMirror{}.Comm), 56},
		{"ev_exec.argc (p[1536:1540])", unsafe.Offsetof(evExecMirror{}.Argc), 1536},
		{"ev_exec.audit_loginuid (p[1540:1544])", unsafe.Offsetof(evExecMirror{}.AuditLoginUID), 1540},
		{"ev_exec.filename_src (p[1552])", unsafe.Offsetof(evExecMirror{}.FilenameSrc), 1552},
		{"ev_exec.cwd_src (p[1553])", unsafe.Offsetof(evExecMirror{}.CwdSrc), 1553},
		{"ev_file_open.file_ptr (p[512:520])", unsafe.Offsetof(evFileOpenMirror{}.FilePtr), 512},
		{"ev_file_open.flags (p[520:524])", unsafe.Offsetof(evFileOpenMirror{}.Flags), 520},
		{"ev_file_open.result (p[524:528])", unsafe.Offsetof(evFileOpenMirror{}.Result), 524},
		{"ev_file_open.path_src (p[528])", unsafe.Offsetof(evFileOpenMirror{}.PathSrc), 528},
		{"ev_file_unlink.result (p[512:516])", unsafe.Offsetof(evFileUnlinkMirror{}.Result), 512},
		{"ev_file_unlink.path_src (p[516])", unsafe.Offsetof(evFileUnlinkMirror{}.PathSrc), 516},
		{"ev_file_rename.result (p[1024:1028])", unsafe.Offsetof(evFileRenameMirror{}.Result), 1024},
		{"ev_file_rename.old_path_src (p[1028])", unsafe.Offsetof(evFileRenameMirror{}.OldPathSrc), 1028},
		{"ev_file_rename.new_path_src (p[1029])", unsafe.Offsetof(evFileRenameMirror{}.NewPathSrc), 1029},
		{"ev_file_chmod.mode (p[512:516])", unsafe.Offsetof(evFileChmodMirror{}.Mode), 512},
		{"ev_file_chmod.result (p[516:520])", unsafe.Offsetof(evFileChmodMirror{}.Result), 516},
		{"ev_file_chmod.path_src (p[520])", unsafe.Offsetof(evFileChmodMirror{}.PathSrc), 520},
		{"ev_file_close.file_ptr (p[512:520])", unsafe.Offsetof(evFileCloseMirror{}.FilePtr), 512},
		{"ev_file_close.read_bytes (p[520:528])", unsafe.Offsetof(evFileCloseMirror{}.ReadBytes), 520},
		{"ev_file_close.write_bytes (p[528:536])", unsafe.Offsetof(evFileCloseMirror{}.WriteBytes), 528},
		{"ev_file_close.open_ts_ns (p[536:544])", unsafe.Offsetof(evFileCloseMirror{}.OpenTSNS), 536},
		{"ev_file_close.path_src (p[544])", unsafe.Offsetof(evFileCloseMirror{}.PathSrc), 544},
		{"ev_net_connect.dport (p[32:34])", unsafe.Offsetof(evNetConnectMirror{}.Dport), 32},
		{"ev_net_connect.sport (p[34:36])", unsafe.Offsetof(evNetConnectMirror{}.Sport), 34},
		{"ev_net_connect.family (p[36:38])", unsafe.Offsetof(evNetConnectMirror{}.Family), 36},
		{"ev_net_connect.protocol (p[38])", unsafe.Offsetof(evNetConnectMirror{}.Protocol), 38},
		{"ev_net_connect.result (p[40:44])", unsafe.Offsetof(evNetConnectMirror{}.Result), 40},
		{"session_info.agent_name (raw[40:72])", unsafe.Offsetof(sessionInfoMirror{}.AgentName), 40},
		{"session_info.root_comm (raw[72:88])", unsafe.Offsetof(sessionInfoMirror{}.RootComm), 72},
		{"fd_info.session_id (raw[512:520])", unsafe.Offsetof(fdInfoMirror{}.SessionID), 512},
		{"fd_info.opener_tgid (raw[552:556])", unsafe.Offsetof(fdInfoMirror{}.OpenerTGID), 552},
		{"fd_info.path_src (raw[564])", unsafe.Offsetof(fdInfoMirror{}.PathSrc), 564},
		{"binary_id.ino (key[8:16])", unsafe.Offsetof(binaryIDMirror{}.Ino), 8},
		{"agent_ref.agent_name (v[4:36])", unsafe.Offsetof(agentRefMirror{}.AgentName), 4},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: Go mirror offset %d, decoder uses %d — ABI drift", tt.name, tt.got, tt.want)
		}
	}
}

func TestRecordSizesMatchEVLEN(t *testing.T) {
	// Total ring record size per type = sizeof(event_hdr) + payload, the
	// EVLEN_<TYPE> constants the BPF side reserves and hdr.size carries.
	sizes := goStructSizes()
	hdr := sizes["event_hdr"]
	tests := []struct {
		typ     uint16
		payload string
	}{
		{1, "ev_exec"}, {2, "ev_fork"}, {3, "ev_exit"}, {4, "ev_file_open"},
		{5, "ev_file_unlink"}, {6, "ev_file_rename"}, {7, "ev_file_chmod"},
		{8, "ev_file_close"}, {9, "ev_file_close"}, {10, "ev_net_connect"},
	}
	for _, tt := range tests {
		raw := buildRecord(tt.typ, 0, make([]byte, sizes[tt.payload]))
		if want := int(hdr + sizes[tt.payload]); len(raw) != want {
			t.Errorf("type %d record = %d bytes, want EVLEN %d", tt.typ, len(raw), want)
		}
		if _, err := Decode(raw); err != nil {
			t.Errorf("type %d full-size zero record failed to decode: %v", tt.typ, err)
		}
	}
}

func TestABIVersionMatchesHeader(t *testing.T) {
	data, err := os.ReadFile("../../bpf/agentloupe.h")
	if err != nil {
		t.Fatalf("read C header: %v", err)
	}
	m := regexp.MustCompile(`#define AGENTLOUPE_ABI_VERSION (\d+)`).FindSubmatch(data)
	if m == nil {
		t.Fatal("AGENTLOUPE_ABI_VERSION not found in bpf/agentloupe.h")
	}
	// Decode rejects anything but version 2 (see TestDecodeMalformed);
	// if the header bumps the version, the decoder must move with it.
	if string(m[1]) != "2" {
		t.Errorf("AGENTLOUPE_ABI_VERSION = %s, but the Go decoder only accepts 2", m[1])
	}
}
