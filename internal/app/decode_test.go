package app

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/InfraMatrix/AgentLoupe/internal/config"
)

// ---- raw record fixtures -------------------------------------------------
// Layout mirrors bpf/agentloupe.h exactly (see abi_layout_test.go, which
// fails if these sizes/offsets drift from the C structs):
//   event_hdr 72 B, then one fixed-size payload per type.
//   ev_exec 1560, ev_fork 8, ev_exit 8, ev_file_open 536, ev_file_unlink 520,
//   ev_file_rename 1032, ev_file_chmod 528, ev_file_close 552, ev_net_connect 48.

func putStr(dst []byte, s string) { copy(dst, s) }

// buildRecord assembles a full ring-buffer record with a valid header.
func buildRecord(typ uint16, flags uint16, payload []byte) []byte {
	raw := make([]byte, 72+len(payload))
	binary.LittleEndian.PutUint16(raw[0:2], typ)
	binary.LittleEndian.PutUint16(raw[2:4], uint16(len(raw))) // hdr.size
	binary.LittleEndian.PutUint16(raw[4:6], 3)                // ABI version
	binary.LittleEndian.PutUint16(raw[6:8], flags)
	binary.LittleEndian.PutUint64(raw[8:16], 123456789) // ts_ns
	binary.LittleEndian.PutUint64(raw[16:24], 42)       // session_id
	binary.LittleEndian.PutUint64(raw[24:32], 7)        // parent_session_id
	binary.LittleEndian.PutUint64(raw[32:40], 99)       // cgroup_id (not decoded)
	binary.LittleEndian.PutUint32(raw[40:44], 1234)     // tgid
	binary.LittleEndian.PutUint32(raw[44:48], 55)       // pid in ns
	binary.LittleEndian.PutUint32(raw[48:52], 1000)     // ppid
	binary.LittleEndian.PutUint32(raw[52:56], 1001)     // uid
	putStr(raw[56:72], "python3")                       // comm
	copy(raw[72:], payload)
	return raw
}

func execPayload() []byte {
	p := make([]byte, 1560)
	putStr(p[0:512], "/usr/bin/python3")
	putStr(p[512:1024], "/work/user/proj")
	putStr(p[1024:1536], "python3\x00-m\x00aider\x00")
	// p[1536:1540] argc is left 0 by the kernel; the decoder counts argv.
	binary.LittleEndian.PutUint32(p[1540:1544], 1000) // audit_loginuid
	binary.LittleEndian.PutUint32(p[1544:1548], 5)    // audit_sessionid
	p[1552] = 1                                       // filename_src = d_path
	p[1553] = 2                                       // cwd_src = dentry_walk
	return p
}

func fileOpenPayload() []byte {
	p := make([]byte, 536)
	putStr(p[0:512], "/tmp/x")
	binary.LittleEndian.PutUint64(p[512:520], 0xffff888012345678) // file_ptr
	binary.LittleEndian.PutUint32(p[520:524], 0o102)              // open_flags (O_CREAT|O_WRONLY)
	binary.LittleEndian.PutUint32(p[524:528], 0)                  // result
	p[528] = 1                                                    // path_src = d_path
	return p
}

func netPayload(family uint16) []byte {
	p := make([]byte, 48)
	if family == 2 {
		copy(p[0:4], net.ParseIP("93.184.216.34").To4())
		copy(p[16:20], net.ParseIP("192.168.1.10").To4())
	} else {
		copy(p[0:16], net.ParseIP("2001:db8::1").To16())
		copy(p[16:32], net.ParseIP("::1").To16())
	}
	binary.LittleEndian.PutUint16(p[32:34], 443)   // dport
	binary.LittleEndian.PutUint16(p[34:36], 54321) // sport
	binary.LittleEndian.PutUint16(p[36:38], family)
	p[38] = 6 // IPPROTO_TCP
	return p
}

func assertField(t *testing.T, d *Decoded, key string, want any) {
	t.Helper()
	got, ok := d.Fields[key]
	if !ok {
		t.Errorf("missing field %q (fields: %v)", key, d.Fields)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("field %q = %#v (%T), want %#v (%T)", key, got, got, want, want)
	}
}

func assertNoField(t *testing.T, d *Decoded, key string) {
	t.Helper()
	if v, ok := d.Fields[key]; ok {
		t.Errorf("field %q = %v, want absent", key, v)
	}
}

func TestDecodeHeaderFields(t *testing.T) {
	d, err := Decode(buildRecord(2, 0, make([]byte, 8)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Type != 2 || d.TsNS != 123456789 || d.SessionID != 42 || d.ParentSID != 7 {
		t.Errorf("header = %+v", d)
	}
	if d.Tgid != 1234 || d.PIDInNS != 55 || d.PPID != 1000 || d.UID != 1001 {
		t.Errorf("ids: tgid=%d pid_in_ns=%d ppid=%d uid=%d", d.Tgid, d.PIDInNS, d.PPID, d.UID)
	}
	if d.Comm != "python3" {
		t.Errorf("comm = %q", d.Comm)
	}
	if d.Provisional {
		t.Error("Provisional = true with flags 0")
	}
}

func TestDecodeValidEvents(t *testing.T) {
	tests := []struct {
		name  string
		raw   []byte
		check func(t *testing.T, d *Decoded)
	}{
		{
			name: "exec",
			raw:  buildRecord(1, 0, execPayload()),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "filename", "/usr/bin/python3")
				assertField(t, d, "cwd", "/work/user/proj")
				assertField(t, d, "argv", []string{"python3", "-m", "aider"})
				assertField(t, d, "argc", 3)
				assertField(t, d, "loginuid", uint32(1000))
				assertField(t, d, "filename_src", "d_path")
				assertField(t, d, "cwd_src", "dentry_walk")
			},
		},
		{
			name: "exec with loginuid unset omits the field",
			raw: func() []byte {
				p := execPayload()
				binary.LittleEndian.PutUint32(p[1540:1544], 4294967295)
				return buildRecord(1, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) { assertNoField(t, d, "loginuid") },
		},
		{
			name: "exec with empty argv",
			raw: func() []byte {
				p := execPayload()
				for i := 1024; i < 1536; i++ {
					p[i] = 0
				}
				return buildRecord(1, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "argv", []string{})
				assertField(t, d, "argc", 0)
			},
		},
		{
			name: "fork",
			raw: func() []byte {
				p := make([]byte, 8)
				binary.LittleEndian.PutUint32(p[0:4], 2345)
				binary.LittleEndian.PutUint32(p[4:8], 66)
				return buildRecord(2, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "child_pid", uint32(2345))
				assertField(t, d, "child_pid_in_ns", uint32(66))
			},
		},
		{
			name: "exit",
			raw: func() []byte {
				p := make([]byte, 8)
				binary.LittleEndian.PutUint32(p[0:4], 0x100) // raw wait status for exit(1)
				return buildRecord(3, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "exit_code", int32(0x100))
			},
		},
		{
			name: "file_open",
			raw:  buildRecord(4, 0, fileOpenPayload()),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "path", "/tmp/x")
				assertField(t, d, "file_ptr", "0xffff888012345678")
				assertField(t, d, "open_flags", uint32(0o102))
				assertField(t, d, "result", int32(0))
				assertField(t, d, "path_src", "d_path")
			},
		},
		{
			name: "file_open with error result",
			raw: func() []byte {
				p := fileOpenPayload()
				binary.LittleEndian.PutUint32(p[524:528], 0xFFFFFFF3) // -13 (EACCES)
				return buildRecord(4, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "result", int32(-13))
			},
		},
		{
			name: "file_unlink",
			raw: func() []byte {
				p := make([]byte, 520)
				putStr(p[0:512], "/tmp/gone")
				binary.LittleEndian.PutUint32(p[512:516], 0)
				p[516] = 3 // raw_arg
				return buildRecord(5, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "path", "/tmp/gone")
				assertField(t, d, "result", int32(0))
				assertField(t, d, "path_src", "raw_arg")
			},
		},
		{
			name: "file_rename",
			raw: func() []byte {
				p := make([]byte, 1032)
				putStr(p[0:512], "/tmp/old")
				putStr(p[512:1024], "/tmp/new")
				binary.LittleEndian.PutUint32(p[1024:1028], 0)
				p[1028] = 1
				p[1029] = 2
				return buildRecord(6, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "old_path", "/tmp/old")
				assertField(t, d, "new_path", "/tmp/new")
				assertField(t, d, "old_path_src", "d_path")
				assertField(t, d, "new_path_src", "dentry_walk")
			},
		},
		{
			name: "file_chmod",
			raw: func() []byte {
				p := make([]byte, 528)
				putStr(p[0:512], "/tmp/x")
				binary.LittleEndian.PutUint32(p[512:516], 0o644)
				binary.LittleEndian.PutUint32(p[516:520], 0)
				p[520] = 1
				return buildRecord(7, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "path", "/tmp/x")
				assertField(t, d, "mode", "0644")
				assertField(t, d, "result", int32(0))
			},
		},
		{
			name: "file_close",
			raw: func() []byte {
				p := make([]byte, 552)
				putStr(p[0:512], "/var/log/app.log")
				binary.LittleEndian.PutUint64(p[512:520], 0xdeadbeef)
				binary.LittleEndian.PutUint64(p[520:528], 4096)
				binary.LittleEndian.PutUint64(p[528:536], 8192)
				p[544] = 1
				return buildRecord(8, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "path", "/var/log/app.log")
				assertField(t, d, "read_bytes", uint64(4096))
				assertField(t, d, "write_bytes", uint64(8192))
				assertField(t, d, "path_src", "d_path")
				assertNoField(t, d, "partial")
			},
		},
		{
			name: "file_io flush is marked partial",
			raw: func() []byte {
				p := make([]byte, 552)
				putStr(p[0:512], "/var/log/app.log")
				binary.LittleEndian.PutUint64(p[528:536], 100)
				return buildRecord(9, 0, p)
			}(),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "partial", true)
				assertField(t, d, "write_bytes", uint64(100))
			},
		},
		{
			name: "net_connect ipv4",
			raw:  buildRecord(10, 0, netPayload(2)),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "daddr", "93.184.216.34")
				assertField(t, d, "saddr", "192.168.1.10")
				assertField(t, d, "dport", uint16(443))
				assertField(t, d, "sport", uint16(54321))
				assertField(t, d, "family", uint16(2))
				assertField(t, d, "protocol", uint8(6))
				assertField(t, d, "result", int32(0))
			},
		},
		{
			name: "net_connect ipv6",
			raw:  buildRecord(10, 0, netPayload(10)),
			check: func(t *testing.T, d *Decoded) {
				assertField(t, d, "daddr", "2001:db8::1")
				assertField(t, d, "saddr", "::1")
				assertField(t, d, "family", uint16(10))
			},
		},
		{
			name: "session types have no kernel payload",
			raw:  buildRecord(11, 0, nil),
			check: func(t *testing.T, d *Decoded) {
				if len(d.Fields) != 0 {
					t.Errorf("fields = %v, want empty", d.Fields)
				}
			},
		},
		{
			name: "unknown type decodes the header only",
			raw:  buildRecord(99, 0, []byte{1, 2, 3}),
			check: func(t *testing.T, d *Decoded) {
				if d.Type != 99 || len(d.Fields) != 0 {
					t.Errorf("decoded = %+v", d)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Decode(tt.raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			tt.check(t, d)
		})
	}
}

func TestDecodeFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		check func(t *testing.T, d *Decoded)
	}{
		{"truncated string flag", 1, func(t *testing.T, d *Decoded) {
			assertField(t, d, "truncated", true)
		}},
		{"path partial flag", 16, func(t *testing.T, d *Decoded) {
			assertField(t, d, "path_partial", true)
		}},
		{"provisional flag", 2, func(t *testing.T, d *Decoded) {
			if !d.Provisional {
				t.Error("Provisional = false, want true")
			}
		}},
		{"no flags, no extra fields", 0, func(t *testing.T, d *Decoded) {
			assertNoField(t, d, "truncated")
			assertNoField(t, d, "path_partial")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Decode(buildRecord(4, tt.flags, fileOpenPayload()))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			tt.check(t, d)
		})
	}
}

func TestDecodeEdgeCases(t *testing.T) {
	t.Run("zero PIDs and empty comm", func(t *testing.T) {
		raw := buildRecord(2, 0, make([]byte, 8))
		binary.LittleEndian.PutUint32(raw[40:44], 0)
		binary.LittleEndian.PutUint32(raw[44:48], 0)
		binary.LittleEndian.PutUint32(raw[48:52], 0)
		binary.LittleEndian.PutUint32(raw[52:56], 0)
		for i := 56; i < 72; i++ {
			raw[i] = 0
		}
		d, err := Decode(raw)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if d.Tgid != 0 || d.PIDInNS != 0 || d.Comm != "" {
			t.Errorf("decoded = %+v", d)
		}
	})

	t.Run("unterminated 512-byte path is kept whole", func(t *testing.T) {
		p := fileOpenPayload()
		long := strings.Repeat("a", 512) // fills the field: no NUL terminator
		copy(p[0:512], long)
		d, err := Decode(buildRecord(4, 1, p)) // EVENT_F_TRUNCATED
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		assertField(t, d, "path", long)
		assertField(t, d, "truncated", true)
	})

	t.Run("unknown path_source decodes as empty string", func(t *testing.T) {
		p := fileOpenPayload()
		p[528] = 99 // not in enum path_source
		d, err := Decode(buildRecord(4, 0, p))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		assertField(t, d, "path_src", "")
	})

	t.Run("trailing bytes beyond hdr.size are ignored", func(t *testing.T) {
		raw := append(buildRecord(2, 0, make([]byte, 8)), 0xde, 0xad, 0xbe, 0xef)
		if _, err := Decode(raw); err != nil {
			t.Fatalf("Decode with trailing bytes: %v", err)
		}
	})
}

func TestDecodeMalformed(t *testing.T) {
	shortPayload := func(typ uint16, payloadLen int) []byte {
		return buildRecord(typ, 0, make([]byte, payloadLen))
	}
	withSize := func(raw []byte, size uint16) []byte {
		binary.LittleEndian.PutUint16(raw[2:4], size)
		return raw
	}
	withVersion := func(raw []byte, v uint16) []byte {
		binary.LittleEndian.PutUint16(raw[4:6], v)
		return raw
	}
	full := buildRecord(1, 0, execPayload())

	tests := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{"empty buffer", nil, "short record"},
		{"one byte", []byte{1}, "short record"},
		{"71 bytes (header truncated)", make([]byte, 71), "short record"},
		{"bad abi version 0", withVersion(buildRecord(2, 0, make([]byte, 8)), 0), "abi version 0"},
		{"bad abi version 2", withVersion(buildRecord(2, 0, make([]byte, 8)), 2), "abi version 2"},
		{"bad abi version 4", withVersion(buildRecord(2, 0, make([]byte, 8)), 4), "abi version 4"},
		{"size below header", withSize(buildRecord(2, 0, make([]byte, 8)), 71), "bad record size 71"},
		{"size zero", withSize(buildRecord(2, 0, make([]byte, 8)), 0), "bad record size 0"},
		{"size beyond buffer", withSize(buildRecord(2, 0, make([]byte, 8)), 999), "bad record size 999"},
		{"exec payload one byte short", shortPayload(1, 1559), "exec payload"},
		{"exec header only", shortPayload(1, 0), "exec payload"},
		{"fork payload short", shortPayload(2, 7), "fork payload short"},
		{"exit payload short", shortPayload(3, 7), "exit payload short"},
		{"file_open payload short", shortPayload(4, 535), "file_open payload short"},
		{"unlink payload short", shortPayload(5, 519), "unlink payload short"},
		{"rename payload short", shortPayload(6, 1031), "rename payload short"},
		{"chmod payload short", shortPayload(7, 527), "chmod payload short"},
		{"file_close payload short", shortPayload(8, 551), "file_close payload short"},
		{"file_io payload short", shortPayload(9, 551), "file_close payload short"},
		{"net payload short", shortPayload(10, 47), "net payload short"},
		{"full record truncated mid-payload", full[:len(full)-1], "bad record size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Decode(tt.raw)
			if err == nil {
				t.Fatalf("Decode succeeded with %+v, want error %q", d, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// ---- JSON output -----------------------------------------------------------

type fakeCtrl struct{ meta SessionMeta }

func (f fakeCtrl) LookupMeta(uint64) (SessionMeta, bool) { return f.meta, true }
func (f fakeCtrl) Confirm(uint64, config.Agent) error    { return nil }
func (f fakeCtrl) Reject(uint64) error                   { return nil }
func (f fakeCtrl) Rules() *config.File                   { return &config.File{} }

func TestProcessorJSONPipeline(t *testing.T) {
	var out []Output
	wallBase := time.Unix(1700000000, 0).UTC()
	proc := NewProcessor(fakeCtrl{meta: SessionMeta{AgentName: "test-agent", RootTGID: 1234}},
		wallBase, func(o Output) error { out = append(out, o); return nil })

	exec, err := Decode(buildRecord(1, 0, execPayload()))
	if err != nil {
		t.Fatal(err)
	}
	proc.Process(exec)
	if len(out) != 2 {
		t.Fatalf("outputs = %d, want session_start + exec: %v", len(out), out)
	}
	if out[0].Type != "session_start" || out[1].Type != "exec" {
		t.Errorf("types = %q, %q", out[0].Type, out[1].Type)
	}
	if out[1].AgentName != "test-agent" || out[1].PID != 1234 || out[1].SessionID != 42 {
		t.Errorf("exec output = %+v", out[1])
	}
	if want := wallBase.Add(time.Duration(123456789)).UTC().Format(time.RFC3339Nano); out[1].Ts != want {
		t.Errorf("ts = %q, want %q (monotonic -> wall clock)", out[1].Ts, want)
	}

	// Marshalled JSON flattens event fields to the top level.
	b, err := json.Marshal(out[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"type": "exec", "agent_name": "test-agent",
		"filename": "/usr/bin/python3", "comm": "python3",
	} {
		if m[key] != want {
			t.Errorf("json[%q] = %v, want %v (json: %s)", key, m[key], want, b)
		}
	}
	if _, ok := m["provisional"]; ok {
		t.Errorf("provisional should be omitted when false: %s", b)
	}

	// Exit of the session root synthesises root_exit, then session_end
	// (no tracked processes remain in this session).
	exit, err := Decode(buildRecord(3, 0, make([]byte, 8)))
	if err != nil {
		t.Fatal(err)
	}
	out = nil
	proc.Process(exit)
	if len(out) != 3 || out[0].Type != "exit" || out[1].Type != "root_exit" || out[2].Type != "session_end" {
		t.Errorf("exit outputs = %v, want [exit root_exit session_end]", out)
	}
	if len(out) == 3 {
		if out[1].Fields["exit_code"] != int32(0) {
			t.Errorf("root_exit exit_code = %v, want 0", out[1].Fields["exit_code"])
		}
		if out[2].Fields["reason"] != "all_exited" {
			t.Errorf("session_end reason = %v, want all_exited", out[2].Fields["reason"])
		}
	}
}

func TestTypeNamesCoverKernelEvents(t *testing.T) {
	// Every kernel event_type 1..10 plus the two userspace-synthesised
	// session types must have a JSONL name.
	for typ := uint16(1); typ <= 12; typ++ {
		if typeNames[typ] == "" {
			t.Errorf("typeNames[%d] missing", typ)
		}
	}
	if fmt.Sprint(typeNames[10]) != "net_connect" {
		t.Errorf("typeNames[10] = %q", typeNames[10])
	}
}
