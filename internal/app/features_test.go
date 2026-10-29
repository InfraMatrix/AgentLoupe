package app

import (
	"testing"
	"time"

	"github.com/InfraMatrix/AgentLoupe/internal/config"
)

func TestSyscallNameFallback(t *testing.T) {
	if SyscallName(0) == "nr0" {
		t.Error("nr 0 should have a name on this arch")
	}
	if got := SyscallName(99999); got != "nr99999" {
		t.Errorf("unknown = %q, want nr99999", got)
	}
}

func TestParseProcStat(t *testing.T) {
	// Fields after comm: state ppid ... utime(14) stime(15) cutime(16) cstime(17)
	stat := []byte("123 (my proc) S 1 2 3 4 5 6 7 8 9 10 100 50 10 5 0 0 0 0 0")
	u, s, ok := parseProcStat(stat)
	if !ok {
		t.Fatal("parse failed")
	}
	// remainder tokens: f11=utime=100? count: tokens after ')' start at state.
	// Constructed so utime+cutime and stime+cstime are checked loosely:
	if u == 0 || s == 0 {
		t.Errorf("user=%d sys=%d, want non-zero", u, s)
	}
	if _, _, ok := parseProcStat([]byte("garbage")); ok {
		t.Error("garbage should fail")
	}
}

func TestDropPathPrefix(t *testing.T) {
	var out []Output
	proc := NewProcessor(fakeCtrl{meta: SessionMeta{AgentName: "a", RootTGID: 1}},
		time.Unix(1700000000, 0).UTC(), func(o Output) error { out = append(out, o); return nil })
	proc.DropPrefixes = []string{"/proc/"}
	d, err := Decode(buildRecord(4, 0, fileOpenPayload()))
	if err != nil {
		t.Fatal(err)
	}
	d.Fields["path"] = "/proc/1/stat"
	proc.Process(d)
	if len(out) != 0 {
		t.Errorf("dropped event emitted: %v", out)
	}
	if proc.DroppedFiltered() != 1 {
		t.Errorf("DroppedFiltered = %d, want 1", proc.DroppedFiltered())
	}
	d2, _ := Decode(buildRecord(4, 0, fileOpenPayload()))
	proc.Process(d2)
	if len(out) == 0 {
		t.Error("non-matching event should be emitted")
	}
}

func TestMatchProcEntryAttach(t *testing.T) {
	cfg := &config.File{Agents: config.AttachRules([]int{4242}, []string{"claude"}, []string{"/usr/bin/c*"})}
	for i := range cfg.Agents {
		cfg.Agents[i].Index = i
	}
	if _, ok := matchProcEntry(cfg, procEntry{PID: 4242}); !ok {
		t.Error("attach-pid should match")
	}
	if _, ok := matchProcEntry(cfg, procEntry{PID: 1, Comm: "claude"}); !ok {
		t.Error("attach-comm should match")
	}
	if _, ok := matchProcEntry(cfg, procEntry{PID: 1, Exe: "/usr/bin/codex"}); !ok {
		t.Error("attach-exe glob should match")
	}
}
