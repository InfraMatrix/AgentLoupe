package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Runs the real hook script with Claude Code-shaped payloads and checks
// that its records are well-formed, carry both clocks, never carry file
// contents, and are accepted by the reducer.
func TestHookScriptRecords(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	script := filepath.Join("..", "..", "hooks", "agentloupe_hook.py")
	out := filepath.Join(t.TempDir(), "run.spans.jsonl")
	payloads := []string{
		`{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"pytest -q","description":"run tests"}}`,
		`{"hook_event_name":"PostToolUse","session_id":"s1","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"pytest -q"},"tool_response":{"stdout":"SECRET OUTPUT"},"duration_ms":1234}`,
		`{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Write","tool_use_id":"toolu_2","tool_input":{"file_path":"/repo/a.py","content":"SECRET FILE CONTENT"}}`,
		`{"hook_event_name":"PostToolUseFailure","session_id":"s1","tool_name":"Write","tool_use_id":"toolu_2","tool_input":{"file_path":"/repo/a.py","content":"SECRET FILE CONTENT"},"error":"denied","is_interrupt":false}`,
		`not json at all`,
	}
	for _, p := range payloads {
		cmd := exec.Command(py, script)
		cmd.Env = append(os.Environ(), "AGENTLOUPE_SPANS="+out)
		cmd.Stdin = strings.NewReader(p)
		stdout, err := cmd.Output()
		if err != nil {
			t.Fatalf("hook exited non-zero on %q: %v", p, err)
		}
		if len(stdout) != 0 {
			t.Fatalf("hook printed to stdout (Claude Code would parse it): %q", stdout)
		}
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SECRET") {
		t.Fatalf("spans file leaked tool output or file contents:\n%s", data)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 {
		t.Fatalf("records = %d, want 4 (garbage input writes nothing)", len(lines))
	}
	var recs []map[string]any
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, m)
	}
	wantEv := []string{"pre", "post", "pre", "post_failure"}
	for i, m := range recs {
		if m["event"] != wantEv[i] {
			t.Errorf("record %d event = %v", i, m["event"])
		}
		for _, k := range []string{"ts_ns", "mono_ns", "pid", "ppid", "tool_use_id", "ancestors"} {
			if _, ok := m[k]; !ok {
				t.Errorf("record %d missing %s", i, k)
			}
		}
	}
	if recs[1]["duration_ms"] != float64(1234) {
		t.Errorf("duration_ms = %v", recs[1]["duration_ms"])
	}
	in := recs[2]["input"].(map[string]any)
	if in["file_path"] != "/repo/a.py" || in["_sizes"].(map[string]any)["content"] != float64(len("SECRET FILE CONTENT")) {
		t.Errorf("write input summary = %v", in)
	}
	if recs[3]["error"] != "denied" {
		t.Errorf("failure record = %v", recs[3])
	}
	parsed, skipped := loadHookRecs(strings.NewReader(string(data)))
	if len(parsed) != 4 || skipped != 0 || parsed[0].MonoNS == 0 {
		t.Errorf("reducer parsed %d (skipped %d)", len(parsed), skipped)
	}
}
