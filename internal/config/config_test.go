package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agents.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantAgents int
		check      func(t *testing.T, cfg *File)
	}{
		{
			name:       "exec_path agent",
			yaml:       "agents:\n  - name: claude-code\n    kind: tool\n    match:\n      exec_path: /usr/local/bin/claude\n",
			wantAgents: 1,
			check: func(t *testing.T, cfg *File) {
				a := cfg.Agents[0]
				if a.Name != "claude-code" || a.Kind != "tool" || a.Match.ExecPath != "/usr/local/bin/claude" {
					t.Errorf("agent = %+v", a)
				}
				if a.Index != 0 {
					t.Errorf("Index = %d, want 0", a.Index)
				}
			},
		},
		{
			name:       "interpreter agent",
			yaml:       "agents:\n  - name: aider\n    kind: tool\n    match:\n      interpreter: /usr/bin/python3\n      argv_contains: aider\n",
			wantAgents: 1,
			check: func(t *testing.T, cfg *File) {
				a := cfg.Agents[0]
				if a.Match.Interpreter != "/usr/bin/python3" || a.Match.ArgvContains != "aider" {
					t.Errorf("match = %+v", a.Match)
				}
				if got := cfg.InterpreterRules(); len(got) != 1 || got[0].Name != "aider" {
					t.Errorf("InterpreterRules = %v", got)
				}
			},
		},
		{
			name:       "cgroup service",
			yaml:       "agents:\n  - name: svc\n    kind: service\n    match:\n      cgroup: /system.slice/my-agent.service\n",
			wantAgents: 1,
			check: func(t *testing.T, cfg *File) {
				if cfg.Agents[0].Match.Cgroup != "/system.slice/my-agent.service" {
					t.Errorf("match = %+v", cfg.Agents[0].Match)
				}
			},
		},
		{
			name:       "k8s label service",
			yaml:       "agents:\n  - name: pod\n    kind: service\n    match:\n      k8s_label: app=my-agent\n",
			wantAgents: 1,
			check: func(t *testing.T, cfg *File) {
				if cfg.Agents[0].Match.K8SLabel != "app=my-agent" {
					t.Errorf("match = %+v", cfg.Agents[0].Match)
				}
			},
		},
		{
			name: "multiple agents get sequential indexes",
			yaml: "agents:\n" +
				"  - name: a\n    match: {exec_path: /bin/a}\n" +
				"  - name: b\n    match: {cgroup: /system.slice/b.service}\n" +
				"  - name: c\n    match: {interpreter: /usr/bin/python3, argv_contains: c}\n",
			wantAgents: 3,
			check: func(t *testing.T, cfg *File) {
				for i, a := range cfg.Agents {
					if a.Index != i {
						t.Errorf("agents[%d].Index = %d", i, a.Index)
					}
				}
				if got := cfg.WatchedPaths(); len(got) != 2 {
					t.Errorf("WatchedPaths = %v, want exec_path + interpreter", got)
				}
			},
		},
		{
			name:       "empty agent list is valid",
			yaml:       "agents: []\n",
			wantAgents: 0,
		},
		{
			name:       "empty file is an empty config",
			yaml:       "",
			wantAgents: 0,
		},
		{
			name:       "comments-only file is an empty config",
			yaml:       "# nothing here\n",
			wantAgents: 0,
		},
		{
			name:       "name at the 31-byte kernel limit is accepted",
			yaml:       "agents:\n  - name: " + strings.Repeat("a", 31) + "\n    match: {exec_path: /bin/a}\n",
			wantAgents: 1,
		},
		{
			name:       "kind omitted stays empty (no invented defaults)",
			yaml:       "agents:\n  - name: a\n    match: {exec_path: /bin/a}\n",
			wantAgents: 1,
			check: func(t *testing.T, cfg *File) {
				if cfg.Agents[0].Kind != "" {
					t.Errorf("Kind = %q, want unset preserved", cfg.Agents[0].Kind)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, existed, err := Load(writeConfig(t, tt.yaml))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !existed {
				t.Error("existed = false, want true")
			}
			if len(cfg.Agents) != tt.wantAgents {
				t.Fatalf("agents = %d, want %d (%+v)", len(cfg.Agents), tt.wantAgents, cfg.Agents)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "missing name",
			yaml:    "agents:\n  - kind: tool\n    match: {exec_path: /bin/a}\n",
			wantErr: "name is required",
		},
		{
			name:    "name over the 31-byte kernel limit",
			yaml:    "agents:\n  - name: " + strings.Repeat("a", 32) + "\n    match: {exec_path: /bin/a}\n",
			wantErr: "exceeds 31 bytes",
		},
		{
			name:    "no match criteria",
			yaml:    "agents:\n  - name: a\n    kind: tool\n",
			wantErr: "match must set",
		},
		{
			name:    "empty match block",
			yaml:    "agents:\n  - name: a\n    match: {}\n",
			wantErr: "match must set",
		},
		{
			name:    "interpreter without argv_contains does not confirm",
			yaml:    "agents:\n  - name: a\n    match: {interpreter: /usr/bin/python3}\n",
			wantErr: "match must set",
		},
		{
			name:    "argv_contains without interpreter does not confirm",
			yaml:    "agents:\n  - name: a\n    match: {argv_contains: aider}\n",
			wantErr: "match must set",
		},
		{
			name:    "unknown top-level field",
			yaml:    "agent: []\n",
			wantErr: "field agent not found",
		},
		{
			name:    "unknown agent field (typo)",
			yaml:    "agents:\n  - name: a\n    names: b\n    match: {exec_path: /bin/a}\n",
			wantErr: "field names not found",
		},
		{
			name:    "unknown match field (typo)",
			yaml:    "agents:\n  - name: a\n    match: {execpath: /bin/a}\n",
			wantErr: "field execpath not found",
		},
		{
			name:    "malformed yaml",
			yaml:    "agents: [\n  - name: a\n",
			wantErr: "parse",
		},
		{
			name:    "wrong type for agents",
			yaml:    "agents: not-a-list\n",
			wantErr: "parse",
		},
		{
			name:    "wrong type for name",
			yaml:    "agents:\n  - name: [a, b]\n    match: {exec_path: /bin/a}\n",
			wantErr: "parse",
		},
		{
			name:    "multiple documents",
			yaml:    "agents: []\n---\nagents: []\n",
			wantErr: "multiple YAML documents",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, existed, err := Load(writeConfig(t, tt.yaml))
			if err == nil {
				t.Fatalf("Load succeeded with %+v, want error containing %q", cfg, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tt.wantErr)
			}
			if !existed {
				t.Error("existed = false, want true (file present but invalid)")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"missing file in existing dir", filepath.Join(t.TempDir(), "agents.yaml")},
		{"missing file in missing dir", filepath.Join(t.TempDir(), "nope", "agents.yaml")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, existed, err := Load(tt.path)
			if err != nil {
				t.Fatalf("Load(missing) = %v, want nil error (dev-mode default)", err)
			}
			if existed {
				t.Error("existed = true, want false")
			}
			if cfg == nil || len(cfg.Agents) != 0 {
				t.Errorf("cfg = %+v, want empty non-nil config", cfg)
			}
		})
	}
}

func TestLoadUnreadablePath(t *testing.T) {
	// A directory cannot be read as a file: this is an error, but not
	// "missing" — the caller must not silently run with no rules.
	cfg, existed, err := Load(t.TempDir())
	if err == nil {
		t.Fatalf("Load(directory) succeeded with %+v", cfg)
	}
	if existed {
		t.Error("existed = true for a directory, want false")
	}
}
