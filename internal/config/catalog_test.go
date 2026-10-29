package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAttachRules(t *testing.T) {
	rules := AttachRules([]int{42}, []string{"claude"}, []string{"/usr/bin/x*"})
	if len(rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(rules))
	}
	if rules[0].Match.K8SLabel != "__attach_pid__" || rules[0].Match.Cgroup != "42" {
		t.Errorf("pid rule = %+v", rules[0])
	}
}

func TestMergeDedupesAndIndexes(t *testing.T) {
	base := &File{Agents: []Agent{{Name: "a", Match: Match{ExecPath: "/bin/a"}}}}
	out := Merge(base, []Agent{
		{Name: "a", Match: Match{ExecPath: "/bin/a"}},
		{Name: "b", Match: Match{ExecPath: "/bin/b"}},
	})
	if len(out.Agents) != 2 {
		t.Fatalf("merged = %d, want 2", len(out.Agents))
	}
	for i, a := range out.Agents {
		if a.Index != i {
			t.Errorf("agent %q index = %d, want %d", a.Name, a.Index, i)
		}
	}
}

func TestCatalogSubset(t *testing.T) {
	// Unknown names yield nothing; aider (interpreter rule) always yields.
	if got := Catalog([]string{"no-such-agent"}); len(got) != 0 {
		t.Errorf("unknown subset = %v, want empty", got)
	}
	found := false
	for _, a := range Catalog([]string{"aider"}) {
		if a.Name == "aider" {
			found = true
		}
	}
	if !found {
		t.Error("aider catalog entry missing")
	}
}

func stubEffectiveHome(t *testing.T, euid int, home string, lookup func(string) (string, bool)) {
	t.Helper()
	origEuid, origHome, origLookup := geteuidFn, userHomeFn, lookupHomeFn
	geteuidFn = func() int { return euid }
	userHomeFn = func() (string, error) { return home, nil }
	if lookup != nil {
		lookupHomeFn = lookup
	}
	t.Cleanup(func() { geteuidFn, userHomeFn, lookupHomeFn = origEuid, origHome, origLookup })
}

func installFakeClaude(t *testing.T, home string) string {
	t.Helper()
	p := filepath.Join(home, ".local", "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func hasExecPath(agents []Agent, want string) bool {
	for _, a := range agents {
		if a.Match.ExecPath == want {
			return true
		}
	}
	return false
}

func TestCatalogFindsClaudeInUserHome(t *testing.T) {
	home := t.TempDir()
	want := installFakeClaude(t, home)
	t.Setenv("SUDO_USER", "")
	stubEffectiveHome(t, 1000, home, nil)
	if got := Catalog([]string{"claude-code"}); !hasExecPath(got, want) {
		t.Errorf("Catalog(claude-code) = %v, want a rule for %s", got, want)
	}
}

// The loader runs under sudo, where $HOME is root's — but agent CLIs
// live in the invoking user's home. Catalog must resolve SUDO_USER's
// home, not root's (regression: --catalog-only claude-code found 0
// rules on a host where claude was at ~/.local/bin/claude).
func TestCatalogUsesSudoUserHome(t *testing.T) {
	home := t.TempDir()
	want := installFakeClaude(t, home)
	t.Setenv("SUDO_USER", "alice")
	stubEffectiveHome(t, 0, "/root", func(user string) (string, bool) {
		if user == "alice" {
			return home, true
		}
		return "", false
	})
	if got := Catalog([]string{"claude-code"}); !hasExecPath(got, want) {
		t.Errorf("Catalog(claude-code) under sudo = %v, want a rule for %s", got, want)
	}
}

func TestCatalogFallsBackWhenSudoUserUnknown(t *testing.T) {
	home := t.TempDir()
	want := installFakeClaude(t, home)
	t.Setenv("SUDO_USER", "ghost")
	stubEffectiveHome(t, 0, home, func(string) (string, bool) { return "", false })
	if got := Catalog([]string{"claude-code"}); !hasExecPath(got, want) {
		t.Errorf("Catalog(claude-code) with unknown SUDO_USER = %v, want fallback rule for %s", got, want)
	}
}
