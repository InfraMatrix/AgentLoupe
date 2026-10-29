package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Built-in catalog of known agent harnesses. Entries whose paths do not
// exist on this host are skipped silently (unlike user config rules,
// which warn), so --catalog is safe on any machine.
type catalogEntry struct {
	Name  string
	Kind  string
	Match Match
	Paths []string // absolute paths, existence-checked before the entry is kept
	// HomePaths are relative to the effective user's home (see
	// effectiveHome) — most agent CLIs install per-user, e.g.
	// ~/.local/bin/claude.
	HomePaths []string
	Bin       string // executable name, for the PATH lookup fallback
}

var catalog = []catalogEntry{
	{Name: "claude-code", Kind: "tool", Bin: "claude", Paths: []string{
		"/usr/local/bin/claude", "/usr/bin/claude",
	}, HomePaths: []string{
		".local/bin/claude", ".local/share/claude/claude",
	}},
	{Name: "codex", Kind: "tool", Bin: "codex", Paths: []string{
		"/usr/local/bin/codex", "/usr/bin/codex",
	}, HomePaths: []string{
		".local/bin/codex",
	}},
	{Name: "gemini-cli", Kind: "tool", Bin: "gemini", Paths: []string{
		"/usr/local/bin/gemini", "/usr/bin/gemini",
	}, HomePaths: []string{
		".local/bin/gemini",
	}},
	{Name: "cursor", Kind: "tool", Bin: "cursor", Paths: []string{
		"/usr/local/bin/cursor", "/usr/bin/cursor", "/opt/cursor/cursor",
	}, HomePaths: []string{
		".local/bin/cursor",
	}},
	{Name: "aider", Kind: "tool", Match: Match{Interpreter: "/usr/bin/python3", ArgvContains: "aider"}},
}

// Test seams: Catalog runs on hosts and under sudo, neither of which a
// unit test can reproduce, so the environment lookups go through vars.
var (
	geteuidFn    = os.Geteuid
	userHomeFn   = os.UserHomeDir
	lookupHomeFn = passwdHome
)

// effectiveHome returns the home directory whose per-user installs the
// catalog should search. The loader normally runs under sudo (it needs
// root for BPF), where $HOME is root's home — but agent CLIs are
// installed in the invoking user's home, so when SUDO_USER names a
// non-root user, resolve that user's home from /etc/passwd instead.
// Falls back to the process home when there is no usable SUDO_USER.
func effectiveHome() string {
	if geteuidFn() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			if home, ok := lookupHomeFn(sudoUser); ok && home != "" {
				return home
			}
		}
	}
	home, _ := userHomeFn()
	return home
}

// passwdHome returns the home directory for user from /etc/passwd.
func passwdHome(user string) (string, bool) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		// name:passwd:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) >= 6 && fields[0] == user {
			return fields[5], fields[5] != ""
		}
	}
	return "", false
}

// Catalog returns preset agents, optionally restricted to the named
// subset. Interpreter entries are kept as-is (argv confirmation happens
// at runtime); binary entries expand to one rule per existing path.
func Catalog(only []string) []Agent {
	want := map[string]bool{}
	for _, n := range only {
		want[n] = true
	}
	home := effectiveHome()
	var out []Agent
	add := func(a Agent) {
		for _, e := range out {
			if e.Name == a.Name && e.Match == a.Match {
				return
			}
		}
		out = append(out, a)
	}
	for _, ce := range catalog {
		if len(want) > 0 && !want[ce.Name] {
			continue
		}
		if ce.Match.Interpreter != "" {
			add(Agent{Name: ce.Name, Kind: ce.Kind, Match: ce.Match})
			continue
		}
		paths := append([]string{}, ce.Paths...)
		if home != "" {
			for _, rel := range ce.HomePaths {
				paths = append(paths, filepath.Join(home, rel))
			}
		}
		if ce.Bin != "" {
			if p, err := lookPath(ce.Bin); err == nil {
				paths = append(paths, p)
			}
		}
		seen := map[string]bool{}
		for _, p := range paths {
			if seen[p] {
				continue
			}
			seen[p] = true
			if _, err := os.Stat(p); err != nil {
				continue
			}
			add(Agent{Name: ce.Name, Kind: ce.Kind, Match: Match{ExecPath: p}})
		}
	}
	// Node-based harnesses (Codex/Gemini CLIs ship as node scripts):
	// match node by argv marker via the interpreter-confirmation path.
	if node, err := lookPath("node"); err == nil {
		for _, n := range []struct{ name, marker string }{
			{"codex", "@openai/codex"}, {"gemini-cli", "@google/gemini-cli"},
		} {
			if len(want) > 0 && !want[n.name] {
				continue
			}
			add(Agent{Name: n.name + "-node", Kind: "tool",
				Match: Match{Interpreter: node, ArgvContains: n.marker}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	for i := range out {
		out[i].Index = i
	}
	return out
}

var lookPath = func(name string) (string, error) {
	for _, dir := range []string{"/usr/local/bin", "/usr/bin", "/bin"} {
		p := dir + "/" + name
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if home := effectiveHome(); home != "" {
		p := fmt.Sprintf("%s/.local/bin/%s", home, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("not found")
}

// AttachRules builds synthetic config rules for --attach-pid/-comm/-exe.
// The kernel rule maps only understand (dev,ino)/cgroup, so ad-hoc
// targets are matched by the /proc adoption path (matchProcEntry
// recognises the marker encodings below).
func AttachRules(pids []int, comms, exes []string) []Agent {
	var out []Agent
	for _, pid := range pids {
		out = append(out, Agent{
			Name: fmt.Sprintf("pid-%d", pid), Kind: "tool",
			Match: Match{K8SLabel: "__attach_pid__", Cgroup: fmt.Sprintf("%d", pid)},
		})
	}
	for _, c := range comms {
		out = append(out, Agent{
			Name: "comm-" + c, Kind: "tool",
			Match: Match{K8SLabel: "__attach_comm__", Cgroup: c},
		})
	}
	for _, e := range exes {
		out = append(out, Agent{
			Name: "exe-" + baseOf(e), Kind: "tool",
			Match: Match{K8SLabel: "__attach_exe__", Cgroup: e},
		})
	}
	return out
}

func baseOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// Merge combines base config agents with extra (catalog/attach) agents,
// de-duplicated by name+match, re-indexed. Catalog agents whose binary
// also appears as a normal exec_path rule are still usable at exec time
// because populateRules resolves every ExecPath entry.
func Merge(base *File, extra []Agent) *File {
	out := &File{Agents: append([]Agent{}, base.Agents...)}
	seen := map[string]bool{}
	for _, a := range out.Agents {
		seen[a.Name+"\x00"+fmt.Sprint(a.Match)] = true
	}
	for _, a := range extra {
		k := a.Name + "\x00" + fmt.Sprint(a.Match)
		if seen[k] {
			continue
		}
		seen[k] = true
		out.Agents = append(out.Agents, a)
	}
	// Attach/catalog rules matched only via /proc adoption carry marker
	// matches that populateRules would try (and fail) to resolve as
	// paths; give them an exec_path view too when possible: adoption is
	// the primary path, exec-time matching comes free for ExecPath ones.
	for i := range out.Agents {
		out.Agents[i].Index = i
		if len(out.Agents[i].Name) > 31 {
			out.Agents[i].Name = out.Agents[i].Name[:31]
		}
	}
	return out
}
