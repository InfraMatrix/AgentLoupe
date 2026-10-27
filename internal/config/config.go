// Package config parses agents.yaml. The loader resolves these rules into
// kernel maps; the kernel never sees paths, only (dev, inode) and cgroup IDs.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Match struct {
	ExecPath      string `yaml:"exec_path"`
	Interpreter   string `yaml:"interpreter"`
	ArgvContains  string `yaml:"argv_contains"`
	Cgroup        string `yaml:"cgroup"`
	K8SLabel      string `yaml:"k8s_label"`
}

type Agent struct {
	Name  string `yaml:"name"`
	Kind  string `yaml:"kind"` // tool | service
	Match Match  `yaml:"match"`

	// Index is the rule_id written into kernel agent_ref values.
	Index int `yaml:"-"`
}

type File struct {
	Agents []Agent `yaml:"agents"`
}

// Load reads and validates the config. A missing file is not fatal in dev
// mode: it yields an empty config and existed=false so the caller can warn.
func Load(path string) (cfg *File, existed bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, false, nil
		}
		return nil, false, err
	}
	cfg = &File{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, true, fmt.Errorf("parse %s: %w", path, err)
	}
	for i := range cfg.Agents {
		a := &cfg.Agents[i]
		a.Index = i
		if a.Name == "" {
			return nil, true, fmt.Errorf("agents[%d]: name is required", i)
		}
		if len(a.Name) > 31 {
			return nil, true, fmt.Errorf("agent %q: name exceeds 31 bytes (kernel AGENT_NAME_LEN)", a.Name)
		}
		m := a.Match
		switch {
		case m.ExecPath != "":
		case m.Interpreter != "" && m.ArgvContains != "":
		case m.Cgroup != "":
		case m.K8SLabel != "":
		default:
			return nil, true, fmt.Errorf("agent %q: match must set exec_path, interpreter+argv_contains, cgroup, or k8s_label", a.Name)
		}
	}
	return cfg, true, nil
}

// InterpreterRules returns agents that confirm provisional sessions by argv.
func (f *File) InterpreterRules() []Agent {
	var out []Agent
	for _, a := range f.Agents {
		if a.Match.Interpreter != "" && a.Match.ArgvContains != "" {
			out = append(out, a)
		}
	}
	return out
}

// WatchedPaths returns every filesystem path whose identity must be
// re-resolved when it changes (binary upgrades replace the inode).
func (f *File) WatchedPaths() []string {
	var out []string
	for _, a := range f.Agents {
		if a.Match.ExecPath != "" {
			out = append(out, a.Match.ExecPath)
		}
		if a.Match.Interpreter != "" {
			out = append(out, a.Match.Interpreter)
		}
	}
	return out
}
