// internal/policy/policy.go
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"netweaver/internal/rules"
	"netweaver/internal/types"
)

type fileFormat struct {
	DefaultPolicy string `json:"default_policy"`
}

// Manager resolves the effective policy for a PID and persists the global
// default policy in a settings file.
type Manager struct {
	mu    sync.RWMutex
	path  string
	store *rules.Store
	def   string
	byPID map[int]string
}

func NewManager(path string, store *rules.Store) *Manager {
	return &Manager{
		path:  path,
		store: store,
		def:   types.PolicyFailover,
		byPID: make(map[int]string),
	}
}

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading policy settings: %w", err)
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing policy settings: %w", err)
	}
	if f.DefaultPolicy == types.PolicyStrict {
		m.def = types.PolicyStrict
	} else {
		m.def = types.PolicyFailover
	}
	return nil
}

func (m *Manager) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileFormat{DefaultPolicy: m.def}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, append(data, '\n'), 0o644)
}

func (m *Manager) Default() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.def
}

func (m *Manager) SetDefault(p string) error {
	if !types.ValidPolicy(p) || p == "" {
		return fmt.Errorf("unknown policy %q (use failover or strict)", p)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.def = p
	return m.saveLocked()
}

// Set records the policy chosen for a PID at assignment time.
func (m *Manager) Set(pid int, p string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byPID[pid] = p
}

func (m *Manager) Forget(pid int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byPID, pid)
}

// Resolve returns the policy for a PID: explicit assignment policy, else a
// matching rule's policy, else the global default.
func (m *Manager) Resolve(pid int) string {
	m.mu.RLock()
	explicit, ok := m.byPID[pid]
	store := m.store
	def := m.def
	m.mu.RUnlock()
	if ok {
		return explicit
	}
	if store != nil {
		name := procFile(pid, "comm")
		cmdline := strings.ReplaceAll(procFile(pid, "cmdline"), "\x00", " ")
		if rule, matched := store.Match(name, cmdline); matched {
			return rule.NormalizedPolicy()
		}
	}
	return def
}

func procFile(pid int, name string) string {
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
