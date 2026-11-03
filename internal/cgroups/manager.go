// internal/cgroups/manager.go
package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var ifaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,16}$`)

type Manager struct {
	cgroupRoot string
}

func NewManager() *Manager {
	return &Manager{cgroupRoot: "/sys/fs/cgroup"}
}

func NewManagerWithRoot(root string) *Manager {
	return &Manager{cgroupRoot: root}
}

func (m *Manager) InterfaceCgroupPath(iface string) (string, error) {
	if !ifaceRegex.MatchString(iface) {
		return "", fmt.Errorf("invalid interface name: %q", iface)
	}
	return filepath.Join(m.cgroupRoot, "netweaver", iface), nil
}

func (m *Manager) InitHierarchy() error {
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	defaultDir := filepath.Join(baseDir, "default")
	if err := os.MkdirAll(defaultDir, 0755); err != nil {
		return fmt.Errorf("failed creating cgroup directory %s: %w", defaultDir, err)
	}
	// Migrate any existing processes trapped in netweaver back to root cgroup
	m.MigrateAllToRoot()
	return nil
}

func (m *Manager) EnsureInterfaceCgroup(iface string) error {
	path, err := m.InterfaceCgroupPath(iface)
	if err != nil {
		return err
	}
	return os.MkdirAll(path, 0755)
}

func (m *Manager) AssignPID(iface string, pid int) error {
	if pid <= 100 {
		return fmt.Errorf("cannot assign system process PID %d", pid)
	}
	path, err := m.InterfaceCgroupPath(iface)
	if err != nil {
		return err
	}
	procsFile := filepath.Join(path, "cgroup.procs")
	f, err := os.OpenFile(procsFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open cgroup.procs: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(strconv.Itoa(pid) + "\n")
	return err
}

func (m *Manager) ResetPID(pid int) error {
	defaultProcs := filepath.Join(m.cgroupRoot, "netweaver", "default", "cgroup.procs")
	return os.WriteFile(defaultProcs, []byte(strconv.Itoa(pid)+"\n"), 0644)
}

func (m *Manager) MigrateAllToRoot() {
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return
	}

	rootProcs := filepath.Join(m.cgroupRoot, "cgroup.procs")
	for _, entry := range entries {
		if entry.IsDir() {
			procsPath := filepath.Join(baseDir, entry.Name(), "cgroup.procs")
			if data, err := os.ReadFile(procsPath); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					pid := strings.TrimSpace(line)
					if pid != "" {
						f, openErr := os.OpenFile(rootProcs, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
						if openErr == nil {
							_, _ = f.WriteString(pid + "\n")
							_ = f.Close()
						}
					}
				}
			}
		}
	}
}

func (m *Manager) Teardown() error {
	m.MigrateAllToRoot()
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	entries, err := os.ReadDir(baseDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				_ = os.Remove(filepath.Join(baseDir, entry.Name()))
			}
		}
	}
	return os.RemoveAll(baseDir)
}
