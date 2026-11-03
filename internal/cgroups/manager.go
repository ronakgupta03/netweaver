// internal/cgroups/manager.go
package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

func (m *Manager) Teardown() error {
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	return os.RemoveAll(baseDir)
}
