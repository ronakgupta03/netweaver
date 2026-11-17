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

// ValidIfaceName reports whether iface is a valid NetWeaver interface/cgroup name.
func ValidIfaceName(iface string) bool {
	return ifaceRegex.MatchString(iface)
}

func (m *Manager) InterfaceCgroupPath(iface string) (string, error) {
	if !ifaceRegex.MatchString(iface) {
		return "", fmt.Errorf("invalid interface name: %q", iface)
	}
	return filepath.Join(m.cgroupRoot, "netweaver", iface), nil
}

// ProcessCgroupPath returns the leaf cgroup path `netweaver/<iface>/p<pid>`
// used for per-process rate limiting and eBPF telemetry while keeping level-2
// `netweaver/<iface>` nftables matching intact.
func (m *Manager) ProcessCgroupPath(iface string, pid int) (string, error) {
	ifacePath, err := m.InterfaceCgroupPath(iface)
	if err != nil {
		return "", err
	}
	if pid <= 0 {
		return "", fmt.Errorf("invalid PID %d", pid)
	}
	return filepath.Join(ifacePath, fmt.Sprintf("p%d", pid)), nil
}

func (m *Manager) InitHierarchy() error {
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	defaultDir := filepath.Join(baseDir, DefaultCgroup)
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

// EnsureProcessCgroup creates and returns the leaf cgroup `netweaver/<iface>/p<pid>`.
func (m *Manager) EnsureProcessCgroup(iface string, pid int) (string, error) {
	if pid <= 100 {
		return "", fmt.Errorf("cannot assign system process PID %d", pid)
	}
	subPath, err := m.ProcessCgroupPath(iface, pid)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(subPath, 0755); err != nil {
		return "", err
	}
	return subPath, nil
}

// BlockedCgroup is the quarantine group whose traffic nftables/eBPF drops.
const BlockedCgroup = "blocked"

// DefaultCgroup is the unrouted fallback group for unassigned processes.
const DefaultCgroup = "default"

func readProcsFile(procsPath string) ([]int, error) {
	data, err := os.ReadFile(procsPath)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func containsPID(procsPath string, target int) bool {
	pids, err := readProcsFile(procsPath)
	if err != nil {
		return false
	}
	for _, pid := range pids {
		if pid == target {
			return true
		}
	}
	return false
}

// PIDs lists process IDs currently attached to an interface cgroup (including
// any per-process leaf sub-cgroups under it).
func (m *Manager) PIDs(iface string) ([]int, error) {
	path, err := m.InterfaceCgroupPath(iface)
	if err != nil {
		return nil, err
	}
	pids, err := readProcsFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	seen := make(map[int]bool, len(pids))
	for _, pid := range pids {
		seen[pid] = true
	}
	if entries, dirErr := os.ReadDir(path); dirErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			subPIDs, subErr := readProcsFile(filepath.Join(path, entry.Name(), "cgroup.procs"))
			if subErr != nil {
				continue
			}
			for _, pid := range subPIDs {
				if !seen[pid] {
					seen[pid] = true
					pids = append(pids, pid)
				}
			}
		}
	}
	return pids, nil
}

// EnsureBlockedCgroup creates the quarantine cgroup used by strict policies.
func (m *Manager) EnsureBlockedCgroup() error {
	return os.MkdirAll(filepath.Join(m.cgroupRoot, "netweaver", BlockedCgroup), 0755)
}

// Block moves a PID into the quarantine cgroup.
func (m *Manager) Block(pid int) error {
	return m.AssignPID(BlockedCgroup, pid)
}

// IsBlocked reports whether pid is currently placed in the quarantine cgroup.
func (m *Manager) IsBlocked(pid int) bool {
	if pid <= 0 {
		return false
	}
	blockedDir := filepath.Join(m.cgroupRoot, "netweaver", BlockedCgroup)
	if containsPID(filepath.Join(blockedDir, "cgroup.procs"), pid) {
		return true
	}
	if entries, err := os.ReadDir(blockedDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && containsPID(filepath.Join(blockedDir, entry.Name(), "cgroup.procs"), pid) {
				return true
			}
		}
	}
	if m.cgroupRoot == "/sys/fs/cgroup" {
		return readProcCgroupName(pid) == BlockedCgroup
	}
	return false
}

// AssignedCgroup returns the top-level NetWeaver cgroup name (such as an
// interface name, "blocked", or "default") that pid currently belongs to, or ""
// if pid is not in any NetWeaver cgroup.
func (m *Manager) AssignedCgroup(pid int) string {
	if pid <= 0 {
		return ""
	}
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	if entries, err := os.ReadDir(baseDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dir := filepath.Join(baseDir, entry.Name())
			if containsPID(filepath.Join(dir, "cgroup.procs"), pid) {
				return entry.Name()
			}
			if subEntries, subErr := os.ReadDir(dir); subErr == nil {
				for _, sub := range subEntries {
					if sub.IsDir() && containsPID(filepath.Join(dir, sub.Name(), "cgroup.procs"), pid) {
						return entry.Name()
					}
				}
			}
		}
	}
	if m.cgroupRoot == "/sys/fs/cgroup" {
		return readProcCgroupName(pid)
	}
	return ""
}

func readProcCgroupName(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	content := string(data)
	idx := strings.Index(content, "/netweaver/")
	if idx == -1 {
		return ""
	}
	sub := content[idx+len("/netweaver/"):]
	if newline := strings.Index(sub, "\n"); newline != -1 {
		sub = sub[:newline]
	}
	if slash := strings.Index(sub, "/"); slash != -1 {
		sub = sub[:slash]
	}
	return strings.TrimSpace(sub)
}

func (m *Manager) AssignPID(iface string, pid int) error {
	if pid <= 100 {
		return fmt.Errorf("cannot assign system process PID %d", pid)
	}
	path, err := m.InterfaceCgroupPath(iface)
	if err != nil {
		return err
	}
	return writePIDToProcs(filepath.Join(path, "cgroup.procs"), pid)
}

// AssignPIDToPath moves pid into a specific cgroup directory under netweaver/.
func (m *Manager) AssignPIDToPath(cgroupPath string, pid int) error {
	if pid <= 100 {
		return fmt.Errorf("cannot assign system process PID %d", pid)
	}
	baseDir := filepath.Clean(filepath.Join(m.cgroupRoot, "netweaver"))
	clean := filepath.Clean(cgroupPath)
	rel, err := filepath.Rel(baseDir, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("invalid cgroup path %q", cgroupPath)
	}
	return writePIDToProcs(filepath.Join(clean, "cgroup.procs"), pid)
}

func writePIDToProcs(procsFile string, pid int) error {
	f, err := os.OpenFile(procsFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open cgroup.procs: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(strconv.Itoa(pid) + "\n")
	return err
}

func (m *Manager) ResetPID(pid int) error {
	defaultProcs := filepath.Join(m.cgroupRoot, "netweaver", DefaultCgroup, "cgroup.procs")
	return os.WriteFile(defaultProcs, []byte(strconv.Itoa(pid)+"\n"), 0644)
}

// CleanupDeadProcessCgroups removes per-process leaf cgroups (`netweaver/<iface>/p<pid>`)
// whose owner PID no longer exists and which contain no live PIDs.
func (m *Manager) CleanupDeadProcessCgroups() error {
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var firstErr error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ifaceDir := filepath.Join(baseDir, entry.Name())
		subEntries, err := os.ReadDir(ifaceDir)
		if err != nil {
			continue
		}
		for _, sub := range subEntries {
			if !sub.IsDir() || !strings.HasPrefix(sub.Name(), "p") {
				continue
			}
			pid, err := strconv.Atoi(sub.Name()[1:])
			if err != nil || pid <= 0 {
				continue
			}
			subPath := filepath.Join(ifaceDir, sub.Name())
			if pidAlive(pid) {
				continue
			}
			if pids, err := readProcsFile(filepath.Join(subPath, "cgroup.procs")); err == nil {
				hasLive := false
				for _, p := range pids {
					if pidAlive(p) {
						hasLive = true
						break
					}
				}
				if hasLive {
					continue
				}
			}
			var rmErr error
			if m.cgroupRoot == "/sys/fs/cgroup" {
				rmErr = os.Remove(subPath)
			} else {
				rmErr = os.RemoveAll(subPath)
			}
			if rmErr != nil && !os.IsNotExist(rmErr) && firstErr == nil {
				firstErr = rmErr
			}
		}
	}
	return firstErr
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return err == nil
}

func migrateProcsFileToRoot(procsPath, rootProcs string) {
	data, err := os.ReadFile(procsPath)
	if err != nil {
		return
	}
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

func (m *Manager) MigrateAllToRoot() {
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return
	}

	rootProcs := filepath.Join(m.cgroupRoot, "cgroup.procs")
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(baseDir, entry.Name())
		if subEntries, subErr := os.ReadDir(dir); subErr == nil {
			for _, sub := range subEntries {
				if sub.IsDir() {
					migrateProcsFileToRoot(filepath.Join(dir, sub.Name(), "cgroup.procs"), rootProcs)
				}
			}
		}
		migrateProcsFileToRoot(filepath.Join(dir, "cgroup.procs"), rootProcs)
	}
}

func (m *Manager) Teardown() error {
	m.MigrateAllToRoot()
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	entries, err := os.ReadDir(baseDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dir := filepath.Join(baseDir, entry.Name())
			if subEntries, subErr := os.ReadDir(dir); subErr == nil {
				for _, sub := range subEntries {
					if sub.IsDir() {
						_ = os.Remove(filepath.Join(dir, sub.Name()))
					}
				}
			}
			_ = os.Remove(dir)
		}
	}
	return os.RemoveAll(baseDir)
}
