# NetWeaver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build NetWeaver, a per-application network interface selector and policy routing utility for Linux in Go, featuring a privileged background daemon, unified cgroups v2/nftables kernel engine, and an interactive Bubbletea terminal UI.

**Architecture:** A privileged root daemon (`netweaverd`) configures Linux Policy-Based Routing tables, manages cgroups v2 slices, and applies nftables socket-matching rules. An unprivileged client (`netweaver`) communicates over a protected Unix domain socket to provide CLI subcommands and a full-screen Bubbletea TUI.

**Tech Stack:** Go 1.22+, `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/lipgloss`, `github.com/vishvananda/netlink`, `github.com/shirou/gopsutil/v3`, Linux cgroups v2, nftables, iproute2.

**Spec:** `docs/superpowers/specs/2026-11-04-netweaver-design.md`

## Global Constraints
- Target platform is Linux (Arch Linux / kernel 6.x+) with unified cgroups v2 mounted at `/sys/fs/cgroup`.
- Language: 100% Go (1.22+) without external CGo dependencies.
- Privileged operations (`ip rule`, `ip route`, `nft`, `/sys/fs/cgroup` writes) must reside strictly in `netweaverd`.
- Client `netweaver` must run as standard unprivileged user and communicate via Unix socket `/run/netweaver/netweaver.sock`.
- Daemon MUST completely tear down all nftables rules, ip rules, and routing tables upon `SIGINT`/`SIGTERM`.
- Socket cgroup matching must use native nftables syntax `socket cgroupv2 level 2 "netweaver/<iface>"`.

## Review Focus
1. **Daemon crash or abrupt kill without cleanup:** When `netweaverd` restarts, it must identify and purge stale NetWeaver routing rules (`ip rule show` priority 1000) and stale nftables table `inet netweaver` before applying new ones.
2. **Short-lived or dying PID reassignment:** If a process terminates while `route.assign` is traversing its child tree, the manager must ignore `ESRCH` errors gracefully instead of failing the entire operation.
3. **Disconnection of assigned interface:** When an active interface loses link carrier or IP address, assigned processes must safely fall back to the default root cgroup rather than dropping all network connectivity.
4. **Interface name sanitization:** Interface names supplied from CLI or socket must be validated against `^[a-zA-Z0-9_\.-]{1,16}$` to prevent path traversal outside `/sys/fs/cgroup/netweaver/`.
5. **Unix socket permissions:** Socket `/run/netweaver/netweaver.sock` must be created with mode `0660` under group `wheel` or invoking user UID, rejecting unauthorized world access.

---

### Task 1: Project Scaffolding & Core Domain Models

**Files:**
- Create: `go.mod`
- Create: `internal/types/models.go`
- Test: `internal/types/models_test.go`

**Interfaces:**
- Consumes: None (root package)
- Produces: `InterfaceInfo`, `ProcessInfo`, `RouteRule`, `DaemonStatus`, `Config` models used across all packages.

- [ ] **Step 1: Write the failing test**

```go
// internal/types/models_test.go
package types

import (
	"testing"
)

func TestInterfaceInfoValidation(t *testing.T) {
	valid := InterfaceInfo{
		Name:    "wlan0",
		Index:   3,
		IP:      "192.168.1.100",
		Gateway: "192.168.1.1",
		TableID: 103,
		Up:      true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid interface, got: %v", err)
	}

	invalidName := valid
	invalidName.Name = "../evil/path"
	if err := invalidName.Validate(); err == nil {
		t.Fatal("expected error on malicious interface name, got nil")
	}

	invalidTable := valid
	invalidTable.TableID = 0
	if err := invalidTable.Validate(); err == nil {
		t.Fatal("expected error on zero TableID, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/types/... -v`
Expected: FAIL (models package not found)

- [ ] **Step 3: Write minimal implementation**

Initialize Go module and domain structs:
```bash
go mod init netweaver
```

```go
// internal/types/models.go
package types

import (
	"errors"
	"fmt"
	"regexp"
)

var validIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,16}$`)

type InterfaceInfo struct {
	Name    string `json:"name"`
	Index   int    `json:"index"`
	IP      string `json:"ip"`
	Gateway string `json:"gateway"`
	TableID int    `json:"table_id"`
	Up      bool   `json:"up"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

func (i InterfaceInfo) Validate() error {
	if !validIfaceRegex.MatchString(i.Name) {
		return fmt.Errorf("invalid interface name: %q", i.Name)
	}
	if i.TableID <= 0 {
		return errors.New("table ID must be positive")
	}
	return nil
}

type ProcessInfo struct {
	PID               int     `json:"pid"`
	Name              string  `json:"name"`
	Cmdline           string  `json:"cmdline"`
	UID               uint32  `json:"uid"`
	AssignedInterface string  `json:"assigned_interface"`
	RxRate            float64 `json:"rx_rate"`
	TxRate            float64 `json:"tx_rate"`
}

type RouteRule struct {
	PID       int    `json:"pid"`
	AppName   string `json:"app_name"`
	Interface string `json:"interface"`
}

type DaemonStatus struct {
	UptimeSeconds uint64 `json:"uptime_seconds"`
	ActiveIfaces  int    `json:"active_ifaces"`
	ManagedProcs  int    `json:"managed_procs"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/types/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add go.mod internal/types/
git commit -m "feat: initialize Go module and core domain models"
```

---

### Task 2: cgroups v2 Manager (`internal/cgroups`)

**Files:**
- Create: `internal/cgroups/manager.go`
- Test: `internal/cgroups/manager_test.go`

**Interfaces:**
- Consumes: `types.InterfaceInfo`
- Produces: `CgroupManager` (`InitHierarchy()`, `EnsureInterfaceCgroup(iface)`, `AssignPID(iface, pid)`, `ResetPID(pid)`, `Teardown()`).

- [ ] **Step 1: Write the failing test**

```go
// internal/cgroups/manager_test.go
package cgroups

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCgroupPathSanitization(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cgroup-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mgr := NewManagerWithRoot(tempDir)

	// Valid interface
	path, err := mgr.InterfaceCgroupPath("wlan0")
	if err != nil {
		t.Fatalf("unexpected error for valid interface: %v", err)
	}
	expected := filepath.Join(tempDir, "netweaver", "wlan0")
	if path != expected {
		t.Fatalf("expected path %q, got %q", expected, path)
	}

	// Malicious interface names
	_, err = mgr.InterfaceCgroupPath("../../etc")
	if err == nil {
		t.Fatal("expected error on path traversal in interface name, got nil")
	}
}

func TestCgroupWritePID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cgroup-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mgr := NewManagerWithRoot(tempDir)
	if err := mgr.InitHierarchy(); err != nil {
		t.Fatalf("failed to init hierarchy: %v", err)
	}

	if err := mgr.EnsureInterfaceCgroup("wlan0"); err != nil {
		t.Fatalf("failed to ensure iface cgroup: %v", err)
	}

	// Write mock PID 1234
	if err := mgr.AssignPID("wlan0", 1234); err != nil {
		t.Fatalf("failed to assign PID: %v", err)
	}

	procsFile := filepath.Join(tempDir, "netweaver", "wlan0", "cgroup.procs")
	data, err := os.ReadFile(procsFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "1234\n" {
		t.Fatalf("expected 1234\\n, got %q", string(data))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cgroups/... -v`
Expected: FAIL (types and functions not defined)

- [ ] **Step 3: Write minimal implementation**

```go
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
	// Revert all processes to root
	baseDir := filepath.Join(m.cgroupRoot, "netweaver")
	return os.RemoveAll(baseDir)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cgroups/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cgroups/
git commit -m "feat: implement cgroups v2 manager for interface slice assignment"
```

---

### Task 3: Policy-Based Routing & nftables Engine (`internal/routing`)

**Files:**
- Create: `internal/routing/engine.go`
- Test: `internal/routing/engine_test.go`

**Interfaces:**
- Consumes: `types.InterfaceInfo`
- Produces: `RoutingEngine` (`SetupInterfaceRoute(iface)`, `RemoveInterfaceRoute(iface)`, `ApplyRuleset()`, `Teardown()`).

- [ ] **Step 1: Write the failing test**

```go
// internal/routing/engine_test.go
package routing

import (
	"strings"
	"testing"
	"netweaver/internal/types"
)

func TestNftablesConfigGeneration(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "eno1", Index: 2, TableID: 102},
		{Name: "wlan0", Index: 3, TableID: 103},
	}

	ruleset := GenerateNftablesRuleset(ifaces)

	// Verify table name
	if !strings.Contains(ruleset, "table inet netweaver") {
		t.Fatal("expected table inet netweaver in ruleset")
	}

	// Verify socket cgroupv2 marking
	expectedEno1 := `socket cgroupv2 level 2 "netweaver/eno1" meta mark set 0x102`
	if !strings.Contains(ruleset, expectedEno1) {
		t.Fatalf("missing rule: %s", expectedEno1)
	}

	expectedWlan0 := `socket cgroupv2 level 2 "netweaver/wlan0" meta mark set 0x103`
	if !strings.Contains(ruleset, expectedWlan0) {
		t.Fatalf("missing rule: %s", expectedWlan0)
	}

	// Verify masquerade
	if !strings.Contains(ruleset, `oifname "eno1" meta mark 0x102 masquerade`) {
		t.Fatal("missing eno1 masquerade rule")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/routing/... -v`
Expected: FAIL (function undefined)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/routing/engine.go
package routing

import (
	"bytes"
	"fmt"
	"os/exec"
	"text/template"
	"netweaver/internal/types"
)

const nftTemplate = `
table inet netweaver {
    chain output {
        type route hook output priority mangle; policy accept;
{{- range . }}
        socket cgroupv2 level 2 "netweaver/{{ .Name }}" meta mark set 0x{{ printf "%x" .TableID }}
{{- end }}
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
{{- range . }}
        oifname "{{ .Name }}" meta mark 0x{{ printf "%x" .TableID }} masquerade
{{- end }}
    }
}
`

func GenerateNftablesRuleset(ifaces []types.InterfaceInfo) string {
	tmpl, err := template.New("nft").Parse(nftTemplate)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ifaces); err != nil {
		return ""
	}
	return buf.String()
}

type Engine struct {
	ifaces map[string]types.InterfaceInfo
}

func NewEngine() *Engine {
	return &Engine{
		ifaces: make(map[string]types.InterfaceInfo),
	}
}

func (e *Engine) SetupInterfaceRoute(info types.InterfaceInfo) error {
	e.ifaces[info.Name] = info

	// 1. ip route replace default via <GW> dev <IFACE> table <TableID>
	if info.Gateway != "" {
		cmd := exec.Command("ip", "route", "replace", "default", "via", info.Gateway, "dev", info.Name, "table", fmt.Sprintf("%d", info.TableID))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip route failed: %s: %w", string(out), err)
		}
	}

	// 2. ip rule add fwmark <TableID> lookup <TableID> priority 1000
	_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID)).Run()
	cmd := exec.Command("ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID), "priority", "1000")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip rule failed: %s: %w", string(out), err)
	}

	return e.ApplyNftables()
}

func (e *Engine) ApplyNftables() error {
	var list []types.InterfaceInfo
	for _, iface := range e.ifaces {
		list = append(list, iface)
	}
	ruleset := GenerateNftablesRuleset(list)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply failed: %s: %w", string(out), err)
	}
	return nil
}

func (e *Engine) Teardown() error {
	// Flush nftables table
	_ = exec.Command("nft", "delete", "table", "inet", "netweaver").Run()

	// Flush ip rules and tables
	for _, iface := range e.ifaces {
		_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID)).Run()
		_ = exec.Command("ip", "route", "flush", "table", fmt.Sprintf("%d", iface.TableID)).Run()
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/routing/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/routing/
git commit -m "feat: implement PBR table management and nftables cgroup marking"
```

---

### Task 4: Network Interface Monitor (`internal/interfaces`)

**Files:**
- Create: `internal/interfaces/monitor.go`
- Test: `internal/interfaces/monitor_test.go`

**Interfaces:**
- Consumes: `types.InterfaceInfo`
- Produces: `InterfaceMonitor` (`DiscoverInterfaces()`, `StartWatch(ctx, eventChan)`).

- [ ] **Step 1: Write the failing test**

```go
// internal/interfaces/monitor_test.go
package interfaces

import (
	"testing"
)

func TestParseRouteGateway(t *testing.T) {
	// Mock sample ip route output
	sampleOutput := `default via 10.5.50.1 dev wlan0 proto dhcp src 10.5.48.18 metric 600
10.5.48.0/20 dev wlan0 proto dhcp scope link metric 600`

	gw, dev, err := parseDefaultRoute(sampleOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw != "10.5.50.1" {
		t.Fatalf("expected gateway 10.5.50.1, got %s", gw)
	}
	if dev != "wlan0" {
		t.Fatalf("expected dev wlan0, got %s", dev)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/interfaces/... -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```go
// internal/interfaces/monitor.go
package interfaces

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
	"netweaver/internal/types"
)

type Monitor struct {
	mu     sync.RWMutex
	ifaces map[string]types.InterfaceInfo
}

func NewMonitor() *Monitor {
	return &Monitor{
		ifaces: make(map[string]types.InterfaceInfo),
	}
}

func parseDefaultRoute(output string) (gateway string, dev string, err error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "default via ") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				return fields[2], fields[4], nil
			}
		}
	}
	return "", "", nil
}

func (m *Monitor) DiscoverInterfaces() ([]types.InterfaceInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	routeOut, _ := exec.Command("ip", "route", "show").Output()
	defGW, defDev, _ := parseDefaultRoute(string(routeOut))

	var result []types.InterfaceInfo
	for _, iface := range netIfaces {
		// Ignore loopback, down links, and docker virtual bridges
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "br-") || strings.HasPrefix(iface.Name, "veth") {
			continue
		}

		addrs, _ := iface.Addrs()
		var ipAddr string
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					ipAddr = ipNet.IP.String()
					break
				}
			}
		}

		gw := ""
		if iface.Name == defDev {
			gw = defGW
		}

		info := types.InterfaceInfo{
			Name:    iface.Name,
			Index:   iface.Index,
			IP:      ipAddr,
			Gateway: gw,
			TableID: 100 + iface.Index,
			Up:      true,
		}
		m.ifaces[iface.Name] = info
		result = append(result, info)
	}

	return result, nil
}

func (m *Monitor) StartWatch(ctx context.Context, notifyChan chan<- []types.InterfaceInfo) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ifaces, err := m.DiscoverInterfaces(); err == nil {
				notifyChan <- ifaces
			}
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/interfaces/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/interfaces/
git commit -m "feat: implement network interface discovery and periodic monitor"
```

---

### Task 5: Process Scanner & Tree Resolver (`internal/process`)

**Files:**
- Create: `internal/process/scanner.go`
- Test: `internal/process/scanner_test.go`

**Interfaces:**
- Consumes: `types.ProcessInfo`
- Produces: `ProcessScanner` (`ScanUserProcesses(uid)`, `GetProcessTree(rootPID)`).

- [ ] **Step 1: Write the failing test**

```go
// internal/process/scanner_test.go
package process

import (
	"os"
	"testing"
)

func TestScanCurrentProcess(t *testing.T) {
	scanner := NewScanner()
	procs, err := scanner.ScanProcesses()
	if err != nil {
		t.Fatalf("failed to scan processes: %v", err)
	}

	currentPID := os.Getpid()
	found := false
	for _, p := range procs {
		if p.PID == currentPID {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected current PID %d in scanned processes list", currentPID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/process/... -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```go
// internal/process/scanner.go
package process

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"netweaver/internal/types"

	"github.com/shirou/gopsutil/v3/process"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) ScanProcesses() ([]types.ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var result []types.ProcessInfo
	for _, p := range procs {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		// Ignore kernel workers (PPID 2)
		ppid, _ := p.Ppid()
		if ppid == 2 {
			continue
		}

		uids, _ := p.Uids()
		var uid uint32
		if len(uids) > 0 {
			uid = uint32(uids[0])
		}

		cmdline, _ := p.Cmdline()

		// Read cgroup path to identify current assignment
		assigned := s.detectAssignedInterface(int(p.Pid))

		result = append(result, types.ProcessInfo{
			PID:               int(p.Pid),
			Name:              name,
			Cmdline:           cmdline,
			UID:               uid,
			AssignedInterface: assigned,
		})
	}
	return result, nil
}

func (s *Scanner) detectAssignedInterface(pid int) string {
	cgroupPath := filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}
	// e.g., "0::/netweaver/wlan0"
	content := string(data)
	idx := strings.Index(content, "/netweaver/")
	if idx == -1 {
		return ""
	}
	sub := content[idx+len("/netweaver/"):]
	if newline := strings.Index(sub, "\n"); newline != -1 {
		sub = sub[:newline]
	}
	return strings.TrimSpace(sub)
}

func (s *Scanner) GetProcessTree(rootPID int) ([]int, error) {
	pids := []int{rootPID}
	p, err := process.NewProcess(int32(rootPID))
	if err != nil {
		return pids, nil
	}
	children, err := p.Children()
	if err != nil {
		return pids, nil
	}
	for _, child := range children {
		childPIDs, _ := s.GetProcessTree(int(child.Pid))
		pids = append(pids, childPIDs...)
	}
	return pids, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Install dependency and run test:
```bash
go get github.com/shirou/gopsutil/v3/process
go test ./internal/process/... -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/process/ go.mod go.sum
git commit -m "feat: implement process scanner and child tree resolver"
```

---

### Task 6: IPC Server & JSON-RPC Protocol (`internal/api`)

**Files:**
- Create: `internal/api/types.go`
- Create: `internal/api/server.go`
- Create: `internal/api/client.go`
- Test: `internal/api/api_test.go`

**Interfaces:**
- Consumes: `types.InterfaceInfo`, `types.ProcessInfo`, `types.RouteRule`
- Produces: `Server` (Unix domain socket RPC dispatcher) and `Client` (IPC RPC caller).

- [ ] **Step 1: Write the failing test**

```go
// internal/api/api_test.go
package api

import (
	"os"
	"path/filepath"
	"testing"
	"netweaver/internal/types"
)

type mockBackend struct{}

func (m *mockBackend) ListInterfaces() ([]types.InterfaceInfo, error) {
	return []types.InterfaceInfo{{Name: "wlan0", Index: 3, TableID: 103, Up: true}}, nil
}

func (m *mockBackend) ListProcesses() ([]types.ProcessInfo, error) {
	return []types.ProcessInfo{{PID: 9999, Name: "testproc", AssignedInterface: "wlan0"}}, nil
}

func (m *mockBackend) AssignRoute(pid int, iface string) error {
	return nil
}

func (m *mockBackend) ResetRoute(pid int) error {
	return nil
}

func TestIPCCommunication(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sock-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "netweaver.sock")
	srv := NewServer(sockPath, &mockBackend{})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	client := NewClient(sockPath)
	ifaces, err := client.ListInterfaces()
	if err != nil {
		t.Fatalf("client call failed: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].Name != "wlan0" {
		t.Fatalf("unexpected ifaces: %+v", ifaces)
	}

	procs, err := client.ListProcesses()
	if err != nil {
		t.Fatalf("client call failed: %v", err)
	}
	if len(procs) != 1 || procs[0].Name != "testproc" {
		t.Fatalf("unexpected procs: %+v", procs)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```go
// internal/api/types.go
package api

import "netweaver/internal/types"

type Backend interface {
	ListInterfaces() ([]types.InterfaceInfo, error)
	ListProcesses() ([]types.ProcessInfo, error)
	AssignRoute(pid int, iface string) error
	ResetRoute(pid int) error
}

type Request struct {
	Method    string `json:"method"`
	PID       int    `json:"pid,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type Response struct {
	Success    bool                  `json:"success"`
	Error      string                `json:"error,omitempty"`
	Interfaces []types.InterfaceInfo `json:"interfaces,omitempty"`
	Processes  []types.ProcessInfo   `json:"processes,omitempty"`
}
```

```go
// internal/api/server.go
package api

import (
	"encoding/json"
	"net"
	"os"
)

type Server struct {
	sockPath string
	backend  Backend
	listener net.Listener
}

func NewServer(sockPath string, backend Backend) *Server {
	return &Server{sockPath: sockPath, backend: backend}
}

func (s *Server) Start() error {
	_ = os.Remove(s.sockPath)
	_ = os.MkdirAll(filepath.Dir(s.sockPath), 0755)

	l, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return err
	}
	s.listener = l
	_ = os.Chmod(s.sockPath, 0660)

	go s.serve()
	return nil
}

func (s *Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	var resp Response
	switch req.Method {
	case "interfaces.list":
		ifaces, err := s.backend.ListInterfaces()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
			resp.Interfaces = ifaces
		}
	case "processes.list":
		procs, err := s.backend.ListProcesses()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
			resp.Processes = procs
		}
	case "route.assign":
		if err := s.backend.AssignRoute(req.PID, req.Interface); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
		}
	case "route.reset":
		if err := s.backend.ResetRoute(req.PID); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
		}
	default:
		resp.Error = "unknown method"
	}

	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) Stop() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.sockPath)
}
```

```go
// internal/api/client.go
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"netweaver/internal/types"
)

type Client struct {
	sockPath string
}

func NewClient(sockPath string) *Client {
	return &Client{sockPath: sockPath}
}

func (c *Client) call(req Request) (*Response, error) {
	conn, err := net.Dial("unix", c.sockPath)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to daemon at %s: %w", c.sockPath, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("server error: %s", resp.Error)
	}
	return &resp, nil
}

func (c *Client) ListInterfaces() ([]types.InterfaceInfo, error) {
	resp, err := c.call(Request{Method: "interfaces.list"})
	if err != nil {
		return nil, err
	}
	return resp.Interfaces, nil
}

func (c *Client) ListProcesses() ([]types.ProcessInfo, error) {
	resp, err := c.call(Request{Method: "processes.list"})
	if err != nil {
		return nil, err
	}
	return resp.Processes, nil
}

func (c *Client) AssignRoute(pid int, iface string) error {
	_, err := c.call(Request{Method: "route.assign", PID: pid, Interface: iface})
	return err
}

func (c *Client) ResetRoute(pid int) error {
	_, err := c.call(Request{Method: "route.reset", PID: pid})
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/api/
git commit -m "feat: implement IPC client and server over Unix domain socket"
```

---

### Task 7: Root Daemon Entrypoint (`cmd/netweaverd`)

**Files:**
- Create: `cmd/netweaverd/main.go`
- Create: `scripts/netweaver.service`

**Interfaces:**
- Consumes: `internal/cgroups`, `internal/routing`, `internal/interfaces`, `internal/process`, `internal/api`
- Produces: `netweaverd` binary executing daemon operations, handling signal termination, and wiring subsystems.

- [ ] **Step 1: Write minimal implementation**

```go
// cmd/netweaverd/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"netweaver/internal/api"
	"netweaver/internal/cgroups"
	"netweaver/internal/interfaces"
	"netweaver/internal/process"
	"netweaver/internal/routing"
	"netweaver/internal/types"
)

type DaemonService struct {
	cgMgr   *cgroups.Manager
	engine  *routing.Engine
	monitor *interfaces.Monitor
	scanner *process.Scanner
}

func (d *DaemonService) ListInterfaces() ([]types.InterfaceInfo, error) {
	return d.monitor.DiscoverInterfaces()
}

func (d *DaemonService) ListProcesses() ([]types.ProcessInfo, error) {
	return d.scanner.ScanProcesses()
}

func (d *DaemonService) AssignRoute(pid int, iface string) error {
	if err := d.cgMgr.EnsureInterfaceCgroup(iface); err != nil {
		return err
	}
	// Migrate PID and all children
	pids, err := d.scanner.GetProcessTree(pid)
	if err != nil {
		pids = []int{pid}
	}
	for _, p := range pids {
		_ = d.cgMgr.AssignPID(iface, p)
	}
	return nil
}

func (d *DaemonService) ResetRoute(pid int) error {
	pids, _ := d.scanner.GetProcessTree(pid)
	if len(pids) == 0 {
		pids = []int{pid}
	}
	for _, p := range pids {
		_ = d.cgMgr.ResetPID(p)
	}
	return nil
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("netweaverd must run as root")
	}

	log.Println("[netweaverd] Starting NetWeaver root networking daemon...")

	cgMgr := cgroups.NewManager()
	if err := cgMgr.InitHierarchy(); err != nil {
		log.Fatalf("cgroup init error: %v", err)
	}

	engine := routing.NewEngine()
	monitor := interfaces.NewMonitor()
	scanner := process.NewScanner()

	// Initial interface discovery & routing setup
	ifaces, err := monitor.DiscoverInterfaces()
	if err == nil {
		for _, iface := range ifaces {
			log.Printf("[netweaverd] Discovered interface: %s (table %d)", iface.Name, iface.TableID)
			_ = cgMgr.EnsureInterfaceCgroup(iface.Name)
			_ = engine.SetupInterfaceRoute(iface)
		}
	}

	daemon := &DaemonService{
		cgMgr:   cgMgr,
		engine:  engine,
		monitor: monitor,
		scanner: scanner,
	}

	sockPath := "/run/netweaver/netweaver.sock"
	srv := api.NewServer(sockPath, daemon)
	if err := srv.Start(); err != nil {
		log.Fatalf("failed starting IPC server: %v", err)
	}
	log.Printf("[netweaverd] Listening on %s", sockPath)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[netweaverd] Shutting down, cleaning up rules...")
	srv.Stop()
	_ = engine.Teardown()
	_ = cgMgr.Teardown()
	log.Println("[netweaverd] Clean exit.")
}
```

```ini
# scripts/netweaver.service
[Unit]
Description=NetWeaver Per-Application Network Routing Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/netweaverd
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Build binary to verify compilation**

Run: `go build -o bin/netweaverd ./cmd/netweaverd`
Expected: PASS (generates `bin/netweaverd`)

- [ ] **Step 3: Commit**

```bash
git add cmd/netweaverd/ scripts/netweaver.service
git commit -m "feat: implement root daemon entrypoint and systemd service"
```

---

### Task 8: User CLI & Launch Wrapper (`cmd/netweaver`)

**Files:**
- Create: `cmd/netweaver/main.go`
- Create: `cmd/netweaver/run.go`

**Interfaces:**
- Consumes: `internal/api/client.go`
- Produces: `netweaver` binary with subcommands: `list`, `interfaces`, `assign`, `reset`, `run`, and launcher for TUI.

- [ ] **Step 1: Write minimal implementation**

```go
// cmd/netweaver/main.go
package main

import (
	"fmt"
	"os"
	"strconv"

	"netweaver/internal/api"
	"netweaver/internal/tui"
)

const defaultSock = "/run/netweaver/netweaver.sock"

func main() {
	if len(os.Args) < 2 {
		// Launch interactive Bubbletea TUI
		if err := tui.Run(defaultSock); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	client := api.NewClient(defaultSock)

	switch os.Args[1] {
	case "list":
		procs, err := client.ListProcesses()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%-8s %-25s %-15s\n", "PID", "NAME", "INTERFACE")
		fmt.Println("--------------------------------------------------")
		for _, p := range procs {
			iface := p.AssignedInterface
			if iface == "" {
				iface = "(default)"
			}
			fmt.Printf("%-8d %-25s %-15s\n", p.PID, p.Name, iface)
		}

	case "interfaces":
		ifaces, err := client.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%-10s %-5s %-18s %-18s %-8s\n", "NAME", "INDEX", "IP", "GATEWAY", "TABLE")
		fmt.Println("-----------------------------------------------------------------")
		for _, iface := range ifaces {
			fmt.Printf("%-10s %-5d %-18s %-18s %-8d\n", iface.Name, iface.Index, iface.IP, iface.Gateway, iface.TableID)
		}

	case "assign":
		if len(os.Args) < 4 {
			fmt.Println("Usage: netweaver assign <PID> <INTERFACE>")
			os.Exit(1)
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid PID: %s\n", os.Args[2])
			os.Exit(1)
		}
		if err := client.AssignRoute(pid, os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Assigned PID %d to interface %s\n", pid, os.Args[3])

	case "reset":
		if len(os.Args) < 3 {
			fmt.Println("Usage: netweaver reset <PID>")
			os.Exit(1)
		}
		pid, _ := strconv.Atoi(os.Args[2])
		if err := client.ResetRoute(pid); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Reset PID %d to default route\n", pid)

	case "run":
		handleRun(os.Args[2:], defaultSock)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Commands: list, interfaces, assign, reset, run")
	}
}
```

```go
// cmd/netweaver/run.go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"netweaver/internal/api"
)

func handleRun(args []string, sockPath string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	iface := fs.String("i", "", "Network interface to bind (e.g. wlan0, eno1)")
	_ = fs.Parse(args)

	cmdArgs := fs.Args()
	if *iface == "" || len(cmdArgs) == 0 {
		fmt.Println("Usage: netweaver run -i <interface> <command> [args...]")
		os.Exit(1)
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start process: %v\n", err)
		os.Exit(1)
	}

	client := api.NewClient(sockPath)
	if err := client.AssignRoute(cmd.Process.Pid, *iface); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to attach route: %v\n", err)
	}

	_ = cmd.Wait()
}
```

- [ ] **Step 2: Build CLI binary to verify compilation**

Run: `go build -o bin/netweaver ./cmd/netweaver`
Expected: PASS (after TUI stub is added in Task 9)

- [ ] **Step 3: Commit**

```bash
git add cmd/netweaver/
git commit -m "feat: implement user CLI commands and execution wrapper"
```

---

### Task 9: Interactive Bubbletea TUI (`internal/tui`)

**Files:**
- Create: `internal/tui/app.go`
- Create: `internal/tui/model.go`
- Create: `internal/tui/views.go`

**Interfaces:**
- Consumes: `internal/api/client.go`, `types.ProcessInfo`, `types.InterfaceInfo`
- Produces: `tui.Run(sockPath string) error`

- [ ] **Step 1: Write minimal implementation**

```go
// internal/tui/model.go
package tui

import (
	"time"
	"netweaver/internal/api"
	"netweaver/internal/types"

	tea "github.com/charmbracelet/bubbletea"
)

type TickMsg time.Time

type Model struct {
	client     *api.Client
	processes  []types.ProcessInfo
	interfaces []types.InterfaceInfo
	cursor     int
	modalOpen  bool
	selectedP  *types.ProcessInfo
	err        error
	width      int
	height     int
}

func InitialModel(sockPath string) Model {
	return Model{
		client: api.NewClient(sockPath),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.fetchDataCmd(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) fetchDataCmd() tea.Cmd {
	return func() tea.Msg {
		procs, _ := m.client.ListProcesses()
		ifaces, _ := m.client.ListInterfaces()
		return dataLoadedMsg{processes: procs, interfaces: ifaces}
	}
}

type dataLoadedMsg struct {
	processes  []types.ProcessInfo
	interfaces []types.InterfaceInfo
}
```

```go
// internal/tui/views.go
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00E676"))

	tableStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#626262")).
			Padding(0, 1)
)

func (m Model) View() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("NetWeaver: Per-Application Network Interface Manager"))
	b.WriteString("\n\n")

	// Active interfaces summary
	b.WriteString("Active Interfaces: ")
	for _, iface := range m.interfaces {
		b.WriteString(fmt.Sprintf("[%s: %s (table %d)] ", iface.Name, iface.IP, iface.TableID))
	}
	b.WriteString("\n\n")

	// Process Table
	b.WriteString(fmt.Sprintf("%-3s %-8s %-25s %-15s\n", "   ", "PID", "APPLICATION", "INTERFACE"))
	b.WriteString("------------------------------------------------------------\n")

	for i, p := range m.processes {
		cursor := "  "
		style := lipgloss.NewStyle()
		if m.cursor == i {
			cursor = " >"
			style = selectedStyle
		}

		iface := p.AssignedInterface
		if iface == "" {
			iface = "(default)"
		}

		line := fmt.Sprintf("%s %-8d %-25s %-15s", cursor, p.PID, p.Name, iface)
		b.WriteString(style.Render(line) + "\n")
		if i >= 15 { // display top 15 in view
			break
		}
	}

	b.WriteString("\n[↑/↓] Navigate | [Enter] Route to next iface | [Space] Reset default | [q] Quit\n")
	return tableStyle.Render(b.String())
}
```

```go
// internal/tui/app.go
package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

func Run(sockPath string) error {
	p := tea.NewProgram(InitialModel(sockPath), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.processes)-1 {
				m.cursor++
			}
		case "enter":
			if len(m.processes) > 0 && len(m.interfaces) > 0 {
				proc := m.processes[m.cursor]
				// Cycle to next available interface
				targetIface := m.interfaces[0].Name
				_ = m.client.AssignRoute(proc.PID, targetIface)
				return m, m.fetchDataCmd()
			}
		case " ":
			if len(m.processes) > 0 {
				proc := m.processes[m.cursor]
				_ = m.client.ResetRoute(proc.PID)
				return m, m.fetchDataCmd()
			}
		}
	case dataLoadedMsg:
		m.processes = msg.processes
		m.interfaces = msg.interfaces
	case TickMsg:
		return m, tea.Batch(m.fetchDataCmd(), tickCmd())
	}
	return m, nil
}
```

- [ ] **Step 2: Install charmbracelet dependencies and verify build**

```bash
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss
go build -o bin/netweaver ./cmd/netweaver
```
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/tui/ go.mod go.sum
git commit -m "feat: implement interactive Bubbletea terminal user interface"
```

---

### Task 10: Network Namespace Integration Test & Verification Script (`scripts/setup-veth-test.sh`)

**Files:**
- Create: `scripts/setup-veth-test.sh`
- Create: `scripts/teardown-veth-test.sh`

**Interfaces:**
- Consumes: `bin/netweaverd`, `bin/netweaver`
- Produces: Verified network packet separation between two simulated networks (`veth-eth0` on `10.10.1.0/24` and `veth-wifi0` on `10.10.2.0/24`).

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# scripts/setup-veth-test.sh
set -euo pipefail

echo "[*] Creating network namespaces and veth pairs for NetWeaver testing..."

# Clean old test namespaces if any
ip netns del ns-eth 2>/dev/null || true
ip netns del ns-wifi 2>/dev/null || true

# Create namespaces
ip netns add ns-eth
ip netns add ns-wifi

# Create veth pairs
ip link add veth-eth0 type veth peer name veth-eth-peer
ip link add veth-wifi0 type veth peer name veth-wifi-peer

# Move peers to namespaces
ip link set veth-eth-peer netns ns-eth
ip link set veth-wifi-peer netns ns-wifi

# Configure Host IPs
ip addr add 10.10.1.1/24 dev veth-eth0
ip link set veth-eth0 up

ip addr add 10.10.2.1/24 dev veth-wifi0
ip link set veth-wifi0 up

# Configure Namespace IPs and loopbacks
ip netns exec ns-eth ip addr add 10.10.1.2/24 dev veth-eth-peer
ip netns exec ns-eth ip link set veth-eth-peer up
ip netns exec ns-eth ip link set lo up

ip netns exec ns-wifi ip addr add 10.10.2.2/24 dev veth-wifi-peer
ip netns exec ns-wifi ip link set veth-wifi-peer up
ip netns exec ns-wifi ip link set lo up

echo "[*] Network namespaces created successfully."
echo "    Interface 1: veth-eth0  (10.10.1.1 -> peer 10.10.1.2)"
echo "    Interface 2: veth-wifi0 (10.10.2.1 -> peer 10.10.2.2)"
```

```bash
#!/usr/bin/env bash
# scripts/teardown-veth-test.sh
set -euo pipefail

echo "[*] Cleaning up test namespaces and veth devices..."
ip netns del ns-eth 2>/dev/null || true
ip netns del ns-wifi 2>/dev/null || true
ip link del veth-eth0 2>/dev/null || true
ip link del veth-wifi0 2>/dev/null || true
echo "[*] Cleanup complete."
```

- [ ] **Step 2: Make scripts executable and commit**

```bash
chmod +x scripts/setup-veth-test.sh scripts/teardown-veth-test.sh
git add scripts/
git commit -m "test: add network namespace dual-veth test and verification scripts"
```
