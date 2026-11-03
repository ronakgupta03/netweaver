// internal/process/scanner.go
package process

import (
	"fmt"
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
		// Ignore low system PIDs
		if p.Pid <= 100 {
			continue
		}

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

		// Only list user processes (UID >= 1000) or user application processes
		if uid < 1000 {
			continue
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
	if rootPID <= 100 {
		return nil, fmt.Errorf("refusing to manipulate system process tree for PID %d", rootPID)
	}
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
