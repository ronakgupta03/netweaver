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

var ignoredServices = map[string]bool{
	"systemd":             true,
	"(sd-pam)":            true,
	"dbus-broker":         true,
	"dbus-broker-launch":  true,
	"pipewire":            true,
	"wireplumber":         true,
	"pipewire-pulse":      true,
	"start-hyprland":      true,
	"Hyprland":            true,
	"Xwayland":            true,
	"waybar":              true,
	"hypridle":            true,
	"wl-paste":            true,
	"gvfsd":               true,
	"gvfsd-fuse":          true,
	"gvfsd-metadata":      true,
	"dconf-service":       true,
	"xsettingsd":          true,
	"at-spi-bus-launcher": true,
	"at-spi2-registryd":   true,
	"hyprpolkitagent":     true,
	"quickshell":          true,
	"cava":                true,
	"awww-daemon":         true,
	"playerctl":           true,
	"obexd":               true,
	"fusermount3":         true,
	"wenativehost":        true,
	"node-MainThread":     true,
	"gitstatusd-linux-x86_64": true,
	"alacritty":           true,
	"kitty":               true,
	"foot":                true,
	"wezterm-gui":         true,
	"crashhelper":         true,
	"forkserver":          true,
	"Socket Process":      true,
	"WebExtensions":       true,
	"RDD Process":         true,
	"Privileged Cont":     true,
	"Utility Process":     true,
	"Isolated Servic":     true,
	"Isolated Web Co":     true,
	"Web Content":         true,
	"chrome_crashpad":     true,
	"chrome_crashpad_handler": true,
	"cat":                 true,
	"sleep":               true,
}

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func isIgnored(name string) bool {
	if ignoredServices[name] {
		return true
	}
	if strings.HasPrefix(name, "xdg-") || strings.HasPrefix(name, "gvfs") {
		return true
	}
	return false
}

func getSessionID(pid int32) int32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	closeIdx := strings.LastIndex(s, ")")
	if closeIdx == -1 || closeIdx+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[closeIdx+2:])
	// fields[0]: state, fields[1]: ppid, fields[2]: pgrp, fields[3]: session
	if len(fields) > 3 {
		sid, _ := strconv.Atoi(fields[3])
		return int32(sid)
	}
	return 0
}

func getShellTask(p *process.Process) string {
	children, err := p.Children()
	if err != nil || len(children) == 0 {
		return "idle"
	}
	for _, child := range children {
		cName, _ := child.Name()
		if cName == "" || strings.HasPrefix(cName, "gitstatusd") {
			continue
		}
		cmdline, _ := child.Cmdline()
		if cmdline != "" {
			fields := strings.Fields(cmdline)
			if len(fields) > 0 {
				prog := filepath.Base(fields[0])
				if len(fields) > 1 {
					arg := fields[1]
					if len(arg) > 20 {
						arg = arg[:17] + "..."
					}
					return fmt.Sprintf("%s %s", prog, arg)
				}
				return prog
			}
		}
		return cName
	}
	return "idle"
}

func (s *Scanner) ScanProcesses() ([]types.ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	procMap := make(map[int32]*process.Process, len(procs))
	for _, p := range procs {
		procMap[p.Pid] = p
	}

	var result []types.ProcessInfo
	for _, p := range procs {
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

		// Only list user processes (UID >= 1000)
		if uid < 1000 {
			continue
		}

		// Filter out internal background daemons and browser child sandboxes
		if isIgnored(name) {
			continue
		}

		parent := procMap[ppid]
		// Collapse browser/multi-process trees: if parent has same name, skip child
		if parent != nil {
			parentName, _ := parent.Name()
			if parentName == name {
				continue
			}
			if (name == "zsh" || name == "bash") && (parentName == "zsh" || parentName == "bash") {
				continue
			}
		}

		displayName := name
		if name == "zsh" || name == "bash" || name == "fish" || name == "sh" {
			sid := getSessionID(p.Pid)
			// Only show the interactive session leader shell
			if p.Pid != sid {
				continue
			}
			task := getShellTask(p)
			displayName = fmt.Sprintf("terminal (%s)", task)
		}

		cmdline, _ := p.Cmdline()

		// Read cgroup path to identify current assignment
		assigned := s.detectAssignedInterface(int(p.Pid))

		result = append(result, types.ProcessInfo{
			PID:               int(p.Pid),
			Name:              displayName,
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
