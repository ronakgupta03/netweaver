// internal/interfaces/monitor.go
package interfaces

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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

func parseDefaultRoutes(output string) map[string]string {
	gateways := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "default via ") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				gateways[fields[4]] = fields[2]
			}
		}
	}
	return gateways
}

func isCarrierUp(name string) bool {
	// Check physical carrier state
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "carrier"))
	if err == nil {
		return strings.TrimSpace(string(data)) == "1"
	}
	// Fallback to operational state for virtual devices
	operData, err := os.ReadFile(filepath.Join("/sys/class/net", name, "operstate"))
	if err == nil {
		state := strings.TrimSpace(string(operData))
		return state != "down"
	}
	return true
}

func (m *Monitor) DiscoverInterfaces() ([]types.InterfaceInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	routeOut, _ := exec.Command("ip", "route", "show").Output()
	gateways := parseDefaultRoutes(string(routeOut))

	var result []types.InterfaceInfo
	for _, iface := range netIfaces {
		// Ignore loopback, down links, and docker bridges
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "br-") || strings.HasPrefix(iface.Name, "docker") {
			continue
		}

		// Verify physical carrier is active (skips unplugged ethernet cables)
		if !isCarrierUp(iface.Name) {
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

		// Only active interfaces with a valid assigned IP can route traffic
		if ipAddr == "" {
			continue
		}

		gw := gateways[iface.Name]

		info := types.InterfaceInfo{
			Name:    iface.Name,
			Index:   iface.Index,
			IP:      ipAddr,
			Gateway: gw,
			TableID: 0x100 + iface.Index,
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
