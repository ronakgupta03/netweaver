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
