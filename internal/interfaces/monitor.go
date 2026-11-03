// internal/interfaces/monitor.go
package interfaces

import (
	"bufio"
	"context"
	"fmt"
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

func parseDefaultRoutes6(output string) map[string]string {
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

func getPreferredMetric(name string) int {
	if strings.HasPrefix(name, "eno") || strings.HasPrefix(name, "eth") {
		return 50 // Highest priority: physical Ethernet
	}
	if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wl") {
		return 100 // Medium priority: Wi-Fi (default when Ethernet is not plugged in)
	}
	if strings.Contains(name, "u") || strings.HasPrefix(name, "usb") || strings.HasPrefix(name, "enp") {
		return 700 // Lowest priority: USB mobile tethering / fallback
	}
	return 200
}

func EnforceDefaultPriorities(gateways map[string]string) {
	for dev, gw := range gateways {
		metric := getPreferredMetric(dev)
		_ = exec.Command("ip", "route", "replace", "default", "via", gw, "dev", dev, "metric", fmt.Sprintf("%d", metric)).Run()
	}
}

func isCarrierUp(name string) bool {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "carrier"))
	if err == nil {
		return strings.TrimSpace(string(data)) == "1"
	}
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

	route6Out, _ := exec.Command("ip", "-6", "route", "show", "default").Output()
	gateways6 := parseDefaultRoutes6(string(route6Out))

	// Enforce default route priority: Ethernet (50) > Wi-Fi (100) > USB tethering (700)
	EnforceDefaultPriorities(gateways)

	var result []types.InterfaceInfo
	for _, iface := range netIfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "br-") || strings.HasPrefix(iface.Name, "docker") {
			continue
		}

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

		if ipAddr == "" {
			continue
		}

		gw := gateways[iface.Name]
		gw6 := gateways6[iface.Name]

		info := types.InterfaceInfo{
			Name:     iface.Name,
			Index:    iface.Index,
			IP:       ipAddr,
			Gateway:  gw,
			Gateway6: gw6,
			TableID:  0x100 + iface.Index,
			Up:       true,
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
