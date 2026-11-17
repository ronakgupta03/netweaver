// internal/interfaces/monitor.go
package interfaces

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"netweaver/internal/types"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultWatchInterval = 2 * time.Second
	defaultWatchDebounce = 50 * time.Millisecond
	defaultSysNetDir     = "/sys/class/net"
	defaultResolveDir    = "/run/systemd/resolve/netif"
)

var tunnelPrefixes = []string{"wg", "tun", "tap", "tailscale", "ppp", "utun"}

// Monitor discovers active Linux network interfaces, enriches them with tunnel,
// metered, DNS, and upstream health telemetry, and watches for changes via
// RTNetlink and periodic polling.
type Monitor struct {
	mu             sync.RWMutex
	ifaces         map[string]types.InterfaceInfo
	prober         *HealthProber
	netlink        *NetlinkWatcher
	netlinkWatchFn func(ctx context.Context) (<-chan struct{}, error)
	discoverFn     func() ([]types.InterfaceInfo, error)
	dnsOverrides   map[string][]string
	watchInterval  time.Duration
	watchDebounce  time.Duration
	sysNetDir      string
	resolveDir     string
}

// NewMonitor creates a Monitor with a default HealthProber and RTNetlink watcher.
func NewMonitor() *Monitor {
	return NewMonitorWithProber(NewHealthProber())
}

// NewMonitorWithProber creates a Monitor using the provided HealthProber (may be nil).
func NewMonitorWithProber(prober *HealthProber) *Monitor {
	nl := NewNetlinkWatcher()
	m := &Monitor{
		ifaces:        make(map[string]types.InterfaceInfo),
		prober:        prober,
		netlink:       nl,
		dnsOverrides:  make(map[string][]string),
		watchInterval: defaultWatchInterval,
		watchDebounce: defaultWatchDebounce,
		sysNetDir:     defaultSysNetDir,
		resolveDir:    defaultResolveDir,
	}
	m.netlinkWatchFn = nl.Watch
	m.discoverFn = m.DiscoverInterfaces
	return m
}

// SetProber replaces the Monitor's HealthProber (may be nil to disable probing).
func (m *Monitor) SetProber(prober *HealthProber) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prober = prober
}

// Prober returns the configured HealthProber, or nil if disabled.
func (m *Monitor) Prober() *HealthProber {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.prober
}

// SetNetlinkWatcher overrides the netlink event stream function (primarily for tests).
func (m *Monitor) SetNetlinkWatcher(fn func(ctx context.Context) (<-chan struct{}, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.netlinkWatchFn = fn
}

// SetWatchTiming configures the periodic fallback interval and netlink debounce window.
func (m *Monitor) SetWatchTiming(interval, debounce time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if interval > 0 {
		m.watchInterval = interval
	}
	if debounce > 0 {
		m.watchDebounce = debounce
	}
}

// SetDNSOverride configures operator-supplied DNS servers for iface.
// Passing nil or an empty slice clears the override so discovered DNS servers are used.
func (m *Monitor) SetDNSOverride(iface string, servers []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if iface == "" {
		return
	}
	cleaned := cleanDNSList(servers)
	if len(cleaned) == 0 {
		delete(m.dnsOverrides, iface)
		if info, ok := m.ifaces[iface]; ok {
			info.DNSServers = discoverInterfaceDNSFromDir(m.resolveDir, info.Index)
			m.ifaces[iface] = info
		}
		return
	}
	m.dnsOverrides[iface] = cleaned
	if info, ok := m.ifaces[iface]; ok {
		cp := make([]string, len(cleaned))
		copy(cp, cleaned)
		info.DNSServers = cp
		m.ifaces[iface] = info
	}
}

// DNSOverride returns a copy of any operator-configured DNS override for iface.
func (m *Monitor) DNSOverride(iface string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ov := m.dnsOverrides[iface]
	if len(ov) == 0 {
		return nil
	}
	out := make([]string, len(ov))
	copy(out, ov)
	return out
}

// SnapshotInterfaces returns a deterministic copy of the most recently discovered interfaces.
func (m *Monitor) SnapshotInterfaces() []types.InterfaceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.ifaces) == 0 {
		return nil
	}
	out := make([]types.InterfaceInfo, 0, len(m.ifaces))
	for _, info := range m.ifaces {
		if len(info.DNSServers) > 0 {
			dnsCopy := make([]string, len(info.DNSServers))
			copy(dnsCopy, info.DNSServers)
			info.DNSServers = dnsCopy
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Index != out[j].Index {
			return out[i].Index < out[j].Index
		}
		return out[i].Name < out[j].Name
	})
	return out
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

func isTunnelName(name string) bool {
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// IsTunnelInterface reports whether the interface is an L3 VPN/tunnel interface.
func IsTunnelInterface(name string, flags net.Flags) bool {
	if flags&net.FlagPointToPoint != 0 {
		return true
	}
	return isTunnelName(name)
}

// IsMeteredInterface reports whether the interface name matches common metered
// USB tethering or cellular interfaces (usb*, enp*u*, rndis*, wwan*).
func IsMeteredInterface(name string) bool {
	if strings.HasPrefix(name, "usb") ||
		strings.HasPrefix(name, "rndis") ||
		strings.HasPrefix(name, "wwan") {
		return true
	}
	if strings.HasPrefix(name, "enp") && strings.Contains(name[3:], "u") {
		return true
	}
	return false
}

// Priority ranks interfaces for default-route preference and failover targets:
// lower is better (Ethernet 50 > Wi-Fi 100 > Other 200 > VPN/Tunnel 400 > USB/Metered 700).
func Priority(name string) int {
	return getPreferredMetric(name)
}

func getPreferredMetric(name string) int {
	if isTunnelName(name) {
		return 400
	}
	if IsMeteredInterface(name) {
		return 700 // Lowest priority: USB mobile tethering / cellular metered fallback
	}
	if strings.HasPrefix(name, "eno") || strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "enp") {
		return 50 // Highest priority: physical Ethernet
	}
	if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wl") {
		return 100 // Medium priority: Wi-Fi (default when Ethernet is not plugged in)
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
	return isCarrierUpFromSys(defaultSysNetDir, name)
}

func isCarrierUpFromSys(sysNetDir, name string) bool {
	operData, operErr := os.ReadFile(filepath.Join(sysNetDir, name, "operstate"))
	operState := ""
	if operErr == nil {
		operState = strings.ToLower(strings.TrimSpace(string(operData)))
		switch operState {
		case "down", "lowerlayerdown", "notpresent":
			return false
		}
	}

	if isTunnelName(name) && operErr == nil && (operState == "unknown" || operState == "up") {
		return true
	}

	data, err := os.ReadFile(filepath.Join(sysNetDir, name, "carrier"))
	if err == nil {
		return strings.TrimSpace(string(data)) == "1"
	}

	if operErr == nil {
		return operState != "down"
	}
	return true
}

// DiscoverInterfaceDNS best-effort reads per-interface DNS servers from systemd-resolved.
func DiscoverInterfaceDNS(index int) []string {
	return discoverInterfaceDNSFromDir(defaultResolveDir, index)
}

func discoverInterfaceDNSFromDir(resolveDir string, index int) []string {
	if index <= 0 || resolveDir == "" {
		return nil
	}
	return parseResolveNetifFile(filepath.Join(resolveDir, fmt.Sprintf("%d", index)))
}

func parseResolveNetifFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var raw []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var val string
		switch {
		case strings.HasPrefix(line, "DNS="):
			val = strings.TrimPrefix(line, "DNS=")
		case strings.HasPrefix(line, "SERVERS="):
			val = strings.TrimPrefix(line, "SERVERS=")
		default:
			continue
		}
		fields := strings.FieldsFunc(val, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ','
		})
		raw = append(raw, fields...)
	}
	return cleanDNSList(raw)
}

func cleanDNSList(servers []string) []string {
	if len(servers) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(servers))
	out := make([]string, 0, len(servers))
	for _, entry := range servers {
		s := strings.TrimSpace(entry)
		if idx := strings.IndexByte(s, '#'); idx >= 0 {
			s = s[:idx]
		}
		if s == "" {
			continue
		}
		// Validate IP or host:port IP while keeping clean IP string when valid.
		candidate := s
		if ip := net.ParseIP(candidate); ip == nil {
			host, _, err := net.SplitHostPort(candidate)
			if err != nil || net.ParseIP(host) == nil {
				continue
			}
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func selectPrimaryIP(addrs []net.Addr) string {
	var v6Fallback string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
			continue
		}
		if ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
		if v6Fallback == "" && !ipNet.IP.IsLinkLocalUnicast() && !ipNet.IP.IsLinkLocalMulticast() {
			v6Fallback = ipNet.IP.String()
		}
	}
	return v6Fallback
}

// DiscoverInterfaces enumerates active interfaces, gateways, tunnel/metered metadata,
// per-interface DNS servers, and latest health metrics.
func (m *Monitor) DiscoverInterfaces() ([]types.InterfaceInfo, error) {
	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	routeOut, _ := exec.Command("ip", "route", "show").Output()
	gateways := parseDefaultRoutes(string(routeOut))

	route6Out, _ := exec.Command("ip", "-6", "route", "show", "default").Output()
	gateways6 := parseDefaultRoutes6(string(route6Out))

	// Enforce default route priority: Ethernet (50) > Wi-Fi (100) > Tunnel (400) > USB tethering (700)
	EnforceDefaultPriorities(gateways)

	return m.discoverFrom(netIfaces, nil, gateways, gateways6), nil
}

func (m *Monitor) discoverFrom(
	netIfaces []net.Interface,
	addrsOverride map[string][]net.Addr,
	gateways map[string]string,
	gateways6 map[string]string,
) []types.InterfaceInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	nextIfaces := make(map[string]types.InterfaceInfo, len(netIfaces))
	var result []types.InterfaceInfo

	for _, iface := range netIfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "br-") || strings.HasPrefix(iface.Name, "docker") {
			continue
		}
		if !isCarrierUpFromSys(m.sysNetDir, iface.Name) {
			continue
		}

		var addrs []net.Addr
		if addrsOverride != nil {
			addrs = addrsOverride[iface.Name]
		} else {
			addrs, _ = iface.Addrs()
		}

		ipAddr := selectPrimaryIP(addrs)
		if ipAddr == "" {
			continue
		}

		gw := gateways[iface.Name]
		gw6 := gateways6[iface.Name]

		var dnsServers []string
		if ov, ok := m.dnsOverrides[iface.Name]; ok && len(ov) > 0 {
			dnsServers = make([]string, len(ov))
			copy(dnsServers, ov)
		} else {
			dnsServers = discoverInterfaceDNSFromDir(m.resolveDir, iface.Index)
		}

		healthy := true
		healthScore := 100.0
		var latencyMs, jitterMs, packetLoss float64
		if m.prober != nil {
			metrics := m.prober.Metrics(iface.Name)
			latencyMs = metrics.LatencyMs
			jitterMs = metrics.JitterMs
			packetLoss = metrics.PacketLoss
			healthy = metrics.Healthy
			healthScore = metrics.HealthScore
		}

		info := types.InterfaceInfo{
			Name:        iface.Name,
			Index:       iface.Index,
			IP:          ipAddr,
			Gateway:     gw,
			Gateway6:    gw6,
			TableID:     0x100 + iface.Index,
			Up:          true,
			IsTunnel:    IsTunnelInterface(iface.Name, iface.Flags),
			LatencyMs:   latencyMs,
			JitterMs:    jitterMs,
			PacketLoss:  packetLoss,
			Healthy:     healthy,
			HealthScore: healthScore,
			Metered:     IsMeteredInterface(iface.Name),
			DNSServers:  dnsServers,
		}
		nextIfaces[iface.Name] = info
		result = append(result, info)
	}

	m.ifaces = nextIfaces
	return result
}

// StartWatch watches for link, address, and route updates via RTNetlink
// (with debounced coalescing) plus a periodic fallback ticker, and runs any
// attached HealthProber until ctx is cancelled.
func (m *Monitor) StartWatch(ctx context.Context, notifyChan chan<- []types.InterfaceInfo) {
	m.mu.RLock()
	interval := m.watchInterval
	debounce := m.watchDebounce
	prober := m.prober
	nlWatch := m.netlinkWatchFn
	discover := m.discoverFn
	m.mu.RUnlock()

	if interval <= 0 {
		interval = defaultWatchInterval
	}
	if debounce <= 0 {
		debounce = defaultWatchDebounce
	}
	if discover == nil {
		discover = m.DiscoverInterfaces
	}

	healthNotify := make(chan struct{}, 1)
	proberDone := make(chan struct{})
	if prober != nil {
		prober.SetInterfaceProvider(m.SnapshotInterfaces)
		prober.setNotifyChan(healthNotify)
		go func() {
			defer close(proberDone)
			prober.Start(ctx)
		}()
	} else {
		close(proberDone)
	}

	var nlEvents <-chan struct{}
	if nlWatch != nil {
		if ch, err := nlWatch(ctx); err == nil {
			nlEvents = ch
		}
	}

	ticker := time.NewTicker(interval)
	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	defer func() {
		ticker.Stop()
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		<-proberDone
		if prober != nil {
			prober.setNotifyChan(nil)
		}
	}()

	pushUpdate := func() bool {
		ifaces, err := discover()
		if err != nil {
			return true
		}
		select {
		case notifyChan <- ifaces:
			return true
		case <-ctx.Done():
			return false
		}
	}

	for {
		select {
		case <-ctx.Done():
			return

		case _, ok := <-nlEvents:
			if !ok {
				nlEvents = nil
				continue
			}
			if debounceTimer == nil {
				debounceTimer = time.NewTimer(debounce)
				debounceCh = debounceTimer.C
			}

		case <-debounceCh:
			debounceTimer = nil
			debounceCh = nil
			if !pushUpdate() {
				return
			}

		case <-healthNotify:
			if debounceTimer != nil {
				debounceTimer.Stop()
				debounceTimer = nil
				debounceCh = nil
			}
			if !pushUpdate() {
				return
			}

		case <-ticker.C:
			if debounceTimer != nil {
				debounceTimer.Stop()
				debounceTimer = nil
				debounceCh = nil
			}
			if !pushUpdate() {
				return
			}
		}
	}
}
