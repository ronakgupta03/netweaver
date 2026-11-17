// internal/interfaces/monitor_test.go
package interfaces

import (
	"context"
	"errors"
	"net"
	"netweaver/internal/types"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseMultipleDefaultRoutes(t *testing.T) {
	sampleOutput := `default via 10.5.50.1 dev wlan0 proto dhcp src 10.5.48.18 metric 600
default via 192.168.1.1 dev eno1 proto dhcp src 192.168.1.50 metric 100
10.5.48.0/20 dev wlan0 proto dhcp scope link metric 600`

	gws := parseDefaultRoutes(sampleOutput)
	if gws["wlan0"] != "10.5.50.1" {
		t.Fatalf("expected wlan0 gw 10.5.50.1, got %s", gws["wlan0"])
	}
	if gws["eno1"] != "192.168.1.1" {
		t.Fatalf("expected eno1 gw 192.168.1.1, got %s", gws["eno1"])
	}
}

func TestPriorityOrderAndTunnels(t *testing.T) {
	cases := []struct {
		iface string
		want  int
	}{
		{"eno1", 50},
		{"eth0", 50},
		{"enp3s0", 50},
		{"wlan0", 100},
		{"wlp2s0", 100},
		{"dummy0", 200},
		{"wg0", 400},
		{"tun0", 400},
		{"tap0", 400},
		{"tailscale0", 400},
		{"ppp0", 400},
		{"utun3", 400},
		{"usb0", 700},
		{"enp5s0f4u2", 700},
		{"rndis0", 700},
		{"wwan0", 700},
	}
	for _, tc := range cases {
		if got := Priority(tc.iface); got != tc.want {
			t.Fatalf("Priority(%q) = %d, want %d", tc.iface, got, tc.want)
		}
	}
}

func TestTunnelDetection(t *testing.T) {
	tunnels := []struct {
		name  string
		flags net.Flags
	}{
		{"wg0", net.FlagUp},
		{"tun0", net.FlagUp},
		{"tap0", net.FlagUp},
		{"tailscale0", net.FlagUp | net.FlagPointToPoint},
		{"ppp0", net.FlagUp | net.FlagPointToPoint},
		{"utun0", net.FlagUp},
		{"vpn99", net.FlagUp | net.FlagPointToPoint},
	}
	for _, tc := range tunnels {
		if !IsTunnelInterface(tc.name, tc.flags) {
			t.Fatalf("expected IsTunnelInterface(%q, %v) = true", tc.name, tc.flags)
		}
	}

	physical := []string{"eno1", "eth0", "wlan0", "enp5s0f4u2", "usb0"}
	for _, name := range physical {
		if IsTunnelInterface(name, net.FlagUp|net.FlagBroadcast|net.FlagMulticast) {
			t.Fatalf("expected IsTunnelInterface(%q) = false", name)
		}
	}
}

func TestMeteredDetection(t *testing.T) {
	metered := []string{"usb0", "usb1", "enp5s0f4u2", "enp0s20f0u1", "rndis0", "wwan0"}
	for _, name := range metered {
		if !IsMeteredInterface(name) {
			t.Fatalf("expected IsMeteredInterface(%q) = true", name)
		}
	}

	unmetered := []string{"eno1", "eth0", "enp3s0", "wlan0", "wlp2s0", "wg0", "tun0", "tailscale0"}
	for _, name := range unmetered {
		if IsMeteredInterface(name) {
			t.Fatalf("expected IsMeteredInterface(%q) = false", name)
		}
	}
}

func TestCarrierUpHandlesUnknownOperstate(t *testing.T) {
	sysNet := t.TempDir()
	writeSys := func(iface, file, val string) {
		dir := filepath.Join(sysNet, iface)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(val), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// WireGuard / tun interfaces commonly report operstate=unknown without carrier=1.
	writeSys("wg0", "operstate", "unknown\n")
	if !isCarrierUpFromSys(sysNet, "wg0") {
		t.Fatal("expected wg0 with operstate=unknown to be UP")
	}

	writeSys("tun0", "operstate", "unknown\n")
	writeSys("tun0", "carrier", "1\n")
	if !isCarrierUpFromSys(sysNet, "tun0") {
		t.Fatal("expected tun0 with operstate=unknown, carrier=1 to be UP")
	}

	writeSys("tun1", "operstate", "down\n")
	writeSys("tun1", "carrier", "0\n")
	if isCarrierUpFromSys(sysNet, "tun1") {
		t.Fatal("expected tun1 with operstate=down to be DOWN")
	}

	writeSys("eno1", "operstate", "down\n")
	writeSys("eno1", "carrier", "0\n")
	if isCarrierUpFromSys(sysNet, "eno1") {
		t.Fatal("expected eno1 with carrier=0 to be DOWN")
	}

	writeSys("wlan0", "operstate", "up\n")
	writeSys("wlan0", "carrier", "1\n")
	if !isCarrierUpFromSys(sysNet, "wlan0") {
		t.Fatal("expected wlan0 with carrier=1 to be UP")
	}
}

func TestDiscoverInterfaceDNSAndOverrides(t *testing.T) {
	resolveDir := t.TempDir()
	netifContent := `# systemd-resolved per-link file
LLMNR=yes
DNS=1.1.1.1 8.8.8.8
SERVERS=8.8.8.8 9.9.9.9#dns.quad9.net 2606:4700:4700::1111
`
	if err := os.WriteFile(filepath.Join(resolveDir, "3"), []byte(netifContent), 0o644); err != nil {
		t.Fatal(err)
	}

	got := discoverInterfaceDNSFromDir(resolveDir, 3)
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("discoverInterfaceDNSFromDir = %v, want %v", got, want)
	}

	if missing := discoverInterfaceDNSFromDir(resolveDir, 999); len(missing) != 0 {
		t.Fatalf("expected empty DNS for missing file, got %v", missing)
	}
}

func TestDiscoverFromPopulatesTunnelMeteredHealthAndDNS(t *testing.T) {
	sysNet := t.TempDir()
	resolveDir := t.TempDir()

	for _, s := range []struct {
		iface, oper, carrier string
	}{
		{"eno1", "up", "1"},
		{"wg0", "unknown", ""},
		{"enp5s0f4u2", "up", "1"},
		{"wlan0", "up", "1"},
	} {
		dir := filepath.Join(sysNet, s.iface)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "operstate"), []byte(s.oper), 0o644); err != nil {
			t.Fatal(err)
		}
		if s.carrier != "" {
			if err := os.WriteFile(filepath.Join(dir, "carrier"), []byte(s.carrier), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := os.WriteFile(filepath.Join(resolveDir, "2"), []byte("DNS=192.168.1.1 1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resolveDir, "5"), []byte("SERVERS=10.8.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	prober := NewHealthProber(HealthProberConfig{
		FailThreshold: 2,
		ProbeFn: func(ctx context.Context, iface types.InterfaceInfo) (time.Duration, error) {
			if iface.Name == "wlan0" {
				return 0, errors.New("broken isp")
			}
			return 12 * time.Millisecond, nil
		},
	})
	// Probe eno1 once (healthy) and wlan0 twice (unhealthy); leave wg0 & enp5s0f4u2 unprobed.
	prober.ProbeOnce(context.Background(), []types.InterfaceInfo{
		{Name: "eno1", IP: "192.168.1.50", Up: true},
		{Name: "wlan0", IP: "10.0.0.12", Up: true},
	})
	prober.ProbeOnce(context.Background(), []types.InterfaceInfo{
		{Name: "wlan0", IP: "10.0.0.12", Up: true},
	})

	m := NewMonitorWithProber(prober)
	m.sysNetDir = sysNet
	m.resolveDir = resolveDir
	m.SetDNSOverride("enp5s0f4u2", []string{"9.9.9.9"})

	netIfaces := []net.Interface{
		{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
		{Index: 2, Name: "eno1", Flags: net.FlagUp | net.FlagBroadcast},
		{Index: 5, Name: "wg0", Flags: net.FlagUp | net.FlagPointToPoint},
		{Index: 6, Name: "enp5s0f4u2", Flags: net.FlagUp | net.FlagBroadcast},
		{Index: 7, Name: "wlan0", Flags: net.FlagUp | net.FlagBroadcast},
	}
	addrs := map[string][]net.Addr{
		"eno1":       {&net.IPNet{IP: net.ParseIP("192.168.1.50"), Mask: net.CIDRMask(24, 32)}},
		"wg0":        {&net.IPNet{IP: net.ParseIP("10.8.0.2"), Mask: net.CIDRMask(24, 32)}},
		"enp5s0f4u2": {&net.IPNet{IP: net.ParseIP("172.20.10.2"), Mask: net.CIDRMask(28, 32)}},
		"wlan0":      {&net.IPNet{IP: net.ParseIP("10.0.0.12"), Mask: net.CIDRMask(24, 32)}},
	}
	gateways := map[string]string{
		"eno1":       "192.168.1.1",
		"enp5s0f4u2": "172.20.10.1",
		"wlan0":      "10.0.0.1",
		// wg0 intentionally has NO Gateway!
	}

	got := m.discoverFrom(netIfaces, addrs, gateways, nil)
	if len(got) != 4 {
		t.Fatalf("expected 4 interfaces, got %d: %+v", len(got), got)
	}

	byName := make(map[string]types.InterfaceInfo)
	for _, iface := range got {
		byName[iface.Name] = iface
	}

	eno := byName["eno1"]
	if eno.IsTunnel || eno.Metered || !eno.Healthy || !almostEqual(eno.LatencyMs, 12.0, 1e-6) {
		t.Fatalf("unexpected eno1: %+v", eno)
	}
	if !reflect.DeepEqual(eno.DNSServers, []string{"192.168.1.1", "1.1.1.1"}) {
		t.Fatalf("eno1 DNS = %v", eno.DNSServers)
	}

	wg := byName["wg0"]
	if !wg.IsTunnel || wg.Gateway != "" || !wg.Healthy || wg.HealthScore != 100 || wg.Metered {
		t.Fatalf("unexpected wg0 (tunnel without gateway, unprobed default healthy): %+v", wg)
	}
	if !reflect.DeepEqual(wg.DNSServers, []string{"10.8.0.1"}) {
		t.Fatalf("wg0 DNS = %v", wg.DNSServers)
	}

	usb := byName["enp5s0f4u2"]
	if !usb.Metered || usb.IsTunnel || !usb.Healthy {
		t.Fatalf("unexpected enp5s0f4u2: %+v", usb)
	}
	if !reflect.DeepEqual(usb.DNSServers, []string{"9.9.9.9"}) {
		t.Fatalf("enp5s0f4u2 DNS override = %v", usb.DNSServers)
	}

	wlan := byName["wlan0"]
	if wlan.Healthy || wlan.HealthScore != 0 {
		t.Fatalf("expected wlan0 unhealthy with score 0, got %+v", wlan)
	}

	// Clearing override falls back to discovered DNS (none for enp5s0f4u2).
	m.SetDNSOverride("enp5s0f4u2", nil)
	got2 := m.discoverFrom(netIfaces, addrs, gateways, nil)
	for _, iface := range got2 {
		if iface.Name == "enp5s0f4u2" && len(iface.DNSServers) != 0 {
			t.Fatalf("expected cleared override to have no DNS, got %v", iface.DNSServers)
		}
	}
}

func TestStartWatchNetlinkDebouncedAndFallback(t *testing.T) {
	// Part 1: Netlink-triggered debounced coalescing.
	m := NewMonitorWithProber(nil)
	m.SetWatchTiming(10*time.Second, 25*time.Millisecond)

	var discoverCalls atomic.Int32
	m.discoverFn = func() ([]types.InterfaceInfo, error) {
		discoverCalls.Add(1)
		return []types.InterfaceInfo{{Name: "eno1", Up: true, Healthy: true}}, nil
	}

	nlCh := make(chan struct{}, 8)
	m.SetNetlinkWatcher(func(ctx context.Context) (<-chan struct{}, error) {
		return nlCh, nil
	})

	notifyCh := make(chan []types.InterfaceInfo, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.StartWatch(ctx, notifyCh)
		close(done)
	}()

	// Emit a burst of 5 netlink signals immediately.
	for i := 0; i < 5; i++ {
		nlCh <- struct{}{}
	}

	select {
	case ifaces := <-notifyCh:
		if len(ifaces) != 1 || ifaces[0].Name != "eno1" {
			t.Fatalf("unexpected notify payload: %+v", ifaces)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for netlink-triggered watch update")
	}

	// Burst should coalesce into a single discovery call.
	time.Sleep(50 * time.Millisecond)
	if got := discoverCalls.Load(); got != 1 {
		t.Fatalf("expected burst of 5 netlink events to coalesce into 1 discovery, got %d", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("StartWatch did not stop on context cancel")
	}

	// Part 2: Graceful degradation to periodic ticker when netlink fails.
	m2 := NewMonitorWithProber(nil)
	m2.SetWatchTiming(20*time.Millisecond, 10*time.Millisecond)
	m2.SetNetlinkWatcher(func(ctx context.Context) (<-chan struct{}, error) {
		return nil, errors.New("netlink permission denied")
	})
	m2.discoverFn = func() ([]types.InterfaceInfo, error) {
		return []types.InterfaceInfo{{Name: "wlan0", Up: true, Healthy: true}}, nil
	}

	notifyCh2 := make(chan []types.InterfaceInfo, 10)
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		m2.StartWatch(ctx2, notifyCh2)
		close(done2)
	}()

	select {
	case ifaces := <-notifyCh2:
		if len(ifaces) != 1 || ifaces[0].Name != "wlan0" {
			t.Fatalf("unexpected ticker fallback payload: %+v", ifaces)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for periodic ticker fallback")
	}

	cancel2()
	<-done2
}

func TestDiscoverInterfacesHostSmoke(t *testing.T) {
	m := NewMonitorWithProber(nil)
	ifaces, err := m.DiscoverInterfaces()
	if err != nil {
		t.Fatalf("DiscoverInterfaces: %v", err)
	}
	for _, iface := range ifaces {
		if !iface.Up || !iface.Healthy {
			t.Fatalf("expected discovered host interface %s to have Up=true and Healthy=true: %+v", iface.Name, iface)
		}
		if iface.Name == "lo" {
			t.Fatal("loopback interface must not be returned")
		}
	}
}
