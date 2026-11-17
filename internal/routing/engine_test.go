// internal/routing/engine_test.go
package routing

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"netweaver/internal/types"
)

func TestNftablesConfigGeneration(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "eno1", Index: 2, TableID: 0x102},
		{Name: "wlan0", Index: 3, TableID: 0x103},
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

	// Existing minimal interfaces must not include extra DNS/split structures.
	if strings.Contains(ruleset, "output_nat") || strings.Contains(ruleset, "dst4_") {
		t.Fatalf("unexpected DNS/split ruleset sections in minimal config:\n%s", ruleset)
	}
}

func TestNftablesDropsQuarantinedCgroup(t *testing.T) {
	ruleset := GenerateNftablesRuleset([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x103}})
	drop := `socket cgroupv2 level 2 "netweaver/blocked" drop`
	if !strings.Contains(ruleset, drop) {
		t.Fatalf("ruleset must drop quarantined traffic: %s", ruleset)
	}
	// The drop must be evaluated before interface marking rules.
	if strings.Index(ruleset, drop) > strings.Index(ruleset, `"netweaver/wlan0"`) {
		t.Fatal("blocked drop rule must precede marking rules")
	}
}

func TestRulesetSkipsMissingCgroupPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "netweaver", "wlan0"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := NewEngineWithCgroupRoot(root)
	e.ifaces["wlan0"] = types.InterfaceInfo{Name: "wlan0", TableID: 0x103}
	e.ifaces["ghost0"] = types.InterfaceInfo{Name: "ghost0", TableID: 0x110}

	ruleset, skipped := e.buildRuleset()
	if len(skipped) != 1 || skipped[0] != "ghost0" {
		t.Fatalf("skipped = %v, want [ghost0]", skipped)
	}
	if !strings.Contains(ruleset, `"netweaver/wlan0"`) {
		t.Fatal("existing cgroup must be marked")
	}
	if strings.Contains(ruleset, `"netweaver/ghost0"`) {
		t.Fatal("missing cgroup must not be referenced")
	}
	if strings.Contains(ruleset, `"netweaver/blocked"`) {
		t.Fatal("blocked rule must be omitted while its cgroup is missing")
	}

	if err := os.MkdirAll(filepath.Join(root, "netweaver", "blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	ruleset, _ = e.buildRuleset()
	if !strings.Contains(ruleset, `"netweaver/blocked" drop`) {
		t.Fatal("blocked rule must appear once the quarantine cgroup exists")
	}
}

func TestMarkingDisabledOmitsSocketRules(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"wlan0", "blocked"} {
		if err := os.MkdirAll(filepath.Join(root, "netweaver", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := NewEngineWithCgroupRoot(root)
	e.ifaces["wlan0"] = types.InterfaceInfo{Name: "wlan0", TableID: 0x104}
	e.SetMarking(false)

	ruleset, _ := e.buildRuleset()
	if strings.Contains(ruleset, "socket cgroupv2") {
		t.Fatalf("eBPF mode must not emit socket marking rules: %s", ruleset)
	}
	if !strings.Contains(ruleset, `oifname "wlan0" meta mark 0x104 masquerade`) {
		t.Fatal("NAT rules must survive when eBPF handles marking")
	}
}

func TestBuildRouteCommandsRegularAndTunnel(t *testing.T) {
	// 1. Standard interface with IPv4 gateway, no IPv6 gateway -> unreachable v6 fallback.
	ethCmds := buildRouteCommands(types.InterfaceInfo{
		Name:     "eno1",
		TableID:  258,
		Gateway:  "192.168.1.1",
		IsTunnel: false,
	}, false)
	wantEth := [][]string{
		{"ip", "route", "replace", "default", "via", "192.168.1.1", "dev", "eno1", "table", "258"},
		{"ip", "-6", "route", "replace", "unreachable", "default", "table", "258"},
		{"ip", "rule", "del", "fwmark", "0x102", "table", "258"},
		{"ip", "rule", "add", "fwmark", "0x102", "table", "258", "priority", "1000"},
		{"ip", "-6", "rule", "del", "fwmark", "0x102", "table", "258"},
		{"ip", "-6", "rule", "add", "fwmark", "0x102", "table", "258", "priority", "1000"},
	}
	if !reflect.DeepEqual(ethCmds, wantEth) {
		t.Fatalf("ethCmds = %#v\nwant %#v", ethCmds, wantEth)
	}

	// 2. Gateway-less IPv4-only L3 VPN tunnel -> dev-scoped v4 route, unreachable v6.
	wgV4Cmds := buildRouteCommands(types.InterfaceInfo{
		Name:     "wg0",
		TableID:  260,
		IP:       "10.8.0.2",
		IsTunnel: true,
	}, false)
	wantWgV4 := [][]string{
		{"ip", "route", "replace", "default", "dev", "wg0", "table", "260"},
		{"ip", "-6", "route", "replace", "unreachable", "default", "table", "260"},
		{"ip", "rule", "del", "fwmark", "0x104", "table", "260"},
		{"ip", "rule", "add", "fwmark", "0x104", "table", "260", "priority", "1000"},
		{"ip", "-6", "rule", "del", "fwmark", "0x104", "table", "260"},
		{"ip", "-6", "rule", "add", "fwmark", "0x104", "table", "260", "priority", "1000"},
	}
	if !reflect.DeepEqual(wgV4Cmds, wantWgV4) {
		t.Fatalf("wgV4Cmds = %#v\nwant %#v", wgV4Cmds, wantWgV4)
	}

	// 3. Gateway-less dual-stack/IPv6 L3 VPN tunnel -> dev-scoped v4 & v6 routes.
	wgDualCmds := buildRouteCommands(types.InterfaceInfo{
		Name:     "tun0",
		TableID:  261,
		IP:       "10.8.0.2",
		IsTunnel: true,
	}, true)
	wantWgDual := [][]string{
		{"ip", "route", "replace", "default", "dev", "tun0", "table", "261"},
		{"ip", "-6", "route", "replace", "default", "dev", "tun0", "table", "261"},
		{"ip", "rule", "del", "fwmark", "0x105", "table", "261"},
		{"ip", "rule", "add", "fwmark", "0x105", "table", "261", "priority", "1000"},
		{"ip", "-6", "rule", "del", "fwmark", "0x105", "table", "261"},
		{"ip", "-6", "rule", "add", "fwmark", "0x105", "table", "261", "priority", "1000"},
	}
	if !reflect.DeepEqual(wgDualCmds, wantWgDual) {
		t.Fatalf("wgDualCmds = %#v\nwant %#v", wgDualCmds, wantWgDual)
	}
}

func TestSetupInterfaceRouteAndRemoveTunnelMocked(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "netweaver", "wg0"), 0o755); err != nil {
		t.Fatal(err)
	}

	e := NewEngineWithCgroupRoot(root)
	var cmds [][]string
	var appliedRuleset string
	e.hasGlobalIPv6Fn = func(iface string) bool { return iface == "wg0" }
	e.runCmdFn = func(name string, args ...string) error {
		cmds = append(cmds, append([]string{name}, args...))
		return nil
	}
	e.runNftFn = func(ruleset string, skipped []string) error {
		appliedRuleset = ruleset
		return nil
	}

	err := e.SetupInterfaceRoute(types.InterfaceInfo{
		Name:       "wg0",
		Index:      4,
		IP:         "10.64.0.2",
		TableID:    0x104,
		IsTunnel:   true,
		DNSServers: []string{"10.64.0.1"},
	})
	if err != nil {
		t.Fatalf("SetupInterfaceRoute: %v", err)
	}

	if len(cmds) != 6 {
		t.Fatalf("expected 6 route/rule cmds, got %d: %#v", len(cmds), cmds)
	}
	if got := strings.Join(cmds[0], " "); got != "ip route replace default dev wg0 table 260" {
		t.Fatalf("unexpected v4 tunnel cmd: %s", got)
	}
	if got := strings.Join(cmds[1], " "); got != "ip -6 route replace default dev wg0 table 260" {
		t.Fatalf("unexpected v6 tunnel cmd: %s", got)
	}
	if !strings.Contains(appliedRuleset, "ip daddr != 10.64.0.1 meta mark 0x104 udp dport 53 dnat ip to 10.64.0.1") {
		t.Fatalf("expected DNS DNAT rule in applied ruleset:\n%s", appliedRuleset)
	}

	cmds = nil
	if err := e.RemoveInterface("wg0"); err != nil {
		t.Fatalf("RemoveInterface: %v", err)
	}
	if len(cmds) != 4 {
		t.Fatalf("expected 4 cleanup cmds, got %d: %#v", len(cmds), cmds)
	}
	if strings.Contains(appliedRuleset, `oifname "wg0"`) {
		t.Fatalf("removed interface must not remain in ruleset:\n%s", appliedRuleset)
	}
}

func TestPerInterfaceDNSIsolationRuleset(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"wlan0", "wg0"} {
		if err := os.MkdirAll(filepath.Join(root, "netweaver", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	e := NewEngineWithCgroupRoot(root)
	e.runCmdFn = func(name string, args ...string) error { return nil }
	e.runNftFn = func(ruleset string, skipped []string) error { return nil }

	// Explicit override must win over discovered InterfaceInfo.DNSServers.
	e.SetInterfaceDNS("wg0", []string{"10.64.0.1", "invalid-host", "10.64.0.1", "fd00::53"})
	if err := e.SetupInterfaceRoute(types.InterfaceInfo{
		Name:       "wg0",
		TableID:    0x104,
		IsTunnel:   true,
		DNSServers: []string{"8.8.8.8"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.SetupInterfaceRoute(types.InterfaceInfo{
		Name:       "wlan0",
		TableID:    0x103,
		Gateway:    "192.168.1.1",
		DNSServers: []string{"1.1.1.1", "9.9.9.9:53"},
	}); err != nil {
		t.Fatal(err)
	}

	if got := e.InterfaceDNS("wg0"); !reflect.DeepEqual(got, []string{"10.64.0.1", "fd00::53"}) {
		t.Fatalf("wg0 DNS = %v, want [10.64.0.1 fd00::53]", got)
	}
	if got := e.InterfaceDNS("wlan0"); !reflect.DeepEqual(got, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Fatalf("wlan0 DNS = %v, want [1.1.1.1 9.9.9.9]", got)
	}

	ruleset, _ := e.buildRuleset()
	checks := []string{
		"chain output_nat {",
		"type nat hook output priority dstnat; policy accept;",
		"ip daddr != { 1.1.1.1, 9.9.9.9 } meta mark 0x103 udp dport 53 dnat ip to 1.1.1.1",
		"ip daddr != { 1.1.1.1, 9.9.9.9 } meta mark 0x103 tcp dport 53 dnat ip to 1.1.1.1",
		"ip daddr != 10.64.0.1 meta mark 0x104 udp dport 53 dnat ip to 10.64.0.1",
		"ip daddr != 10.64.0.1 meta mark 0x104 tcp dport 53 dnat ip to 10.64.0.1",
		"ip6 daddr != fd00::53 meta mark 0x104 udp dport 53 dnat ip6 to fd00::53",
		"ip6 daddr != fd00::53 meta mark 0x104 tcp dport 53 dnat ip6 to fd00::53",
	}
	for _, want := range checks {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("missing DNS isolation rule %q in:\n%s", want, ruleset)
		}
	}

	// Clearing explicit override reverts wg0 to discovered DNS (8.8.8.8).
	e.SetInterfaceDNS("wg0", nil)
	if got := e.InterfaceDNS("wg0"); !reflect.DeepEqual(got, []string{"8.8.8.8"}) {
		t.Fatalf("wg0 DNS after override clear = %v, want [8.8.8.8]", got)
	}

	// DNS isolation must remain active even when eBPF handles socket marking.
	e.SetMarking(false)
	ruleset, _ = e.buildRuleset()
	if strings.Contains(ruleset, "socket cgroupv2") {
		t.Fatalf("socket cgroupv2 rules must stay omitted when marking=false")
	}
	if !strings.Contains(ruleset, "chain output_nat {") {
		t.Fatalf("output_nat must stay active when DNS servers are configured")
	}
}

func TestDestinationAndDomainSplitTunneling(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"wg-work", "wlan0", "blocked"} {
		if err := os.MkdirAll(filepath.Join(root, "netweaver", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	e := NewEngineWithCgroupRoot(root)
	e.ifaces["wlan0"] = types.InterfaceInfo{Name: "wlan0", TableID: 0x103}
	e.ifaces["wg-work"] = types.InterfaceInfo{Name: "wg-work", TableID: 0x105}
	e.ifaces["ghost0"] = types.InterfaceInfo{Name: "ghost0", TableID: 0x109}

	var lookedUp []string
	e.SetLookupFunc(func(host string) ([]net.IP, error) {
		lookedUp = append(lookedUp, host)
		switch host {
		case "ac.in":
			return []net.IP{
				net.ParseIP("14.139.0.10"),
				net.ParseIP("2405:200::10"),
			}, nil
		case "fail.invalid":
			return nil, errors.New("nxdomain")
		default:
			return nil, nil
		}
	})

	e.SetDestinationRules([]types.Rule{
		{
			Match:     "firefox",
			Interface: "wg-work",
			Domains:   []string{"*.ac.in", "10.0.0.0/8", "192.168.50.5", "2001:db8::/32", "fail.invalid"},
		},
		{
			Match:     "curl",
			Interface: "ghost0",
			Domains:   []string{"172.16.0.0/12"},
		},
	})

	if len(lookedUp) != 2 || lookedUp[0] != "ac.in" || lookedUp[1] != "fail.invalid" {
		t.Fatalf("unexpected lookup hosts: %v", lookedUp)
	}

	v4, v6 := e.DestinationSplit("wg-work")
	if !reflect.DeepEqual(v4, []string{"10.0.0.0/8", "14.139.0.10", "192.168.50.5"}) {
		t.Fatalf("wg-work v4 split = %v", v4)
	}
	if !reflect.DeepEqual(v6, []string{"2001:db8::/32", "2405:200::10"}) {
		t.Fatalf("wg-work v6 split = %v", v6)
	}

	ruleset, skipped := e.buildRuleset()
	if len(skipped) != 1 || skipped[0] != "ghost0" {
		t.Fatalf("skipped = %v, want [ghost0]", skipped)
	}

	// Sanitized set names and interval flags.
	expectedParts := []string{
		"set dst4_wg_work {",
		"type ipv4_addr",
		"flags interval",
		"auto-merge",
		"elements = { 10.0.0.0/8, 14.139.0.10, 192.168.50.5 }",
		"set dst6_wg_work {",
		"type ipv6_addr",
		"elements = { 2001:db8::/32, 2405:200::10 }",
		"ip daddr @dst4_wg_work meta mark set 0x105",
		"ip6 daddr @dst6_wg_work meta mark set 0x105",
	}
	for _, part := range expectedParts {
		if !strings.Contains(ruleset, part) {
			t.Fatalf("missing %q in ruleset:\n%s", part, ruleset)
		}
	}

	// Skipped cgroup interface must not leave dangling sets.
	if strings.Contains(ruleset, "dst4_ghost0") {
		t.Fatalf("skipped interface must not emit destination set:\n%s", ruleset)
	}

	// Destination override rules must follow blocked drop and cgroup socket marking.
	dropIdx := strings.Index(ruleset, `socket cgroupv2 level 2 "netweaver/blocked" drop`)
	markIdx := strings.Index(ruleset, `socket cgroupv2 level 2 "netweaver/wlan0" meta mark set 0x103`)
	dstIdx := strings.Index(ruleset, `ip daddr @dst4_wg_work meta mark set 0x105`)
	if dropIdx < 0 || markIdx < 0 || dstIdx < 0 || !(dropIdx < markIdx && markIdx < dstIdx) {
		t.Fatalf("unexpected rule order (drop=%d, mark=%d, dst=%d):\n%s", dropIdx, markIdx, dstIdx, ruleset)
	}

	// Clearing destination split removes sets cleanly.
	e.SetDestinationSplit("wg-work", nil)
	ruleset, _ = e.buildRuleset()
	if strings.Contains(ruleset, "dst4_wg_work") || strings.Contains(ruleset, "dst6_wg_work") {
		t.Fatalf("expected destination sets to be removed:\n%s", ruleset)
	}
}

func TestEngineConcurrentDNSAndRulesetAccess(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "netweaver", "wlan0"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := NewEngineWithCgroupRoot(root)
	e.SetLookupFunc(func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	})
	e.runCmdFn = func(name string, args ...string) error { return nil }
	e.runNftFn = func(ruleset string, skipped []string) error { return nil }
	_ = e.SetupInterfaceRoute(types.InterfaceInfo{Name: "wlan0", TableID: 0x103, Gateway: "192.168.1.1"})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if idx%2 == 0 {
					e.SetInterfaceDNS("wlan0", []string{"1.1.1.1"})
					e.SetDestinationSplit("wlan0", []string{"example.com"})
				} else {
					_ = e.InterfaceDNS("wlan0")
					_, _ = e.buildRuleset()
					_, _ = e.DestinationSplit("wlan0")
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestTeardownCleansNftAndInterfaceTables(t *testing.T) {
	e := NewEngineWithCgroupRoot(t.TempDir())
	var cmds []string
	e.runCmdFn = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil
	}
	e.ifaces["wg0"] = types.InterfaceInfo{Name: "wg0", TableID: 0x104}

	if err := e.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	want := []string{
		"nft delete table inet netweaver",
		"ip rule del fwmark 0x104 table 260",
		"ip -6 rule del fwmark 0x104 table 260",
		"ip route flush table 260",
		"ip -6 route flush table 260",
	}
	if !reflect.DeepEqual(cmds, want) {
		t.Fatalf("Teardown cmds = %v\nwant %v", cmds, want)
	}
}
