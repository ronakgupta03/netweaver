// internal/routing/engine_test.go
package routing

import (
	"netweaver/internal/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
