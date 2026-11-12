// internal/routing/engine_test.go
package routing

import (
	"netweaver/internal/types"
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
