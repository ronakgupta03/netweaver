// internal/interfaces/monitor_test.go
package interfaces

import (
	"testing"
)

func TestParseRouteGateway(t *testing.T) {
	// Mock sample ip route output
	sampleOutput := `default via 10.5.50.1 dev wlan0 proto dhcp src 10.5.48.18 metric 600
10.5.48.0/20 dev wlan0 proto dhcp scope link metric 600`

	gw, dev, err := parseDefaultRoute(sampleOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw != "10.5.50.1" {
		t.Fatalf("expected gateway 10.5.50.1, got %s", gw)
	}
	if dev != "wlan0" {
		t.Fatalf("expected dev wlan0, got %s", dev)
	}
}
