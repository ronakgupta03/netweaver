// internal/interfaces/monitor_test.go
package interfaces

import (
	"testing"
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
