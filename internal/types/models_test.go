// internal/types/models_test.go
package types

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestInterfaceInfoValidation(t *testing.T) {
	valid := InterfaceInfo{
		Name:    "wlan0",
		Index:   3,
		IP:      "192.168.1.100",
		Gateway: "192.168.1.1",
		TableID: 103,
		Up:      true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid interface, got: %v", err)
	}

	invalidName := valid
	invalidName.Name = "../evil/path"
	if err := invalidName.Validate(); err == nil {
		t.Fatal("expected error on malicious interface name, got nil")
	}

	invalidTable := valid
	invalidTable.TableID = 0
	if err := invalidTable.Validate(); err == nil {
		t.Fatal("expected error on zero TableID, got nil")
	}
}

func TestIsVirtualProfile(t *testing.T) {
	valid := []string{ProfileLowLatency, ProfileHighBandwidth, ProfileUnmetered, "@bulk"}
	for _, p := range valid {
		if !IsVirtualProfile(p) {
			t.Errorf("IsVirtualProfile(%q) = false, want true", p)
		}
	}

	invalid := []string{"", "wlan0", "@unknown", "@low_latency", "low-latency"}
	for _, p := range invalid {
		if IsVirtualProfile(p) {
			t.Errorf("IsVirtualProfile(%q) = true, want false", p)
		}
	}
}

func TestExtendedModelsJSONRoundTrip(t *testing.T) {
	iface := InterfaceInfo{
		Name:            "wg0",
		Index:           9,
		IP:              "10.0.0.2",
		Gateway:         "10.0.0.1",
		TableID:         109,
		Up:              true,
		IsTunnel:        true,
		LatencyMs:       12.5,
		JitterMs:        1.2,
		PacketLoss:      0.1,
		Healthy:         false,
		HealthScore:     42.5,
		Metered:         true,
		DailyQuotaBytes: 1000,
		DailyUsedBytes:  250,
		QuotaExceeded:   true,
		DNSServers:      []string{"1.1.1.1", "9.9.9.9"},
	}
	raw, err := json.Marshal(iface)
	if err != nil {
		t.Fatalf("marshal iface: %v", err)
	}
	var gotIface InterfaceInfo
	if err := json.Unmarshal(raw, &gotIface); err != nil {
		t.Fatalf("unmarshal iface: %v", err)
	}
	if !reflect.DeepEqual(gotIface, iface) {
		t.Fatalf("iface roundtrip mismatch: got %+v, want %+v", gotIface, iface)
	}

	proc := ProcessInfo{
		PID:               1234,
		Name:              "curl",
		AssignedInterface: "wg0",
		Blocked:           true,
		RateLimitBps:      512000,
		Profile:           ProfileLowLatency,
	}
	raw, err = json.Marshal(proc)
	if err != nil {
		t.Fatalf("marshal proc: %v", err)
	}
	var gotProc ProcessInfo
	if err := json.Unmarshal(raw, &gotProc); err != nil {
		t.Fatalf("unmarshal proc: %v", err)
	}
	if !reflect.DeepEqual(gotProc, proc) {
		t.Fatalf("proc roundtrip mismatch: got %+v, want %+v", gotProc, proc)
	}

	quota := QuotaConfig{
		Interface:       "wwan0",
		Metered:         true,
		DailyLimitBytes: 5_000_000,
		UsedBytes:       1_000_000,
		WarnPercent:     80,
	}
	raw, err = json.Marshal(quota)
	if err != nil {
		t.Fatalf("marshal quota: %v", err)
	}
	var gotQuota QuotaConfig
	if err := json.Unmarshal(raw, &gotQuota); err != nil {
		t.Fatalf("unmarshal quota: %v", err)
	}
	if !reflect.DeepEqual(gotQuota, quota) {
		t.Fatalf("quota roundtrip mismatch: got %+v, want %+v", gotQuota, quota)
	}

	ev := Event{
		ID:            7,
		Timestamp:     1700000000,
		Type:          "failover",
		PID:           1234,
		App:           "firefox",
		Interface:     "eno1",
		FromInterface: "wlan0",
		Policy:        PolicyFailover,
		Message:       "moved to eno1",
	}
	raw, err = json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var gotEv Event
	if err := json.Unmarshal(raw, &gotEv); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if !reflect.DeepEqual(gotEv, ev) {
		t.Fatalf("event roundtrip mismatch: got %+v, want %+v", gotEv, ev)
	}
}
