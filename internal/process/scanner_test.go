// internal/process/scanner_test.go
package process

import (
	"testing"
)

func TestScanUserApplications(t *testing.T) {
	scanner := NewScanner()
	procs, err := scanner.ScanProcesses()
	if err != nil {
		t.Fatalf("failed to scan processes: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("expected at least one user process to be scanned")
	}
}

func TestIgnoredServicesExcluded(t *testing.T) {
	scanner := NewScanner()
	procs, err := scanner.ScanProcesses()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.Name == "systemd" || p.Name == "pipewire" || p.Name == "wireplumber" || p.Name == "waybar" {
			t.Fatalf("unexpected system service in user app list: %s", p.Name)
		}
	}
}
