// internal/process/scanner_test.go
package process

import (
	"os"
	"testing"
)

func TestScanCurrentProcess(t *testing.T) {
	scanner := NewScanner()
	procs, err := scanner.ScanProcesses()
	if err != nil {
		t.Fatalf("failed to scan processes: %v", err)
	}

	currentPID := os.Getpid()
	found := false
	for _, p := range procs {
		if p.PID == currentPID {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected current PID %d in scanned processes list", currentPID)
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
