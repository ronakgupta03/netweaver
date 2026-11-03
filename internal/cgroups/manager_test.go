// internal/cgroups/manager_test.go
package cgroups

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCgroupPathSanitization(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cgroup-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mgr := NewManagerWithRoot(tempDir)

	// Valid interface
	path, err := mgr.InterfaceCgroupPath("wlan0")
	if err != nil {
		t.Fatalf("unexpected error for valid interface: %v", err)
	}
	expected := filepath.Join(tempDir, "netweaver", "wlan0")
	if path != expected {
		t.Fatalf("expected path %q, got %q", expected, path)
	}

	// Malicious interface names
	_, err = mgr.InterfaceCgroupPath("../../etc")
	if err == nil {
		t.Fatal("expected error on path traversal in interface name, got nil")
	}
}

func TestCgroupWritePID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cgroup-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mgr := NewManagerWithRoot(tempDir)
	if err := mgr.InitHierarchy(); err != nil {
		t.Fatalf("failed to init hierarchy: %v", err)
	}

	if err := mgr.EnsureInterfaceCgroup("wlan0"); err != nil {
		t.Fatalf("failed to ensure iface cgroup: %v", err)
	}

	// Write mock PID 1234
	if err := mgr.AssignPID("wlan0", 1234); err != nil {
		t.Fatalf("failed to assign PID: %v", err)
	}

	procsFile := filepath.Join(tempDir, "netweaver", "wlan0", "cgroup.procs")
	data, err := os.ReadFile(procsFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "1234\n" {
		t.Fatalf("expected 1234\\n, got %q", string(data))
	}
}

func TestTeardownMigratesProcesses(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cgroup-test-teardown")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mgr := NewManagerWithRoot(tempDir)
	_ = mgr.InitHierarchy()
	_ = mgr.EnsureInterfaceCgroup("wlan0")
	_ = mgr.AssignPID("wlan0", 5555)

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("teardown failed: %v", err)
	}

	rootProcs := filepath.Join(tempDir, "cgroup.procs")
	data, err := os.ReadFile(rootProcs)
	if err != nil {
		t.Fatalf("failed reading root procs: %v", err)
	}
	if !strings.Contains(string(data), "5555") {
		t.Fatalf("expected 5555 in root procs, got: %q", string(data))
	}
}
