// internal/cgroups/manager_test.go
package cgroups

import (
	"os"
	"path/filepath"
	"slices"
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
	if !ValidIfaceName("wlan0") || ValidIfaceName("../../etc") {
		t.Fatal("ValidIfaceName check failed")
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

	subPath, err := mgr.EnsureProcessCgroup("wlan0", 6666)
	if err != nil {
		t.Fatalf("EnsureProcessCgroup: %v", err)
	}
	if err := mgr.AssignPIDToPath(subPath, 6666); err != nil {
		t.Fatalf("AssignPIDToPath: %v", err)
	}

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("teardown failed: %v", err)
	}

	rootProcs := filepath.Join(tempDir, "cgroup.procs")
	data, err := os.ReadFile(rootProcs)
	if err != nil {
		t.Fatalf("failed reading root procs: %v", err)
	}
	if !strings.Contains(string(data), "5555") || !strings.Contains(string(data), "6666") {
		t.Fatalf("expected 5555 and 6666 in root procs, got: %q", string(data))
	}
}

func TestIsBlockedAndAssignedCgroup(t *testing.T) {
	tempDir := t.TempDir()
	mgr := NewManagerWithRoot(tempDir)
	if err := mgr.InitHierarchy(); err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureBlockedCgroup(); err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureInterfaceCgroup("wlan0"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureInterfaceCgroup("eno1"); err != nil {
		t.Fatal(err)
	}

	if mgr.IsBlocked(2001) {
		t.Fatal("pid 2001 must not be blocked initially")
	}
	if err := mgr.Block(2001); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !mgr.IsBlocked(2001) {
		t.Fatal("pid 2001 must be reported blocked")
	}
	if got := mgr.AssignedCgroup(2001); got != BlockedCgroup {
		t.Fatalf("AssignedCgroup(2001) = %q, want %q", got, BlockedCgroup)
	}

	if err := mgr.AssignPID("eno1", 3001); err != nil {
		t.Fatal(err)
	}
	if got := mgr.AssignedCgroup(3001); got != "eno1" {
		t.Fatalf("AssignedCgroup(3001) = %q, want eno1", got)
	}

	// Ensure per-process leaf cgroup under wlan0 is discovered by both AssignedCgroup and PIDs.
	subPath, err := mgr.EnsureProcessCgroup("wlan0", 4001)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.AssignPIDToPath(subPath, 4001); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "netweaver", "wlan0", "cgroup.procs"), []byte("4000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := mgr.AssignedCgroup(4001); got != "wlan0" {
		t.Fatalf("AssignedCgroup(4001) = %q, want wlan0", got)
	}
	pids, err := mgr.PIDs("wlan0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pids, 4000) || !slices.Contains(pids, 4001) {
		t.Fatalf("PIDs(wlan0) = %v, want 4000 and 4001", pids)
	}

	// Reject path traversal in AssignPIDToPath.
	if err := mgr.AssignPIDToPath(filepath.Join(tempDir, "other"), 4002); err == nil {
		t.Fatal("expected error for cgroup path outside netweaver/")
	}
}

func TestCleanupDeadProcessCgroups(t *testing.T) {
	tempDir := t.TempDir()
	mgr := NewManagerWithRoot(tempDir)
	if err := mgr.InitHierarchy(); err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureInterfaceCgroup("wlan0"); err != nil {
		t.Fatal(err)
	}

	// Live PID (current test process) must be kept.
	livePID := os.Getpid()
	if livePID <= 100 {
		t.Skip("test pid <= 100")
	}
	livePath, err := mgr.EnsureProcessCgroup("wlan0", livePID)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.AssignPIDToPath(livePath, livePID); err != nil {
		t.Fatal(err)
	}

	// Dead PID leaf cgroup must be removed.
	deadPath, err := mgr.EnsureProcessCgroup("wlan0", 999999999)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.AssignPIDToPath(deadPath, 999999999); err != nil {
		t.Fatal(err)
	}

	if err := mgr.CleanupDeadProcessCgroups(); err != nil {
		t.Fatalf("CleanupDeadProcessCgroups: %v", err)
	}

	if _, err := os.Stat(livePath); err != nil {
		t.Fatalf("live process cgroup should be retained: %v", err)
	}
	if _, err := os.Stat(deadPath); !os.IsNotExist(err) {
		t.Fatalf("dead process cgroup should be removed, stat err = %v", err)
	}
}
