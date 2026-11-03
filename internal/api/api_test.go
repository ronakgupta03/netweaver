// internal/api/api_test.go
package api

import (
	"os"
	"path/filepath"
	"testing"
	"netweaver/internal/types"
)

type mockBackend struct{}

func (m *mockBackend) ListInterfaces() ([]types.InterfaceInfo, error) {
	return []types.InterfaceInfo{{Name: "wlan0", Index: 3, TableID: 0x103, Up: true}}, nil
}

func (m *mockBackend) ListProcesses() ([]types.ProcessInfo, error) {
	return []types.ProcessInfo{{PID: 9999, Name: "testproc", AssignedInterface: "wlan0"}}, nil
}

func (m *mockBackend) AssignRoute(pid int, iface string) error {
	return nil
}

func (m *mockBackend) ResetRoute(pid int) error {
	return nil
}

func TestIPCCommunication(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sock-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "netweaver.sock")
	srv := NewServer(sockPath, &mockBackend{})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	client := NewClient(sockPath)
	ifaces, err := client.ListInterfaces()
	if err != nil {
		t.Fatalf("client call failed: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].Name != "wlan0" {
		t.Fatalf("unexpected ifaces: %+v", ifaces)
	}

	procs, err := client.ListProcesses()
	if err != nil {
		t.Fatalf("client call failed: %v", err)
	}
	if len(procs) != 1 || procs[0].Name != "testproc" {
		t.Fatalf("unexpected procs: %+v", procs)
	}
}
