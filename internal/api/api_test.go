// internal/api/api_test.go
package api

import (
	"netweaver/internal/types"
	"os"
	"path/filepath"
	"testing"
)

type mockBackend struct {
	rules []types.Rule
}

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

func (m *mockBackend) ListRules() []types.Rule {
	return m.rules
}

func (m *mockBackend) AddRule(rule types.Rule) error {
	m.rules = append(m.rules, rule)
	return nil
}

func (m *mockBackend) RemoveRule(match string) error {
	for i := range m.rules {
		if m.rules[i].Match == match {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	return nil
}

func TestIPCCommunication(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sock-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "netweaver.sock")
	backend := &mockBackend{}
	srv := NewServer(sockPath, backend)
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

	if err := client.AddRule(types.Rule{Match: "firefox", Interface: "wlan0", Policy: types.PolicyStrict}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	rules, err := client.ListRules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 || rules[0].Interface != "wlan0" || rules[0].Policy != types.PolicyStrict {
		t.Fatalf("unexpected rules: %+v", rules)
	}
	if err := client.RemoveRule("firefox"); err != nil {
		t.Fatalf("remove rule: %v", err)
	}
	if rules, _ := client.ListRules(); len(rules) != 0 {
		t.Fatalf("rule not removed: %+v", rules)
	}
}
