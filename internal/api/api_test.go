// internal/api/api_test.go
package api

import (
	"netweaver/internal/types"
	"os"
	"path/filepath"
	"testing"
)

type mockBackend struct {
	rules  []types.Rule
	policy string
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

func (m *mockBackend) GetPolicy() string {
	if m.policy == "" {
		return types.PolicyFailover
	}
	return m.policy
}

func (m *mockBackend) SetPolicy(p string) error {
	m.policy = p
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

	if p, err := client.GetPolicy(); err != nil || p != types.PolicyFailover {
		t.Fatalf("get policy = %q err=%v", p, err)
	}
	if p, err := client.SetPolicy(types.PolicyStrict); err != nil || p != types.PolicyStrict {
		t.Fatalf("set policy = %q err=%v", p, err)
	}

	// Non-extended backend falls back to AssignRoute and returns clear errors for extended methods.
	if err := client.AssignRouteWithOpts(100, "wlan0", types.PolicyStrict, 1024); err != nil {
		t.Fatalf("AssignRouteWithOpts fallback failed: %v", err)
	}
	if err := client.BlockProcess(100, true); err == nil {
		t.Fatal("expected error for unsupported extended method BlockProcess")
	}
	if _, err := client.ListQuotas(); err == nil {
		t.Fatal("expected error for unsupported extended method ListQuotas")
	}
}

type mockExtendedBackend struct {
	mockBackend
	assignOptsCalls int
	assignCalls     int
	lastPolicy      map[int]string
	blocked         map[int]bool
	rateLimits      map[int]uint64
	quotas          map[string]types.QuotaConfig
	dns             map[string][]string
	events          []types.Event
}

func newMockExtendedBackend() *mockExtendedBackend {
	return &mockExtendedBackend{
		lastPolicy: make(map[int]string),
		blocked:    make(map[int]bool),
		rateLimits: make(map[int]uint64),
		quotas:     make(map[string]types.QuotaConfig),
		dns:        make(map[string][]string),
		events: []types.Event{
			{ID: 1, Timestamp: 100, Type: "assign", PID: 10, Interface: "wlan0", Message: "assigned"},
			{ID: 2, Timestamp: 200, Type: "failover", PID: 10, Interface: "eno1", FromInterface: "wlan0", Message: "moved"},
		},
	}
}

func (m *mockExtendedBackend) AssignRoute(pid int, iface string) error {
	m.assignCalls++
	return nil
}

func (m *mockExtendedBackend) AssignRouteWithOpts(pid int, iface string, policy string, rateLimitBps uint64) error {
	m.assignOptsCalls++
	m.lastPolicy[pid] = policy
	m.rateLimits[pid] = rateLimitBps
	return nil
}

func (m *mockExtendedBackend) SetProcessPolicy(pid int, policy string) error {
	m.lastPolicy[pid] = policy
	return nil
}

func (m *mockExtendedBackend) BlockProcess(pid int, blocked bool) error {
	m.blocked[pid] = blocked
	return nil
}

func (m *mockExtendedBackend) SetProcessRateLimit(pid int, bps uint64) error {
	m.rateLimits[pid] = bps
	return nil
}

func (m *mockExtendedBackend) SwitchInterface(fromIface, toIface string) (int, error) {
	return 3, nil
}

func (m *mockExtendedBackend) ListQuotas() []types.QuotaConfig {
	out := make([]types.QuotaConfig, 0, len(m.quotas))
	for _, q := range m.quotas {
		out = append(out, q)
	}
	return out
}

func (m *mockExtendedBackend) SetQuota(cfg types.QuotaConfig) error {
	m.quotas[cfg.Interface] = cfg
	return nil
}

func (m *mockExtendedBackend) RemoveQuota(iface string) error {
	delete(m.quotas, iface)
	return nil
}

func (m *mockExtendedBackend) SetInterfaceDNS(iface string, servers []string) error {
	m.dns[iface] = append([]string(nil), servers...)
	return nil
}

func (m *mockExtendedBackend) ListEvents(since uint64) []types.Event {
	var out []types.Event
	for _, ev := range m.events {
		if ev.ID > since {
			out = append(out, ev)
		}
	}
	return out
}

func TestExtendedIPCCommunication(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "netweaver.sock")
	backend := newMockExtendedBackend()
	srv := NewServer(sockPath, backend)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	client := NewClient(sockPath)

	// Plain AssignRoute should call AssignRoute, not AssignRouteWithOpts.
	if err := client.AssignRoute(100, "wlan0"); err != nil {
		t.Fatalf("AssignRoute: %v", err)
	}
	if backend.assignCalls != 1 || backend.assignOptsCalls != 0 {
		t.Fatalf("expected assignCalls=1 assignOptsCalls=0, got %d / %d", backend.assignCalls, backend.assignOptsCalls)
	}

	// AssignRouteWithOpts with policy or rate limit should call AssignRouteWithOpts.
	if err := client.AssignRouteWithOpts(200, "eno1", types.PolicyStrict, 125000); err != nil {
		t.Fatalf("AssignRouteWithOpts: %v", err)
	}
	if backend.assignOptsCalls != 1 || backend.lastPolicy[200] != types.PolicyStrict || backend.rateLimits[200] != 125000 {
		t.Fatalf("AssignRouteWithOpts state mismatch: calls=%d pol=%q bps=%d", backend.assignOptsCalls, backend.lastPolicy[200], backend.rateLimits[200])
	}

	if err := client.SetProcessPolicy(200, types.PolicyFailover); err != nil {
		t.Fatalf("SetProcessPolicy: %v", err)
	}
	if backend.lastPolicy[200] != types.PolicyFailover {
		t.Fatalf("SetProcessPolicy = %q, want failover", backend.lastPolicy[200])
	}

	if err := client.BlockProcess(200, true); err != nil {
		t.Fatalf("BlockProcess(true): %v", err)
	}
	if !backend.blocked[200] {
		t.Fatal("expected PID 200 blocked")
	}
	if err := client.BlockProcess(200, false); err != nil {
		t.Fatalf("BlockProcess(false): %v", err)
	}
	if backend.blocked[200] {
		t.Fatal("expected PID 200 unblocked")
	}

	if err := client.SetProcessRateLimit(200, 500000); err != nil {
		t.Fatalf("SetProcessRateLimit: %v", err)
	}
	if backend.rateLimits[200] != 500000 {
		t.Fatalf("rateLimit = %d, want 500000", backend.rateLimits[200])
	}

	moved, err := client.SwitchInterface("wlan0", "eno1")
	if err != nil {
		t.Fatalf("SwitchInterface: %v", err)
	}
	if moved != 3 {
		t.Fatalf("moved = %d, want 3", moved)
	}

	q := types.QuotaConfig{Interface: "wwan0", Metered: true, DailyLimitBytes: 1024 * 1024, WarnPercent: 80}
	if err := client.SetQuota(q); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	quotas, err := client.ListQuotas()
	if err != nil {
		t.Fatalf("ListQuotas: %v", err)
	}
	if len(quotas) != 1 || quotas[0].Interface != "wwan0" || !quotas[0].Metered || quotas[0].DailyLimitBytes != 1024*1024 {
		t.Fatalf("unexpected quotas: %+v", quotas)
	}
	if err := client.RemoveQuota("wwan0"); err != nil {
		t.Fatalf("RemoveQuota: %v", err)
	}
	quotas, err = client.ListQuotas()
	if err != nil || len(quotas) != 0 {
		t.Fatalf("expected empty quotas after remove, got %+v err=%v", quotas, err)
	}

	if err := client.SetInterfaceDNS("wg0", []string{"1.1.1.1", "8.8.8.8"}); err != nil {
		t.Fatalf("SetInterfaceDNS: %v", err)
	}
	if len(backend.dns["wg0"]) != 2 || backend.dns["wg0"][0] != "1.1.1.1" {
		t.Fatalf("unexpected DNS servers: %+v", backend.dns["wg0"])
	}

	events, err := client.ListEvents(1)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 || events[0].ID != 2 || events[0].FromInterface != "wlan0" {
		t.Fatalf("unexpected events: %+v", events)
	}

	if _, err := client.call(Request{Method: "quota.set"}); err == nil {
		t.Fatal("expected error when quota payload is nil")
	}
}
