// internal/tui/app_test.go
package tui

import (
	"strings"
	"testing"

	"netweaver/internal/types"

	tea "github.com/charmbracelet/bubbletea"
)

type fakeTUIClient struct {
	processes    []types.ProcessInfo
	interfaces   []types.InterfaceInfo
	quotas       []types.QuotaConfig
	events       []types.Event
	globalPolicy string

	assignCalls        []assignCall
	resetCalls         []int
	processPolicyCalls []policyCall
	blockCalls         []blockCall
	rateCalls          []rateCall
	setPolicyCalls     []string
}

type assignCall struct {
	pid   int
	iface string
}

type policyCall struct {
	pid    int
	policy string
}

type blockCall struct {
	pid     int
	blocked bool
}

type rateCall struct {
	pid int
	bps uint64
}

func (f *fakeTUIClient) ListProcesses() ([]types.ProcessInfo, error) {
	return f.processes, nil
}

func (f *fakeTUIClient) ListInterfaces() ([]types.InterfaceInfo, error) {
	return f.interfaces, nil
}

func (f *fakeTUIClient) GetPolicy() (string, error) {
	if f.globalPolicy == "" {
		return types.PolicyFailover, nil
	}
	return f.globalPolicy, nil
}

func (f *fakeTUIClient) SetPolicy(policy string) (string, error) {
	f.setPolicyCalls = append(f.setPolicyCalls, policy)
	f.globalPolicy = policy
	return policy, nil
}

func (f *fakeTUIClient) AssignRoute(pid int, iface string) error {
	f.assignCalls = append(f.assignCalls, assignCall{pid: pid, iface: iface})
	for i := range f.processes {
		if f.processes[i].PID == pid {
			if types.IsVirtualProfile(iface) {
				f.processes[i].Profile = iface
				f.processes[i].AssignedInterface = "eno1"
			} else {
				f.processes[i].Profile = ""
				f.processes[i].AssignedInterface = iface
			}
		}
	}
	return nil
}

func (f *fakeTUIClient) ResetRoute(pid int) error {
	f.resetCalls = append(f.resetCalls, pid)
	for i := range f.processes {
		if f.processes[i].PID == pid {
			f.processes[i].AssignedInterface = ""
			f.processes[i].Profile = ""
		}
	}
	return nil
}

func (f *fakeTUIClient) SetProcessPolicy(pid int, policy string) error {
	f.processPolicyCalls = append(f.processPolicyCalls, policyCall{pid: pid, policy: policy})
	for i := range f.processes {
		if f.processes[i].PID == pid {
			f.processes[i].Policy = policy
		}
	}
	return nil
}

func (f *fakeTUIClient) BlockProcess(pid int, blocked bool) error {
	f.blockCalls = append(f.blockCalls, blockCall{pid: pid, blocked: blocked})
	for i := range f.processes {
		if f.processes[i].PID == pid {
			f.processes[i].Blocked = blocked
		}
	}
	return nil
}

func (f *fakeTUIClient) SetProcessRateLimit(pid int, bps uint64) error {
	f.rateCalls = append(f.rateCalls, rateCall{pid: pid, bps: bps})
	for i := range f.processes {
		if f.processes[i].PID == pid {
			f.processes[i].RateLimitBps = bps
		}
	}
	return nil
}

func (f *fakeTUIClient) ListQuotas() ([]types.QuotaConfig, error) {
	return f.quotas, nil
}

func (f *fakeTUIClient) ListEvents(since uint64) ([]types.Event, error) {
	return f.events, nil
}

func keyRune(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func TestInitialModel(t *testing.T) {
	m := InitialModel("/tmp/test.sock")
	if m.client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNavigationAndQuit(t *testing.T) {
	fc := &fakeTUIClient{
		processes: []types.ProcessInfo{
			{PID: 101, Name: "firefox"},
			{PID: 202, Name: "curl"},
		},
	}
	m := InitialModelWithClient(fc)
	updated, _ := m.Update(dataLoadedMsg{processes: fc.processes, globalPolicy: types.PolicyFailover})
	m = updated.(Model)

	updated, _ = m.Update(keyRune('j'))
	m = updated.(Model)
	if m.cursor != 1 {
		t.Fatalf("cursor after j = %d, want 1", m.cursor)
	}

	updated, _ = m.Update(keyRune('k'))
	m = updated.(Model)
	if m.cursor != 0 {
		t.Fatalf("cursor after k = %d, want 0", m.cursor)
	}

	_, cmd := m.Update(keyRune('q'))
	if cmd == nil {
		t.Fatal("expected quit cmd on q")
	}
}

func TestEnterCyclesInterfacesAndSmartProfiles(t *testing.T) {
	fc := &fakeTUIClient{
		interfaces: []types.InterfaceInfo{
			{Name: "eno1", Healthy: true},
			{Name: "wlan0", Healthy: true},
		},
		processes: []types.ProcessInfo{
			{PID: 1500, Name: "firefox", AssignedInterface: ""},
		},
	}
	m := InitialModelWithClient(fc)
	updated, _ := m.Update(dataLoadedMsg{processes: fc.processes, interfaces: fc.interfaces})
	m = updated.(Model)

	wantSeq := []string{
		"eno1",
		"wlan0",
		types.ProfileLowLatency,
		types.ProfileHighBandwidth,
		types.ProfileUnmetered,
		"eno1",
	}
	for i, want := range wantSeq {
		updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = updated.(Model)
		if cmd == nil {
			t.Fatalf("step %d: expected fetch cmd", i)
		}
		if len(fc.assignCalls) != i+1 || fc.assignCalls[i].iface != want {
			t.Fatalf("step %d: assignCalls = %+v, want %q", i, fc.assignCalls, want)
		}
		// Simulate refresh
		updated, _ = m.Update(cmd())
		m = updated.(Model)
	}
}

func TestProcessControlsKeybindings(t *testing.T) {
	fc := &fakeTUIClient{
		interfaces: []types.InterfaceInfo{{Name: "wlan0", Healthy: true}},
		processes: []types.ProcessInfo{
			{PID: 2001, Name: "firefox", AssignedInterface: "wlan0", Policy: types.PolicyFailover, Blocked: false, RateLimitBps: 0},
		},
		globalPolicy: types.PolicyFailover,
	}
	m := InitialModelWithClient(fc)
	updated, _ := m.Update(dataLoadedMsg{
		processes:    fc.processes,
		interfaces:   fc.interfaces,
		globalPolicy: types.PolicyFailover,
	})
	m = updated.(Model)

	// [p] toggle per-app policy failover -> strict -> failover
	updated, cmd := m.Update(keyRune('p'))
	m = updated.(Model)
	if len(fc.processPolicyCalls) != 1 || fc.processPolicyCalls[0].policy != types.PolicyStrict {
		t.Fatalf("expected strict policy call, got %+v", fc.processPolicyCalls)
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	updated, cmd = m.Update(keyRune('p'))
	m = updated.(Model)
	if len(fc.processPolicyCalls) != 2 || fc.processPolicyCalls[1].policy != types.PolicyFailover {
		t.Fatalf("expected failover policy call, got %+v", fc.processPolicyCalls)
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	// [b] toggle manual block/unblock
	updated, cmd = m.Update(keyRune('b'))
	m = updated.(Model)
	if len(fc.blockCalls) != 1 || !fc.blockCalls[0].blocked {
		t.Fatalf("expected block(true) call, got %+v", fc.blockCalls)
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	updated, cmd = m.Update(keyRune('b'))
	m = updated.(Model)
	if len(fc.blockCalls) != 2 || fc.blockCalls[1].blocked {
		t.Fatalf("expected block(false) call, got %+v", fc.blockCalls)
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	// [l] cycle rate cap: 0 -> 256KiB -> 1MiB -> 5MiB -> 0
	wantRates := []uint64{256 * 1024, 1024 * 1024, 5 * 1024 * 1024, 0}
	for i, want := range wantRates {
		updated, cmd = m.Update(keyRune('l'))
		m = updated.(Model)
		if len(fc.rateCalls) != i+1 || fc.rateCalls[i].bps != want {
			t.Fatalf("rate step %d: got %+v, want %d", i, fc.rateCalls, want)
		}
		updated, _ = m.Update(cmd())
		m = updated.(Model)
	}

	// [P] toggle global default policy failover -> strict
	updated, cmd = m.Update(keyRune('P'))
	m = updated.(Model)
	if len(fc.setPolicyCalls) != 1 || fc.setPolicyCalls[0] != types.PolicyStrict {
		t.Fatalf("expected global SetPolicy(strict), got %+v", fc.setPolicyCalls)
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)

	// [Space] reset route
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)
	if len(fc.resetCalls) != 1 || fc.resetCalls[0] != 2001 {
		t.Fatalf("expected ResetRoute(2001), got %+v", fc.resetCalls)
	}
}

func TestViewDisplaysTelemetryVPNQuotaBlockedProfileAndRateCap(t *testing.T) {
	m := InitialModelWithClient(&fakeTUIClient{})
	updated, _ := m.Update(dataLoadedMsg{
		globalPolicy: types.PolicyStrict,
		interfaces: []types.InterfaceInfo{
			{
				Name:            "wg0",
				IP:              "10.8.0.2",
				TableID:         263,
				Up:              true,
				Healthy:         true,
				IsTunnel:        true,
				LatencyMs:       18,
				Metered:         true,
				DailyUsedBytes:  512 * 1024,
				DailyQuotaBytes: 1024 * 1024,
			},
			{
				Name:    "wlan0",
				IP:      "192.168.1.10",
				TableID: 259,
				Up:      true,
				Healthy: false,
			},
		},
		processes: []types.ProcessInfo{
			{
				PID:               3001,
				Name:              "firefox",
				AssignedInterface: "wg0",
				Profile:           types.ProfileLowLatency,
				Policy:            types.PolicyStrict,
				RateLimitBps:      1024 * 1024,
				Blocked:           true,
				RxRate:            2048,
				TxRate:            1024,
				RxBytes:           8192,
			},
		},
		events: []types.Event{
			{ID: 1, Type: "killswitch", Message: "quarantined firefox"},
		},
	})
	m = updated.(Model)

	view := m.View()
	expectedTokens := []string{
		"Default: strict",
		"wg0 [VPN]",
		"18ms",
		"512 KiB/1.0 MiB",
		"wlan0",
		"DOWN",
		"[BLOCKED] firefox",
		"wg0 (@low-latency)",
		"strict",
		"1.0 MiB/s",
		"RATE CAP",
		"Latest Event: [killswitch] quarantined firefox",
		"[p] App policy",
		"[b] Block",
		"[l] Rate cap",
		"[P] Global policy",
	}
	for _, tok := range expectedTokens {
		if !strings.Contains(view, tok) {
			t.Fatalf("View() missing %q in:\n%s", tok, view)
		}
	}
}
