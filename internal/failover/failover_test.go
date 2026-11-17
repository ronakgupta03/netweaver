package failover

import (
	"reflect"
	"testing"

	"netweaver/internal/types"
)

type fakeMover struct {
	pids      map[string][]int
	policies  map[int]string
	assigned  map[int]string
	blocked   map[int]bool
	failBlock bool
}

func newFakeMover() *fakeMover {
	return &fakeMover{
		pids:     make(map[string][]int),
		policies: make(map[int]string),
		assigned: make(map[int]string),
		blocked:  make(map[int]bool),
	}
}

func (f *fakeMover) PIDs(iface string) ([]int, error) { return f.pids[iface], nil }
func (f *fakeMover) Assign(iface string, pid int) error {
	f.assigned[pid] = iface
	return nil
}
func (f *fakeMover) Block(pid int, from string) error {
	if f.failBlock {
		return errBlocked
	}
	f.blocked[pid] = true
	return nil
}
func (f *fakeMover) Policy(pid int) string {
	if p, ok := f.policies[pid]; ok {
		return p
	}
	return types.PolicyFailover
}

var errBlocked = &blockedErr{}

type blockedErr struct{}

func (*blockedErr) Error() string { return "block refused" }

func TestBestInterfaceUsesPriorityOrder(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"prefers ethernet", []string{"enp5s0f4u2", "wlan0", "eno1"}, "eno1"},
		{"wifi over usb tether", []string{"enp5s0f4u2", "wlan0"}, "wlan0"},
		{"usb tether only", []string{"enp5s0f4u2"}, "enp5s0f4u2"},
		{"ignores loopback", []string{"lo"}, ""},
		{"empty", nil, ""},
	}
	for _, c := range cases {
		if got := BestInterface(c.in); got != c.want {
			t.Fatalf("%s: BestInterface(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestHandleLossFailoverMovesToBestRemaining(t *testing.T) {
	m := newFakeMover()
	m.pids["wlan0"] = []int{1001, 1002}
	m.policies[1002] = types.PolicyFailover

	actions := HandleLoss([]string{"wlan0"}, []string{"enp5s0f4u2", "eno1"}, m)
	if len(actions) != 2 {
		t.Fatalf("actions = %d, want 2", len(actions))
	}
	for _, pid := range []int{1001, 1002} {
		if m.assigned[pid] != "eno1" {
			t.Fatalf("pid %d moved to %q, want eno1", pid, m.assigned[pid])
		}
	}
}

func TestHandleLossStrictBlocksInsteadOfLeaking(t *testing.T) {
	m := newFakeMover()
	m.pids["wlan0"] = []int{2001, 2002}
	m.policies[2001] = types.PolicyStrict

	actions := HandleLoss([]string{"wlan0"}, []string{"eno1"}, m)

	if !m.blocked[2001] {
		t.Fatal("strict process must be quarantined")
	}
	if m.assigned[2001] != "" {
		t.Fatal("strict process must not be moved to another interface")
	}
	if m.assigned[2002] != "eno1" {
		t.Fatalf("failover process moved to %q, want eno1", m.assigned[2002])
	}
	var strictAction *Action
	for i := range actions {
		if actions[i].PID == 2001 {
			strictAction = &actions[i]
		}
	}
	if strictAction == nil || !strictAction.Blocked || strictAction.To != "" {
		t.Fatalf("strict action = %+v", strictAction)
	}
}

func TestHandleLossWithoutSurvivorLeavesProcessesInPlace(t *testing.T) {
	m := newFakeMover()
	m.pids["wlan0"] = []int{3001}

	actions := HandleLoss([]string{"wlan0"}, nil, m)
	if len(actions) != 1 || actions[0].To != "" || actions[0].Blocked {
		t.Fatalf("actions = %+v", actions)
	}
	if m.assigned[3001] != "" {
		t.Fatal("process must not be moved when no interface survives")
	}
}

func TestHandleLossSkipsUnknownInterface(t *testing.T) {
	m := newFakeMover()
	if actions := HandleLoss([]string{"ghost0"}, []string{"wlan0"}, m); len(actions) != 0 {
		t.Fatalf("expected no actions, got %+v", actions)
	}
}

func TestBestInterfaceWithTunnelAndUSB(t *testing.T) {
	if got := BestInterface([]string{"enp5s0f4u2", "wg0", "tun0"}); got != "tun0" {
		t.Fatalf("expected tunnel over USB, got %q", got)
	}
	if got := BestInterface([]string{"wg0", "wlan0", "eno1"}); got != "eno1" {
		t.Fatalf("expected eno1 over wlan0 and wg0, got %q", got)
	}
	if got := BestInterface([]string{"wg0", "wlan0"}); got != "wlan0" {
		t.Fatalf("expected wlan0 over wg0, got %q", got)
	}
}

func TestUnhealthyInterfaces(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "lo", Up: true, Healthy: false},
		{Name: "eno1", Up: true, Healthy: true},
		{Name: "wlan0", Up: true, Healthy: false},
		{Name: "usb0", Up: false, Healthy: false}, // down link is not carrier-up unhealthy
		{Name: "wg0", Up: true, Healthy: false},
	}

	got := UnhealthyInterfaces(ifaces)
	want := []string{"wlan0", "wg0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnhealthyInterfaces = %v, want %v", got, want)
	}

	if gotNone := UnhealthyInterfaces([]types.InterfaceInfo{
		{Name: "eno1", Up: true, Healthy: true},
	}); len(gotNone) != 0 {
		t.Fatalf("expected no unhealthy interfaces, got %v", gotNone)
	}
}

func TestResolveSmartProfileLowLatency(t *testing.T) {
	// Chooses lowest latency/jitter/loss healthy non-tunnel, non-quota-exceeded interface.
	ifaces := []types.InterfaceInfo{
		{Name: "eno1", Up: true, Healthy: true, LatencyMs: 35, JitterMs: 4, PacketLoss: 0, HealthScore: 92},
		{Name: "wlan0", Up: true, Healthy: true, LatencyMs: 8, JitterMs: 1, PacketLoss: 0, HealthScore: 98},
		{Name: "wg0", Up: true, Healthy: true, IsTunnel: true, LatencyMs: 3, JitterMs: 0.5, PacketLoss: 0, HealthScore: 99},
		{Name: "usb0", Up: true, Healthy: true, LatencyMs: 4, JitterMs: 1, PacketLoss: 0, HealthScore: 99, QuotaExceeded: true},
		{Name: "eth1", Up: true, Healthy: false, LatencyMs: 1, HealthScore: 0},
	}
	if got := ResolveSmartProfile(types.ProfileLowLatency, ifaces); got != "wlan0" {
		t.Fatalf("expected wlan0 (healthy non-tunnel, !QuotaExceeded, lowest latency), got %q", got)
	}

	// Falls back to tunnel if only tunnel is healthy.
	tunnelOnly := []types.InterfaceInfo{
		{Name: "eno1", Up: true, Healthy: false, LatencyMs: 10, HealthScore: 0},
		{Name: "wg0", Up: true, Healthy: true, IsTunnel: true, LatencyMs: 18, JitterMs: 2, HealthScore: 96},
	}
	if got := ResolveSmartProfile(types.ProfileLowLatency, tunnelOnly); got != "wg0" {
		t.Fatalf("expected fallback to healthy tunnel wg0, got %q", got)
	}

	// Handles interfaces with LatencyMs/JitterMs populated and HealthScore left 0.
	noScore := []types.InterfaceInfo{
		{Name: "eno1", Up: true, Healthy: true, LatencyMs: 40, JitterMs: 8},
		{Name: "wlan0", Up: true, Healthy: true, LatencyMs: 11, JitterMs: 1.5},
	}
	if got := ResolveSmartProfile(types.ProfileLowLatency, noScore); got != "wlan0" {
		t.Fatalf("expected wlan0 when HealthScore omitted, got %q", got)
	}

	// Avoids high-packet-loss link even if raw RTT is slightly lower.
	lossy := []types.InterfaceInfo{
		{Name: "eno1", Up: true, Healthy: true, LatencyMs: 5, JitterMs: 1, PacketLoss: 30, HealthScore: 68.75},
		{Name: "wlan0", Up: true, Healthy: true, LatencyMs: 14, JitterMs: 2, PacketLoss: 0, HealthScore: 96.9},
	}
	if got := ResolveSmartProfile(types.ProfileLowLatency, lossy); got != "wlan0" {
		t.Fatalf("expected clean wlan0 over lossy eno1, got %q", got)
	}
}

func TestResolveSmartProfileHighBandwidthAndBulk(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "usb0", Up: true, Healthy: true, Metered: true, HealthScore: 99},
		{Name: "wlan0", Up: true, Healthy: true, Metered: false, HealthScore: 97},
		{Name: "eno1", Up: true, Healthy: true, Metered: false, HealthScore: 94},
		{Name: "wg0", Up: true, Healthy: true, IsTunnel: true, Metered: false, HealthScore: 98},
	}
	if got := ResolveSmartProfile(types.ProfileHighBandwidth, ifaces); got != "eno1" {
		t.Fatalf("@high-bandwidth expected eno1, got %q", got)
	}
	if got := ResolveSmartProfile(types.ProfileBulk, ifaces); got != "eno1" {
		t.Fatalf("@bulk expected eno1, got %q", got)
	}

	// Prefers !Metered && !QuotaExceeded over higher-priority metered/quota-exceeded link.
	quotaAndMetered := []types.InterfaceInfo{
		{Name: "eno1", Up: true, Healthy: true, Metered: false, QuotaExceeded: true, HealthScore: 99},
		{Name: "enp5s0f4u2", Up: true, Healthy: true, Metered: true, QuotaExceeded: false, HealthScore: 99},
		{Name: "wlan0", Up: true, Healthy: true, Metered: false, QuotaExceeded: false, HealthScore: 91},
	}
	if got := ResolveSmartProfile(types.ProfileHighBandwidth, quotaAndMetered); got != "wlan0" {
		t.Fatalf("expected unmetered non-exceeded wlan0, got %q", got)
	}

	// Same interface priority tie-breaks by highest HealthScore.
	samePriority := []types.InterfaceInfo{
		{Name: "wlan0", Up: true, Healthy: true, HealthScore: 82},
		{Name: "wlan1", Up: true, Healthy: true, HealthScore: 96},
	}
	if got := ResolveSmartProfile(types.ProfileBulk, samePriority); got != "wlan1" {
		t.Fatalf("expected wlan1 with higher HealthScore, got %q", got)
	}
}

func TestResolveSmartProfileUnmeteredAndEdgeCases(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "usb0", Up: true, Healthy: true, Metered: true, HealthScore: 99},
		{Name: "eno1", Up: true, Healthy: true, Metered: false, QuotaExceeded: true, HealthScore: 99},
		{Name: "wlan0", Up: true, Healthy: false, Metered: false, QuotaExceeded: false, HealthScore: 0},
	}
	if got := ResolveSmartProfile(types.ProfileUnmetered, ifaces); got != "" {
		t.Fatalf("expected empty string when no healthy unmetered !QuotaExceeded link exists, got %q", got)
	}

	withUnmetered := append(ifaces, types.InterfaceInfo{
		Name: "wlp2s0", Up: true, Healthy: true, Metered: false, QuotaExceeded: false, HealthScore: 93,
	})
	if got := ResolveSmartProfile(types.ProfileUnmetered, withUnmetered); got != "wlp2s0" {
		t.Fatalf("expected wlp2s0, got %q", got)
	}

	// Unknown profile and empty/all-unhealthy inputs return "".
	if got := ResolveSmartProfile("@unknown", withUnmetered); got != "" {
		t.Fatalf("expected empty for unknown profile, got %q", got)
	}
	if got := ResolveSmartProfile(types.ProfileLowLatency, nil); got != "" {
		t.Fatalf("expected empty for nil interfaces, got %q", got)
	}
	if got := ResolveSmartProfile(types.ProfileHighBandwidth, []types.InterfaceInfo{
		{Name: "eno1", Up: false, Healthy: true},
		{Name: "wlan0", Up: true, Healthy: false},
	}); got != "" {
		t.Fatalf("expected empty when all interfaces are down or unhealthy, got %q", got)
	}
}
