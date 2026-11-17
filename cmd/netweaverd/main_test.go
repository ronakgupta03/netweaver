// cmd/netweaverd/main_test.go
package main

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"netweaver/internal/api"
	"netweaver/internal/autoroute"
	"netweaver/internal/cgroups"
	"netweaver/internal/classifier"
	"netweaver/internal/events"
	"netweaver/internal/interfaces"
	"netweaver/internal/policy"
	"netweaver/internal/process"
	"netweaver/internal/quota"
	"netweaver/internal/routing"
	"netweaver/internal/rules"
	"netweaver/internal/telemetry"
	"netweaver/internal/types"
)

type testHarness struct {
	daemon     *DaemonService
	cgRoot     string
	ifacesMu   sync.Mutex
	ifaces     []types.InterfaceInfo
	nftApplied int
	notifies   []string
}

func newTestHarness(t *testing.T, initial []types.InterfaceInfo) *testHarness {
	t.Helper()
	root := t.TempDir()

	cgMgr := cgroups.NewManagerWithRoot(root)
	if err := cgMgr.InitHierarchy(); err != nil {
		t.Fatalf("InitHierarchy: %v", err)
	}
	if err := cgMgr.EnsureBlockedCgroup(); err != nil {
		t.Fatalf("EnsureBlockedCgroup: %v", err)
	}

	engine := routing.NewEngineWithCgroupRoot(root)
	prober := interfaces.NewHealthProber()
	monitor := interfaces.NewMonitorWithProber(prober)
	scanner := process.NewScanner()
	tel := telemetry.NewEngineWithRoot(root)

	ruleStore := rules.NewStore(filepath.Join(root, "rules.json"))
	policyMgr := policy.NewManager(filepath.Join(root, "settings.json"), ruleStore)
	quotaMgr := quota.NewManager(filepath.Join(root, "quotas.json"))
	eventBus := events.NewBus(256)

	h := &testHarness{
		cgRoot: root,
		ifaces: append([]types.InterfaceInfo(nil), initial...),
	}
	eventBus.SetExecFn(func(name string, args ...string) error {
		h.ifacesMu.Lock()
		h.notifies = append(h.notifies, strings.Join(args, " "))
		h.ifacesMu.Unlock()
		return nil
	})

	d := newDaemonService(cgMgr, engine, monitor, scanner, tel, ruleStore, policyMgr, quotaMgr, eventBus, root)
	d.discoverIfacesFn = func() ([]types.InterfaceInfo, error) {
		h.ifacesMu.Lock()
		defer h.ifacesMu.Unlock()
		out := make([]types.InterfaceInfo, len(h.ifaces))
		copy(out, h.ifaces)
		return out, nil
	}
	d.snapshotIfacesFn = func() []types.InterfaceInfo {
		h.ifacesMu.Lock()
		defer h.ifacesMu.Unlock()
		out := make([]types.InterfaceInfo, len(h.ifaces))
		copy(out, h.ifaces)
		return out
	}
	d.applyNftFn = func() error {
		h.ifacesMu.Lock()
		h.nftApplied++
		h.ifacesMu.Unlock()
		return nil
	}
	for _, info := range initial {
		_ = cgMgr.EnsureInterfaceCgroup(info.Name)
	}
	h.daemon = d
	return h
}

func (h *testHarness) setIfaces(next []types.InterfaceInfo) {
	h.ifacesMu.Lock()
	h.ifaces = append([]types.InterfaceInfo(nil), next...)
	h.ifacesMu.Unlock()
}

func spawnSleeper(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed starting sleeper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	if cmd.Process.Pid <= 100 {
		t.Skipf("pid %d <= 100", cmd.Process.Pid)
	}
	return cmd.Process.Pid
}

func TestAssignRouteWithOptsLeafAndReset(t *testing.T) {
	h := newTestHarness(t, []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, HealthScore: 95},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true, HealthScore: 90},
	})
	pid := spawnSleeper(t)

	if err := h.daemon.AssignRouteWithOpts(pid, "wlan0", types.PolicyStrict, 512*1024); err != nil {
		t.Fatalf("AssignRouteWithOpts: %v", err)
	}

	if got := h.daemon.cgMgr.AssignedCgroup(pid); got != "wlan0" {
		t.Fatalf("AssignedCgroup(%d) = %q, want wlan0", pid, got)
	}
	pids, err := h.daemon.cgMgr.PIDs("wlan0")
	if err != nil || !slices.Contains(pids, pid) {
		t.Fatalf("PIDs(wlan0) = %v (err=%v), expected %d", pids, err, pid)
	}
	if got := h.daemon.policy.Resolve(pid); got != types.PolicyStrict {
		t.Fatalf("policy = %q, want strict", got)
	}
	if got := h.daemon.getRateLimit(pid); got != 512*1024 {
		t.Fatalf("rateLimit = %d, want %d", got, 512*1024)
	}

	evs := h.daemon.ListEvents(0)
	if len(evs) == 0 || evs[len(evs)-1].Type != "assign" || evs[len(evs)-1].Interface != "wlan0" {
		t.Fatalf("expected assign event, got %+v", evs)
	}

	// Plain AssignRoute preserves existing rate limit when moving to eno1.
	if err := h.daemon.AssignRoute(pid, "eno1"); err != nil {
		t.Fatalf("AssignRoute: %v", err)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pid); got != "eno1" {
		t.Fatalf("AssignedCgroup(%d) after move = %q, want eno1", pid, got)
	}
	if got := h.daemon.getRateLimit(pid); got != 512*1024 {
		t.Fatalf("rateLimit should be preserved across plain AssignRoute, got %d", got)
	}

	if err := h.daemon.ResetRoute(pid); err != nil {
		t.Fatalf("ResetRoute: %v", err)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pid); got != "default" {
		t.Fatalf("AssignedCgroup(%d) after reset = %q, want default", pid, got)
	}
	if got := h.daemon.getRateLimit(pid); got != 0 {
		t.Fatalf("rateLimit after reset = %d, want 0", got)
	}
}

func TestVirtualProfileResolutionAndStrictQuarantine(t *testing.T) {
	meteredOnly := []types.InterfaceInfo{
		{Name: "usb0", Index: 5, IP: "10.42.0.2", TableID: 261, Up: true, Healthy: true, Metered: true, LatencyMs: 40, HealthScore: 80},
	}
	h := newTestHarness(t, meteredOnly)
	pidFail := spawnSleeper(t)
	pidStrict := spawnSleeper(t)

	// @unmetered with failover when only metered is up -> error
	if err := h.daemon.AssignRouteWithOpts(pidFail, types.ProfileUnmetered, types.PolicyFailover, 0); err == nil {
		t.Fatal("expected error assigning @unmetered under failover when only metered is up")
	}

	// @unmetered with strict when only metered is up -> quarantine in blocked
	if err := h.daemon.AssignRouteWithOpts(pidStrict, types.ProfileUnmetered, types.PolicyStrict, 0); err != nil {
		t.Fatalf("expected strict quarantine to succeed without leak, got: %v", err)
	}
	if !h.daemon.cgMgr.IsBlocked(pidStrict) {
		t.Fatalf("expected pid %d to be quarantined in blocked cgroup", pidStrict)
	}

	// Now an unmetered interface comes up -> handleInterfaceChanges releases pidStrict to eno1.
	both := []types.InterfaceInfo{
		meteredOnly[0],
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, LatencyMs: 8, HealthScore: 98},
	}
	h.setIfaces(both)
	h.daemon.handleInterfaceChanges(meteredOnly, both)

	if h.daemon.cgMgr.IsBlocked(pidStrict) {
		t.Fatalf("expected pid %d to be released from blocked once eno1 appeared", pidStrict)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pidStrict); got != "eno1" {
		t.Fatalf("AssignedCgroup(%d) = %q, want eno1", pidStrict, got)
	}

	// Test @low-latency selection & dynamic re-evaluation when health/latency flips.
	pidLat := spawnSleeper(t)
	twoUnmetered := []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, LatencyMs: 5, HealthScore: 98},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true, LatencyMs: 45, HealthScore: 70},
	}
	h.setIfaces(twoUnmetered)
	if err := h.daemon.AssignRouteWithOpts(pidLat, types.ProfileLowLatency, types.PolicyFailover, 0); err != nil {
		t.Fatalf("AssignRouteWithOpts(@low-latency): %v", err)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pidLat); got != "eno1" {
		t.Fatalf("expected @low-latency to choose eno1, got %q", got)
	}

	// Flip health so wlan0 is now much healthier / lower latency.
	flipped := []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, LatencyMs: 120, HealthScore: 40},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true, LatencyMs: 6, HealthScore: 99},
	}
	h.setIfaces(flipped)
	h.daemon.handleInterfaceChanges(twoUnmetered, flipped)
	if got := h.daemon.cgMgr.AssignedCgroup(pidLat); got != "wlan0" {
		t.Fatalf("expected @low-latency to migrate to wlan0, got %q", got)
	}
}

func TestManualBlockAndRestoreIsolation(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, HealthScore: 95},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true, HealthScore: 90},
	}
	h := newTestHarness(t, ifaces)
	pid := spawnSleeper(t)
	unassignedPID := spawnSleeper(t)

	if err := h.daemon.AssignRouteWithOpts(pid, "wlan0", types.PolicyStrict, 256*1024); err != nil {
		t.Fatalf("AssignRouteWithOpts: %v", err)
	}
	if err := h.daemon.BlockProcess(pid, true); err != nil {
		t.Fatalf("BlockProcess(true): %v", err)
	}
	if !h.daemon.cgMgr.IsBlocked(pid) {
		t.Fatalf("expected pid %d to be blocked", pid)
	}

	// Interface churn / restoreBlocked must NEVER auto-unblock a manual block.
	h.daemon.handleInterfaceChanges(ifaces, ifaces)
	if !h.daemon.cgMgr.IsBlocked(pid) {
		t.Fatalf("manual block on pid %d was auto-released unexpectedly", pid)
	}

	// Unblocking restores to wlan0 (present & healthy) with rate limit preserved.
	if err := h.daemon.BlockProcess(pid, false); err != nil {
		t.Fatalf("BlockProcess(false): %v", err)
	}
	if h.daemon.cgMgr.IsBlocked(pid) {
		t.Fatalf("expected pid %d unblocked", pid)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pid); got != "wlan0" {
		t.Fatalf("restored iface = %q, want wlan0", got)
	}
	if got := h.daemon.getRateLimit(pid); got != 256*1024 {
		t.Fatalf("rate limit after unblock = %d, want %d", got, 256*1024)
	}

	// Manual block when prevIface disappears -> unblock falls back to BestInterface (eno1).
	if err := h.daemon.BlockProcess(pid, true); err != nil {
		t.Fatal(err)
	}
	onlyEno1 := ifaces[:1]
	h.setIfaces(onlyEno1)
	if err := h.daemon.BlockProcess(pid, false); err != nil {
		t.Fatal(err)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pid); got != "eno1" {
		t.Fatalf("unblock fallback iface = %q, want eno1", got)
	}

	// Manual block on previously unassigned PID -> unblock resets to default.
	if err := h.daemon.BlockProcess(unassignedPID, true); err != nil {
		t.Fatal(err)
	}
	if err := h.daemon.BlockProcess(unassignedPID, false); err != nil {
		t.Fatal(err)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(unassignedPID); got != "default" {
		t.Fatalf("unassigned unblock cgroup = %q, want default", got)
	}
}

func TestSetProcessPolicyAndRateLimit(t *testing.T) {
	h := newTestHarness(t, []types.InterfaceInfo{
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true},
	})
	pid := spawnSleeper(t)

	if err := h.daemon.SetProcessPolicy(pid, "invalid"); err == nil {
		t.Fatal("expected error for invalid process policy")
	}
	if err := h.daemon.SetProcessPolicy(pid, "STRICT"); err != nil {
		t.Fatalf("SetProcessPolicy: %v", err)
	}
	if got := h.daemon.policy.Resolve(pid); got != types.PolicyStrict {
		t.Fatalf("policy = %q, want strict", got)
	}

	// Unassigned PID gets leaf cgroup under default.
	if err := h.daemon.SetProcessRateLimit(pid, 1024*1024); err != nil {
		t.Fatalf("SetProcessRateLimit: %v", err)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pid); got != "default" {
		t.Fatalf("AssignedCgroup = %q, want default", got)
	}
	if got := h.daemon.getRateLimit(pid); got != 1024*1024 {
		t.Fatalf("rateLimit = %d, want %d", got, 1024*1024)
	}

	// Assigning route later keeps or applies rate limit; setting rate limit on assigned PID uses iface leaf.
	if err := h.daemon.AssignRoute(pid, "wlan0"); err != nil {
		t.Fatal(err)
	}
	if err := h.daemon.SetProcessRateLimit(pid, 2*1024*1024); err != nil {
		t.Fatal(err)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pid); got != "wlan0" {
		t.Fatalf("AssignedCgroup = %q, want wlan0", got)
	}
	if got := h.daemon.getRateLimit(pid); got != 2*1024*1024 {
		t.Fatalf("rateLimit = %d, want %d", got, 2*1024*1024)
	}
}

func TestSwitchInterface(t *testing.T) {
	h := newTestHarness(t, []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, HealthScore: 95},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true, HealthScore: 90},
	})
	p1 := spawnSleeper(t)
	p2 := spawnSleeper(t)

	if err := h.daemon.AssignRouteWithOpts(p1, "wlan0", types.PolicyStrict, 256*1024); err != nil {
		t.Fatal(err)
	}
	if err := h.daemon.AssignRoute(p2, "wlan0"); err != nil {
		t.Fatal(err)
	}

	moved, err := h.daemon.SwitchInterface("wlan0", "")
	if err != nil {
		t.Fatalf("SwitchInterface: %v", err)
	}
	if moved != 2 {
		t.Fatalf("moved = %d, want 2", moved)
	}
	if h.daemon.cgMgr.AssignedCgroup(p1) != "eno1" || h.daemon.cgMgr.AssignedCgroup(p2) != "eno1" {
		t.Fatalf("expected both pids on eno1, got %q and %q", h.daemon.cgMgr.AssignedCgroup(p1), h.daemon.cgMgr.AssignedCgroup(p2))
	}
	if h.daemon.policy.Resolve(p1) != types.PolicyStrict || h.daemon.getRateLimit(p1) != 256*1024 {
		t.Fatalf("expected policy & rate limit preserved on p1: pol=%q rate=%d", h.daemon.policy.Resolve(p1), h.daemon.getRateLimit(p1))
	}
}

func TestQuotaLifecycleAndBackgroundQuarantine(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true},
	}
	h := newTestHarness(t, ifaces)
	bgPID := spawnSleeper(t)

	if err := h.daemon.AddRule(types.Rule{
		Match:      "sleep",
		Interface:  "wlan0",
		Policy:     types.PolicyFailover,
		Background: true,
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := h.daemon.AssignRoute(bgPID, "wlan0"); err != nil {
		t.Fatal(err)
	}

	if err := h.daemon.SetQuota(types.QuotaConfig{
		Interface:       "wlan0",
		Metered:         true,
		DailyLimitBytes: 1000,
		WarnPercent:     80,
	}); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	quotas := h.daemon.ListQuotas()
	if len(quotas) != 1 || quotas[0].Interface != "wlan0" || !quotas[0].Metered {
		t.Fatalf("unexpected quotas: %+v", quotas)
	}

	// Simulate baseline + warn + exceed via telemetry reader.
	var rxTotal, txTotal uint64 = 100, 0
	h.daemon.telemetry.SetCgroupStatsReader(func(iface string) (uint64, uint64, bool) {
		if iface == "wlan0" {
			return rxTotal, txTotal, true
		}
		return 0, 0, false
	})
	h.daemon.telemetry.TrackInterface("wlan0")
	h.daemon.telemetry.Sample()
	_, _ = h.daemon.ListInterfaces() // baseline sample (delta 0)

	// Jump to 850 bytes -> JustWarned
	rxTotal = 950
	h.daemon.telemetry.Sample()
	gotIfaces, err := h.daemon.ListInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if !gotIfaces[0].Metered || gotIfaces[0].DailyUsedBytes != 850 || gotIfaces[0].QuotaExceeded {
		t.Fatalf("unexpected interface quota state at warn: %+v", gotIfaces[0])
	}

	// Jump to 1200 bytes -> JustExceeded -> auto-quarantine background process
	rxTotal = 1300
	h.daemon.telemetry.Sample()
	gotIfaces, err = h.daemon.ListInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if !gotIfaces[0].QuotaExceeded {
		t.Fatalf("expected QuotaExceeded=true, got %+v", gotIfaces[0])
	}
	if !h.daemon.cgMgr.IsBlocked(bgPID) {
		t.Fatalf("expected background process pid %d auto-quarantined on quota exceed", bgPID)
	}

	// Raising quota limit releases background process when reconciled.
	if err := h.daemon.SetQuota(types.QuotaConfig{
		Interface:       "wlan0",
		Metered:         true,
		DailyLimitBytes: 10000,
		WarnPercent:     80,
	}); err != nil {
		t.Fatal(err)
	}
	if h.daemon.cgMgr.IsBlocked(bgPID) {
		t.Fatalf("expected background pid %d released after raising quota limit", bgPID)
	}

	if err := h.daemon.RemoveQuota("wlan0"); err != nil {
		t.Fatalf("RemoveQuota: %v", err)
	}
	if got := h.daemon.ListQuotas(); len(got) != 0 {
		t.Fatalf("expected empty quotas after remove, got %+v", got)
	}

	evs := h.daemon.ListEvents(0)
	var sawWarn, sawExceed bool
	for _, ev := range evs {
		if ev.Type == "quota_warn" {
			sawWarn = true
		}
		if ev.Type == "quota_exceeded" {
			sawExceed = true
		}
	}
	if !sawWarn || !sawExceed {
		t.Fatalf("expected quota_warn and quota_exceeded events, got %+v", evs)
	}
}

func TestSetInterfaceDNSAndRulesSplitTunnel(t *testing.T) {
	h := newTestHarness(t, []types.InterfaceInfo{
		{Name: "wg0", Index: 7, IP: "10.8.0.2", TableID: 263, Up: true, Healthy: true, IsTunnel: true},
	})
	router := autoroute.NewRouter(h.daemon.rules, routerAssigner{h.daemon})
	h.daemon.router = router

	if err := h.daemon.SetInterfaceDNS("wg0", []string{"1.1.1.1", "9.9.9.9"}); err != nil {
		t.Fatalf("SetInterfaceDNS: %v", err)
	}
	if got := h.daemon.monitor.DNSOverride("wg0"); len(got) != 2 || got[0] != "1.1.1.1" {
		t.Fatalf("monitor DNSOverride = %v", got)
	}
	if got := h.daemon.engine.InterfaceDNS("wg0"); len(got) != 2 || got[1] != "9.9.9.9" {
		t.Fatalf("engine InterfaceDNS = %v", got)
	}
	if h.nftApplied == 0 {
		t.Fatal("expected ApplyNftables to be called")
	}

	if err := h.daemon.AddRule(types.Rule{
		Match:     "curl",
		Interface: "wg0",
		Policy:    types.PolicyStrict,
		Domains:   []string{"198.51.100.0/24"},
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	v4, _ := h.daemon.engine.DestinationSplit("wg0")
	if !slices.Contains(v4, "198.51.100.0/24") {
		t.Fatalf("DestinationSplit(wg0) = %v, want 198.51.100.0/24", v4)
	}
	if err := h.daemon.RemoveRule("curl"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	v4After, _ := h.daemon.engine.DestinationSplit("wg0")
	if len(v4After) != 0 {
		t.Fatalf("expected empty DestinationSplit after RemoveRule, got %v", v4After)
	}
}

func TestHandleInterfaceChangesUnhealthyNoThrashAndPruneDead(t *testing.T) {
	healthyBoth := []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, HealthScore: 95},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true, HealthScore: 90},
	}
	h := newTestHarness(t, healthyBoth)
	pidStrict := spawnSleeper(t)
	pidFailover := spawnSleeper(t)

	if err := h.daemon.AssignRouteWithOpts(pidStrict, "wlan0", types.PolicyStrict, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.daemon.AssignRouteWithOpts(pidFailover, "wlan0", types.PolicyFailover, 0); err != nil {
		t.Fatal(err)
	}

	// Simulate stale dead PID state + dead leaf cgroup.
	deadPID := 999999999
	deadLeaf, err := h.daemon.cgMgr.EnsureProcessCgroup("eno1", deadPID)
	if err != nil {
		t.Fatal(err)
	}
	_ = h.daemon.cgMgr.AssignPIDToPath(deadLeaf, deadPID)
	h.daemon.stateMu.Lock()
	h.daemon.rateLimits[deadPID] = 1234
	h.daemon.profiles[deadPID] = types.ProfileLowLatency
	h.daemon.stateMu.Unlock()

	// Carrier UP on wlan0, but upstream health dead!
	wlanUnhealthy := []types.InterfaceInfo{
		healthyBoth[0],
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: false, HealthScore: 0},
	}
	h.setIfaces(wlanUnhealthy)
	h.daemon.handleInterfaceChanges(healthyBoth, wlanUnhealthy)

	if !h.daemon.cgMgr.IsBlocked(pidStrict) {
		t.Fatalf("expected strict pid %d quarantined when wlan0 unhealthy", pidStrict)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pidFailover); got != "eno1" {
		t.Fatalf("expected failover pid %d moved to eno1, got %q", pidFailover, got)
	}
	if got := h.daemon.getRateLimit(deadPID); got != 0 {
		t.Fatalf("expected deadPID pruned from rateLimits, got %d", got)
	}

	// Repeated ticks with wlan0 still unhealthy must not thrash / emit duplicate killswitch events.
	beforeEvents := len(h.daemon.ListEvents(0))
	h.daemon.handleInterfaceChanges(wlanUnhealthy, wlanUnhealthy)
	afterEvents := len(h.daemon.ListEvents(0))
	if afterEvents != beforeEvents {
		t.Fatalf("expected no thrashing events on repeated unhealthy tick, got %d -> %d", beforeEvents, afterEvents)
	}

	// wlan0 recovers health -> strict pid restored!
	h.setIfaces(healthyBoth)
	h.daemon.handleInterfaceChanges(wlanUnhealthy, healthyBoth)
	if h.daemon.cgMgr.IsBlocked(pidStrict) {
		t.Fatalf("expected strict pid %d released when wlan0 recovered health", pidStrict)
	}
	if got := h.daemon.cgMgr.AssignedCgroup(pidStrict); got != "wlan0" {
		t.Fatalf("expected strict pid %d restored to wlan0, got %q", pidStrict, got)
	}
}

func TestDaemonServiceIPCRoundTrip(t *testing.T) {
	h := newTestHarness(t, []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true, HealthScore: 95},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true, HealthScore: 90},
	})
	pid := spawnSleeper(t)

	sockPath := filepath.Join(t.TempDir(), "netweaver.sock")
	srv := api.NewServer(sockPath, h.daemon)
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Stop()

	client := api.NewClient(sockPath)
	if err := client.AssignRouteWithOpts(pid, "wlan0", types.PolicyStrict, 128*1024); err != nil {
		t.Fatalf("client.AssignRouteWithOpts: %v", err)
	}
	if err := client.SetProcessPolicy(pid, types.PolicyFailover); err != nil {
		t.Fatalf("client.SetProcessPolicy: %v", err)
	}
	if err := client.SetProcessRateLimit(pid, 256*1024); err != nil {
		t.Fatalf("client.SetProcessRateLimit: %v", err)
	}
	if err := client.BlockProcess(pid, true); err != nil {
		t.Fatalf("client.BlockProcess(true): %v", err)
	}
	if err := client.BlockProcess(pid, false); err != nil {
		t.Fatalf("client.BlockProcess(false): %v", err)
	}
	moved, err := client.SwitchInterface("wlan0", "eno1")
	if err != nil || moved != 1 {
		t.Fatalf("client.SwitchInterface = (%d, %v), want (1, nil)", moved, err)
	}
	if err := client.SetQuota(types.QuotaConfig{Interface: "wlan0", Metered: true, DailyLimitBytes: 5000, WarnPercent: 80}); err != nil {
		t.Fatalf("client.SetQuota: %v", err)
	}
	quotas, err := client.ListQuotas()
	if err != nil || len(quotas) != 1 {
		t.Fatalf("client.ListQuotas = (%+v, %v)", quotas, err)
	}
	if err := client.SetInterfaceDNS("eno1", []string{"1.1.1.1"}); err != nil {
		t.Fatalf("client.SetInterfaceDNS: %v", err)
	}
	ifaces, err := client.ListInterfaces()
	if err != nil || len(ifaces) != 2 {
		t.Fatalf("client.ListInterfaces = (%+v, %v)", ifaces, err)
	}
	evs, err := client.ListEvents(0)
	if err != nil || len(evs) < 5 {
		t.Fatalf("client.ListEvents = (%d events, %v)", len(evs), err)
	}

	// Ensure autoroute OptsAssigner passes policy + rate limit.
	assigner := routerAssigner{h.daemon}
	pAuto := spawnSleeper(t)
	if err := assigner.AssignWithOpts(pAuto, types.ProfileLowLatency, types.PolicyStrict, 64*1024); err != nil {
		t.Fatalf("routerAssigner.AssignWithOpts: %v", err)
	}
	if got := assigner.Current(pAuto); got != types.ProfileLowLatency {
		t.Fatalf("routerAssigner.Current = %q, want %q", got, types.ProfileLowLatency)
	}
	// Give async operations a tiny breath before cleanup checks.
	_ = time.Millisecond
}

func TestConcurrentClassifierAccessAndDisable(t *testing.T) {
	ifaces := []types.InterfaceInfo{
		{Name: "eno1", Index: 2, IP: "10.0.0.2", TableID: 258, Up: true, Healthy: true},
		{Name: "wlan0", Index: 3, IP: "192.168.1.5", TableID: 259, Up: true, Healthy: true},
	}
	h := newTestHarness(t, ifaces)
	p1 := spawnSleeper(t)
	p2 := spawnSleeper(t)

	h.daemon.setClassifier(classifier.New(h.cgRoot))
	h.daemon.engine.SetMarking(false)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				switch id % 4 {
				case 0:
					_ = h.daemon.AssignRouteWithOpts(p1, "wlan0", types.PolicyStrict, 1024*1024)
				case 1:
					_ = h.daemon.SetProcessRateLimit(p2, 512*1024)
				case 2:
					_ = h.daemon.BlockProcess(p2, i%2 == 0)
				case 3:
					h.daemon.handleInterfaceChanges(ifaces, ifaces)
				}
			}
		}(g)
	}
	wg.Wait()

	if h.daemon.hasClassifier() {
		t.Fatal("expected unloaded classifier to be disabled and cleared")
	}
	if !h.daemon.engine.MarkingEnabled() {
		t.Fatal("expected nftables marking fallback to be restored")
	}
}

