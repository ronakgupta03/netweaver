package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

type fakeBackend struct {
	mu            sync.Mutex
	rules         []types.Rule
	policy        string
	assign        []string
	assignOpts    []assignOptsCall
	resets        []int
	processPolicy map[int]string
	blocked       map[int]bool
	rateLimits    map[int]uint64
	switches      []switchCall
	quotas        map[string]types.QuotaConfig
	dns           map[string][]string
	events        []types.Event
}

type assignOptsCall struct {
	pid          int
	iface        string
	policy       string
	rateLimitBps uint64
}

type switchCall struct {
	from string
	to   string
}

var _ api.ExtendedBackend = (*fakeBackend)(nil)

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		processPolicy: make(map[int]string),
		blocked:       make(map[int]bool),
		rateLimits:    make(map[int]uint64),
		quotas:        make(map[string]types.QuotaConfig),
		dns:           make(map[string][]string),
		events: []types.Event{
			{ID: 1, Timestamp: 1700000001, Type: "assign", PID: 1725, App: "firefox", Interface: "wlan0", Policy: types.PolicyStrict, Message: "assigned firefox to wlan0"},
			{ID: 2, Timestamp: 1700000002, Type: "failover", PID: 1725, App: "firefox", FromInterface: "wlan0", Interface: "eth0", Message: "failed over to eth0"},
		},
	}
}

func (f *fakeBackend) ListInterfaces() ([]types.InterfaceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []types.InterfaceInfo{
		{
			Name:       "wlan0",
			Index:      4,
			IP:         "10.0.0.2",
			Gateway:    "10.0.0.1",
			TableID:    260,
			Up:         true,
			Healthy:    true,
			RxRate:     2048,
			TxRate:     512,
			LatencyMs:  14.5,
			JitterMs:   1.2,
			DNSServers: append([]string(nil), f.dns["wlan0"]...),
		},
	}, nil
}

func (f *fakeBackend) ListProcesses() ([]types.ProcessInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pol := f.processPolicy[1725]
	if pol == "" {
		pol = types.PolicyStrict
	}
	return []types.ProcessInfo{
		{
			PID:               1725,
			Name:              "firefox",
			AssignedInterface: "wlan0",
			Policy:            pol,
			Blocked:           f.blocked[1725],
			RateLimitBps:      f.rateLimits[1725],
		},
	}, nil
}

func (f *fakeBackend) AssignRoute(pid int, iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assign = append(f.assign, iface)
	return nil
}

func (f *fakeBackend) AssignRouteWithOpts(pid int, iface string, policy string, rateLimitBps uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assignOpts = append(f.assignOpts, assignOptsCall{
		pid:          pid,
		iface:        iface,
		policy:       policy,
		rateLimitBps: rateLimitBps,
	})
	if policy != "" {
		f.processPolicy[pid] = policy
	}
	if rateLimitBps > 0 {
		f.rateLimits[pid] = rateLimitBps
	}
	return nil
}

func (f *fakeBackend) ResetRoute(pid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets = append(f.resets, pid)
	return nil
}

func (f *fakeBackend) ListRules() []types.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]types.Rule, len(f.rules))
	copy(out, f.rules)
	return out
}

func (f *fakeBackend) AddRule(rule types.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule)
	return nil
}

func (f *fakeBackend) RemoveRule(match string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.rules {
		if f.rules[i].Match == match {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeBackend) GetPolicy() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy == "" {
		return types.PolicyFailover
	}
	return f.policy
}

func (f *fakeBackend) SetPolicy(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy = p
	return nil
}

func (f *fakeBackend) SetProcessPolicy(pid int, policy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.processPolicy[pid] = policy
	return nil
}

func (f *fakeBackend) BlockProcess(pid int, blocked bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[pid] = blocked
	return nil
}

func (f *fakeBackend) SetProcessRateLimit(pid int, bps uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rateLimits[pid] = bps
	return nil
}

func (f *fakeBackend) SwitchInterface(fromIface, toIface string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.switches = append(f.switches, switchCall{from: fromIface, to: toIface})
	return 2, nil
}

func (f *fakeBackend) ListQuotas() []types.QuotaConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]types.QuotaConfig, 0, len(f.quotas))
	for _, q := range f.quotas {
		out = append(out, q)
	}
	return out
}

func (f *fakeBackend) SetQuota(cfg types.QuotaConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quotas[cfg.Interface] = cfg
	return nil
}

func (f *fakeBackend) RemoveQuota(iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.quotas, iface)
	return nil
}

func (f *fakeBackend) SetInterfaceDNS(iface string, servers []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dns[iface] = append([]string(nil), servers...)
	return nil
}

func (f *fakeBackend) ListEvents(since uint64) []types.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []types.Event
	for _, ev := range f.events {
		if ev.ID > since {
			out = append(out, ev)
		}
	}
	return out
}

func (f *fakeBackend) appendEvent(ev types.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

// basicBackend implements only api.Backend (not ExtendedBackend) to verify graceful fallback.
type basicBackend struct{}

func (b *basicBackend) ListInterfaces() ([]types.InterfaceInfo, error) {
	return []types.InterfaceInfo{{Name: "eth0", Index: 2, IP: "192.168.1.10", TableID: 258, Up: true}}, nil
}
func (b *basicBackend) ListProcesses() ([]types.ProcessInfo, error) {
	return []types.ProcessInfo{{PID: 101, Name: "curl", AssignedInterface: "eth0"}}, nil
}
func (b *basicBackend) AssignRoute(pid int, iface string) error { return nil }
func (b *basicBackend) ResetRoute(pid int) error                { return nil }
func (b *basicBackend) ListRules() []types.Rule                 { return nil }
func (b *basicBackend) AddRule(rule types.Rule) error           { return nil }
func (b *basicBackend) RemoveRule(match string) error           { return nil }
func (b *basicBackend) GetPolicy() string                       { return types.PolicyFailover }
func (b *basicBackend) SetPolicy(policy string) error           { return nil }

func startStackWithBackend(t *testing.T, backend api.Backend, sseInterval time.Duration) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "daemon.sock")

	daemon := api.NewServer(sock, backend)
	if err := daemon.Start(); err != nil {
		t.Fatalf("daemon: %v", err)
	}
	t.Cleanup(daemon.Stop)

	srv := NewServer("127.0.0.1:0", sock)
	srv.sseInterval = sseInterval
	if err := srv.Start(); err != nil {
		t.Fatalf("web: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return "http://" + srv.Addr()
}

func startStack(t *testing.T) (*fakeBackend, string) {
	t.Helper()
	backend := newFakeBackend()
	return backend, startStackWithBackend(t, backend, 0)
}

func TestIndexServesDashboard(t *testing.T) {
	_, base := startStack(t)
	res, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	html := string(body)
	for _, want := range []string{
		"NetWeaver",
		"/api/state",
		"/api/events",
		"/api/block",
		"/api/process-policy",
		"/api/ratelimit",
		"/api/switch",
		"/api/quota",
		"/api/dns",
		"@low-latency",
		"interactiveFocus",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard HTML missing expected token %q", want)
		}
	}
}

func TestStateEndpointReflectsDaemon(t *testing.T) {
	backend, base := startStack(t)
	_ = backend.SetQuota(types.QuotaConfig{Interface: "wlan0", Metered: true, DailyLimitBytes: 1024 * 1024, UsedBytes: 256, WarnPercent: 80})

	res, err := http.Get(base + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var state stateResponse
	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if len(state.Interfaces) != 1 || state.Interfaces[0].Name != "wlan0" || state.Interfaces[0].RxRate != 2048 {
		t.Fatalf("interfaces = %+v", state.Interfaces)
	}
	if len(state.Processes) != 1 || state.Processes[0].Name != "firefox" {
		t.Fatalf("processes = %+v", state.Processes)
	}
	if state.Policy != types.PolicyFailover {
		t.Fatalf("policy = %q", state.Policy)
	}
	if len(state.Quotas) != 1 || state.Quotas[0].Interface != "wlan0" {
		t.Fatalf("quotas = %+v", state.Quotas)
	}
	if len(state.Events) != 2 || state.Events[0].ID != 1 {
		t.Fatalf("events = %+v", state.Events)
	}
}

func TestStateGracefulFallbackOnBasicBackend(t *testing.T) {
	base := startStackWithBackend(t, &basicBackend{}, 0)
	res, err := http.Get(base + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var state stateResponse
	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if len(state.Interfaces) != 1 || state.Interfaces[0].Name != "eth0" {
		t.Fatalf("interfaces = %+v", state.Interfaces)
	}
	if state.Quotas == nil || len(state.Quotas) != 0 {
		t.Fatalf("expected non-nil empty quotas slice, got %#v", state.Quotas)
	}
	if state.Events == nil || len(state.Events) != 0 {
		t.Fatalf("expected non-nil empty events slice, got %#v", state.Events)
	}

	evRes, err := http.Get(base + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer evRes.Body.Close()
	if evRes.StatusCode != http.StatusOK {
		t.Fatalf("/api/events status = %d, want 200", evRes.StatusCode)
	}
	var evPayload struct {
		Events []types.Event `json:"events"`
	}
	if err := json.NewDecoder(evRes.Body).Decode(&evPayload); err != nil {
		t.Fatal(err)
	}
	if len(evPayload.Events) != 0 {
		t.Fatalf("expected 0 events, got %+v", evPayload.Events)
	}
}

func TestRuleAndPolicyMutations(t *testing.T) {
	backend, base := startStack(t)

	res, err := http.Post(base+"/api/rules", "application/json", strings.NewReader(`{"match":"firefox","interface":"@low-latency","policy":"strict","domains":["*.ac.in","10.0.0.0/8"],"rate_limit_bps":524288,"background":true}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("add rule status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	if len(backend.rules) != 1 || backend.rules[0].Policy != types.PolicyStrict || backend.rules[0].Interface != "@low-latency" ||
		len(backend.rules[0].Domains) != 2 || backend.rules[0].RateLimitBps != 524288 || !backend.rules[0].Background {
		backend.mu.Unlock()
		t.Fatalf("rules = %+v", backend.rules)
	}
	backend.mu.Unlock()

	req, _ := http.NewRequest(http.MethodDelete, base+"/api/rules?match=firefox", nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	backend.mu.Lock()
	if len(backend.rules) != 0 {
		backend.mu.Unlock()
		t.Fatalf("rule not deleted: %+v", backend.rules)
	}
	backend.mu.Unlock()

	res, err = http.Post(base+"/api/policy", "application/json", strings.NewReader(`{"policy":"strict"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	backend.mu.Lock()
	if backend.policy != types.PolicyStrict {
		backend.mu.Unlock()
		t.Fatalf("policy = %q, want strict", backend.policy)
	}
	backend.mu.Unlock()

	res, err = http.Post(base+"/api/assign", "application/json", strings.NewReader(`{"pid":1725,"interface":"wlan0"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	backend.mu.Lock()
	if len(backend.assign) != 1 || backend.assign[0] != "wlan0" || len(backend.assignOpts) != 0 {
		backend.mu.Unlock()
		t.Fatalf("assign calls = %v opts = %v", backend.assign, backend.assignOpts)
	}
	backend.mu.Unlock()
}

func TestExtendedAssignAndProcessControls(t *testing.T) {
	backend, base := startStack(t)

	// Extended assign with policy and rate limit
	res, err := http.Post(base+"/api/assign", "application/json", strings.NewReader(`{"pid":1725,"interface":"@low-latency","policy":"strict","rate_limit_bps":1048576}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("extended assign status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	if len(backend.assignOpts) != 1 || backend.assignOpts[0].iface != "@low-latency" ||
		backend.assignOpts[0].policy != types.PolicyStrict || backend.assignOpts[0].rateLimitBps != 1048576 {
		backend.mu.Unlock()
		t.Fatalf("assignOpts = %+v", backend.assignOpts)
	}
	backend.mu.Unlock()

	// Block / Unblock
	res, err = http.Post(base+"/api/block", "application/json", strings.NewReader(`{"pid":1725,"blocked":true}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("block status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	if !backend.blocked[1725] {
		backend.mu.Unlock()
		t.Fatal("expected PID 1725 blocked")
	}
	backend.mu.Unlock()

	res, err = http.Post(base+"/api/block", "application/json", strings.NewReader(`{"pid":1725,"blocked":false}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	backend.mu.Lock()
	if backend.blocked[1725] {
		backend.mu.Unlock()
		t.Fatal("expected PID 1725 unblocked")
	}
	backend.mu.Unlock()

	// Process policy
	res, err = http.Post(base+"/api/process-policy", "application/json", strings.NewReader(`{"pid":1725,"policy":"failover"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("process-policy status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	if backend.processPolicy[1725] != types.PolicyFailover {
		backend.mu.Unlock()
		t.Fatalf("processPolicy = %q, want failover", backend.processPolicy[1725])
	}
	backend.mu.Unlock()

	// Process rate limit (set and clear)
	res, err = http.Post(base+"/api/ratelimit", "application/json", strings.NewReader(`{"pid":1725,"rate_limit_bps":262144}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ratelimit status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	if backend.rateLimits[1725] != 262144 {
		backend.mu.Unlock()
		t.Fatalf("rateLimit = %d, want 262144", backend.rateLimits[1725])
	}
	backend.mu.Unlock()

	res, err = http.Post(base+"/api/ratelimit", "application/json", strings.NewReader(`{"pid":1725,"rate_limit_bps":0}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	backend.mu.Lock()
	if backend.rateLimits[1725] != 0 {
		backend.mu.Unlock()
		t.Fatalf("rateLimit = %d, want 0", backend.rateLimits[1725])
	}
	backend.mu.Unlock()

	// Reset
	res, err = http.Post(base+"/api/reset", "application/json", strings.NewReader(`{"pid":1725}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reset status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	if len(backend.resets) != 1 || backend.resets[0] != 1725 {
		backend.mu.Unlock()
		t.Fatalf("resets = %v", backend.resets)
	}
	backend.mu.Unlock()
}

func TestSwitchQuotaAndDNS(t *testing.T) {
	backend, base := startStack(t)

	// Switch interface
	res, err := http.Post(base+"/api/switch", "application/json", strings.NewReader(`{"from_interface":"wlan0","to_interface":"eth0"}`))
	if err != nil {
		t.Fatal(err)
	}
	var switchResp struct {
		OK    bool `json:"ok"`
		Moved int  `json:"moved"`
	}
	if err := json.NewDecoder(res.Body).Decode(&switchResp); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !switchResp.OK || switchResp.Moved != 2 {
		t.Fatalf("switch resp = %d %+v", res.StatusCode, switchResp)
	}
	backend.mu.Lock()
	if len(backend.switches) != 1 || backend.switches[0].from != "wlan0" || backend.switches[0].to != "eth0" {
		backend.mu.Unlock()
		t.Fatalf("switches = %+v", backend.switches)
	}
	backend.mu.Unlock()

	// Set quota
	res, err = http.Post(base+"/api/quota", "application/json", strings.NewReader(`{"interface":"wwan0","metered":true,"daily_limit_bytes":5242880,"warn_percent":85}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("set quota status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	q, ok := backend.quotas["wwan0"]
	backend.mu.Unlock()
	if !ok || !q.Metered || q.DailyLimitBytes != 5242880 || q.WarnPercent != 85 {
		t.Fatalf("quota = %+v ok=%v", q, ok)
	}

	// Remove quota
	req, _ := http.NewRequest(http.MethodDelete, base+"/api/quota?interface=wwan0", nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete quota status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	_, ok = backend.quotas["wwan0"]
	backend.mu.Unlock()
	if ok {
		t.Fatal("quota was not removed")
	}

	// Set DNS
	res, err = http.Post(base+"/api/dns", "application/json", strings.NewReader(`{"interface":"wlan0","dns_servers":["1.1.1.1"," 8.8.8.8 "]}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("set dns status = %d", res.StatusCode)
	}
	backend.mu.Lock()
	dns := append([]string(nil), backend.dns["wlan0"]...)
	backend.mu.Unlock()
	if len(dns) != 2 || dns[0] != "1.1.1.1" || dns[1] != "8.8.8.8" {
		t.Fatalf("dns = %+v", dns)
	}

	// Clear DNS
	res, err = http.Post(base+"/api/dns", "application/json", strings.NewReader(`{"interface":"wlan0","dns_servers":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	backend.mu.Lock()
	if len(backend.dns["wlan0"]) != 0 {
		backend.mu.Unlock()
		t.Fatalf("expected cleared dns, got %+v", backend.dns["wlan0"])
	}
	backend.mu.Unlock()
}

func TestEventsJSONAndSSE(t *testing.T) {
	backend := newFakeBackend()
	base := startStackWithBackend(t, backend, 25*time.Millisecond)

	// JSON events (all)
	res, err := http.Get(base + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	var allResp struct {
		Events []types.Event `json:"events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&allResp); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(allResp.Events) != 2 {
		t.Fatalf("expected 2 events, got %+v", allResp.Events)
	}

	// JSON events (?since=1)
	res, err = http.Get(base + "/api/events?since=1")
	if err != nil {
		t.Fatal(err)
	}
	var sinceResp struct {
		Events []types.Event `json:"events"`
	}
	if err := json.NewDecoder(res.Body).Decode(&sinceResp); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(sinceResp.Events) != 1 || sinceResp.Events[0].ID != 2 {
		t.Fatalf("expected event ID 2, got %+v", sinceResp.Events)
	}

	// SSE stream via Accept header + ?since=1
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/events?since=1", nil)
	req.Header.Set("Accept", "text/event-stream")
	sseRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sseRes.Body.Close()

	if ct := sseRes.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	dataCh := make(chan types.Event, 8)
	errCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(sseRes.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				var ev types.Event
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err == nil {
					dataCh <- ev
				}
			}
		}
		errCh <- scanner.Err()
	}()

	// Expect initial buffered event ID 2
	select {
	case ev := <-dataCh:
		if ev.ID != 2 || ev.Type != "failover" {
			t.Fatalf("unexpected first SSE event: %+v", ev)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for initial SSE event")
	}

	// Emit a new event and verify it streams on the next poll tick
	backend.appendEvent(types.Event{
		ID:        3,
		Timestamp: 1700000003,
		Type:      "quota",
		Interface: "wwan0",
		Message:   "quota threshold reached",
	})

	select {
	case ev := <-dataCh:
		if ev.ID != 3 || ev.Type != "quota" || ev.Interface != "wwan0" {
			t.Fatalf("unexpected streamed SSE event: %+v", ev)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for live streamed SSE event")
	}

	// SSE stream via ?stream=1 query parameter (without Accept header)
	streamCtx, streamCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer streamCancel()
	streamReq, _ := http.NewRequestWithContext(streamCtx, http.MethodGet, base+"/api/events?stream=1&since=2", nil)
	qRes, err := http.DefaultClient.Do(streamReq)
	if err != nil {
		t.Fatal(err)
	}
	if ct := qRes.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		qRes.Body.Close()
		t.Fatalf("?stream=1 Content-Type = %q, want text/event-stream", ct)
	}
	qScanner := bufio.NewScanner(qRes.Body)
	gotStream1 := false
	for qScanner.Scan() {
		line := qScanner.Text()
		if strings.HasPrefix(line, "data: ") {
			var ev types.Event
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err == nil && ev.ID == 3 {
				gotStream1 = true
				break
			}
		}
	}
	qRes.Body.Close()
	if !gotStream1 {
		t.Fatal("expected event ID 3 via ?stream=1 SSE endpoint")
	}

	cancel()
}

func TestInvalidRequestsRejected(t *testing.T) {
	_, base := startStack(t)

	cases := []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{http.MethodPost, "/api/assign", `{"pid":0}`, http.StatusBadRequest},
		{http.MethodPost, "/api/assign", `{"pid":10,"interface":"wlan0","policy":"bogus"}`, http.StatusBadRequest},
		{http.MethodPost, "/api/block", `{"pid":0,"blocked":true}`, http.StatusBadRequest},
		{http.MethodPost, "/api/process-policy", `{"pid":0,"policy":"strict"}`, http.StatusBadRequest},
		{http.MethodPost, "/api/process-policy", `{"pid":10,"policy":""}`, http.StatusBadRequest},
		{http.MethodPost, "/api/process-policy", `{"pid":10,"policy":"   "}`, http.StatusBadRequest},
		{http.MethodPost, "/api/process-policy", `{"pid":10,"policy":"invalid"}`, http.StatusBadRequest},
		{http.MethodPost, "/api/ratelimit", `{"pid":0,"rate_limit_bps":1000}`, http.StatusBadRequest},
		{http.MethodPost, "/api/switch", `{"from_interface":"wlan0"}`, http.StatusBadRequest},
		{http.MethodPost, "/api/quota", `{"interface":""}`, http.StatusBadRequest},
		{http.MethodDelete, "/api/quota", ``, http.StatusBadRequest},
		{http.MethodPost, "/api/dns", `{"interface":""}`, http.StatusBadRequest},
		{http.MethodGet, "/api/events?since=abc", ``, http.StatusBadRequest},
		{http.MethodGet, "/api/rules", ``, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/block", ``, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/process-policy", ``, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/ratelimit", ``, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/switch", ``, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/quota", ``, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/dns", ``, http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/events", ``, http.StatusMethodNotAllowed},
		{http.MethodGet, "/missing", ``, http.StatusNotFound},
	}

	for _, tc := range cases {
		var body io.Reader
		if tc.body != "" {
			body = strings.NewReader(tc.body)
		}
		req, err := http.NewRequest(tc.method, base+tc.path, body)
		if err != nil {
			t.Fatal(err)
		}
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Fatalf("%s %s body=%s: status = %d, want %d", tc.method, tc.path, tc.body, res.StatusCode, tc.want)
		}
	}
}
