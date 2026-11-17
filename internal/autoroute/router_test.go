package autoroute

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"netweaver/internal/rules"
	"netweaver/internal/types"
)

type fakeAssigner struct {
	mu       sync.Mutex
	assigned map[int]string
	calls    []Event
	failFor  map[int]bool
}

func newFakeAssigner() *fakeAssigner {
	return &fakeAssigner{assigned: make(map[int]string), failFor: make(map[int]bool)}
}

func (f *fakeAssigner) Assign(pid int, iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFor[pid] {
		return os.ErrPermission
	}
	f.assigned[pid] = iface
	f.calls = append(f.calls, Event{PID: pid, Interface: iface})
	return nil
}

func (f *fakeAssigner) Current(pid int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assigned[pid]
}

type fakeOptsAssigner struct {
	mu           sync.Mutex
	assigned     map[int]string
	optCalls     []Event
	basicCalls   int
	failFor      map[int]bool
	resolveAs    string
}

func newFakeOptsAssigner() *fakeOptsAssigner {
	return &fakeOptsAssigner{assigned: make(map[int]string), failFor: make(map[int]bool)}
}

func (f *fakeOptsAssigner) Assign(pid int, iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.basicCalls++
	f.assigned[pid] = iface
	return nil
}

func (f *fakeOptsAssigner) AssignWithOpts(pid int, iface, policy string, rateLimitBps uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFor[pid] {
		return os.ErrPermission
	}
	target := iface
	if f.resolveAs != "" {
		target = f.resolveAs
	}
	f.assigned[pid] = target
	f.optCalls = append(f.optCalls, Event{
		PID:          pid,
		Interface:    iface,
		Policy:       policy,
		RateLimitBps: rateLimitBps,
	})
	return nil
}

func (f *fakeOptsAssigner) Current(pid int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assigned[pid]
}

func makeProc(t *testing.T, root string, pid int, name string, uid string, cmdline string) {
	t.Helper()
	dir := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\t"+name+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestScanOnceAssignsMatchingUserProcess(t *testing.T) {
	procRoot := t.TempDir()
	makeProc(t, procRoot, 4001, "firefox", "1000", "/usr/lib/firefox/firefox\x00")
	makeProc(t, procRoot, 4002, "sshd", "0", "/usr/sbin/sshd\x00")

	store := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := store.Add(types.Rule{Match: "firefox", Interface: "wlan0"}); err != nil {
		t.Fatal(err)
	}

	fa := newFakeAssigner()
	router := NewRouterWithProcRoot(store, fa, procRoot)
	if router.interval != 500*time.Millisecond {
		t.Fatalf("default interval = %v, want 500ms", router.interval)
	}

	var got []Event
	router.OnAssign(func(e Event) { got = append(got, e) })

	events := router.ScanOnce()
	if len(events) != 1 || events[0].PID != 4001 || events[0].Interface != "wlan0" {
		t.Fatalf("events = %+v", events)
	}
	if len(got) != 1 {
		t.Fatalf("listener got %d events, want 1", len(got))
	}
	if fa.assigned[4002] != "" {
		t.Fatal("root-owned process must not be auto-routed")
	}

	// Second scan must not re-apply the same PID.
	router.ScanOnce()
	if len(fa.calls) != 1 {
		t.Fatalf("assign calls = %d, want 1", len(fa.calls))
	}
}

func TestScanOnceRetriesAfterFailure(t *testing.T) {
	procRoot := t.TempDir()
	makeProc(t, procRoot, 5001, "steam", "1000", "/usr/bin/steam\x00")

	store := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := store.Add(types.Rule{Match: "steam", Interface: "eno1"}); err != nil {
		t.Fatal(err)
	}
	fa := newFakeAssigner()
	fa.failFor[5001] = true
	router := NewRouterWithProcRoot(store, fa, procRoot)

	if events := router.ScanOnce(); len(events) != 0 {
		t.Fatalf("expected no events on failure, got %+v", events)
	}
	fa.failFor[5001] = false
	if events := router.ScanOnce(); len(events) != 1 {
		t.Fatalf("expected retry to succeed, got %+v", events)
	}
	if fa.assigned[5001] != "eno1" {
		t.Fatalf("assigned = %q, want eno1", fa.assigned[5001])
	}
}

func TestRuleChangeReappliesRunningProcess(t *testing.T) {
	procRoot := t.TempDir()
	makeProc(t, procRoot, 6001, "chrome", "1000", "/usr/bin/chrome\x00")

	store := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := store.Add(types.Rule{Match: "chrome", Interface: "wlan0"}); err != nil {
		t.Fatal(err)
	}
	fa := newFakeAssigner()
	router := NewRouterWithProcRoot(store, fa, procRoot)
	router.ScanOnce()

	if err := store.Add(types.Rule{Match: "chrome", Interface: "eno1"}); err != nil {
		t.Fatal(err)
	}
	events := router.ScanOnce()
	if len(events) != 1 || events[0].Interface != "eno1" {
		t.Fatalf("events after rule change = %+v", events)
	}
	if fa.assigned[6001] != "eno1" {
		t.Fatalf("assigned = %q, want eno1", fa.assigned[6001])
	}
}

func TestScanOnceUsesOptsAssigner(t *testing.T) {
	procRoot := t.TempDir()
	makeProc(t, procRoot, 7001, "zoom", "1000", "/usr/bin/zoom\x00")
	makeProc(t, procRoot, 7002, "aria2c", "1000", "/usr/bin/aria2c\x00")

	store := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := store.Add(types.Rule{
		Match:        "zoom",
		Interface:    types.ProfileLowLatency,
		Policy:       types.PolicyStrict,
		RateLimitBps: 2_000_000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(types.Rule{
		Match:        "aria2c",
		Interface:    "wlan0",
		RateLimitBps: 512_000,
	}); err != nil {
		t.Fatal(err)
	}

	oa := newFakeOptsAssigner()
	oa.resolveAs = "eno1"
	router := NewRouterWithProcRoot(store, oa, procRoot)

	events := router.ScanOnce()
	if len(events) != 2 {
		t.Fatalf("events len = %d, want 2: %+v", len(events), events)
	}
	if oa.basicCalls != 0 {
		t.Fatalf("expected AssignWithOpts instead of Assign, basicCalls = %d", oa.basicCalls)
	}
	if len(oa.optCalls) != 2 {
		t.Fatalf("optCalls len = %d, want 2", len(oa.optCalls))
	}

	byPID := make(map[int]Event, 2)
	for _, ev := range oa.optCalls {
		byPID[ev.PID] = ev
	}
	if ev := byPID[7001]; ev.Interface != types.ProfileLowLatency || ev.Policy != types.PolicyStrict || ev.RateLimitBps != 2_000_000 {
		t.Fatalf("unexpected 7001 opts call: %+v", ev)
	}
	if ev := byPID[7002]; ev.Interface != "wlan0" || ev.Policy != types.PolicyFailover || ev.RateLimitBps != 512_000 {
		t.Fatalf("unexpected 7002 opts call: %+v", ev)
	}

	// Second scan must not re-apply handled virtual profile PID.
	if again := router.ScanOnce(); len(again) != 0 {
		t.Fatalf("expected 0 events on repeat scan, got %+v", again)
	}
	if len(oa.optCalls) != 2 {
		t.Fatalf("optCalls after repeat = %d, want 2", len(oa.optCalls))
	}
}

func TestTriggerScanWakesStartImmediately(t *testing.T) {
	procRoot := t.TempDir()
	store := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := store.Add(types.Rule{Match: "curl", Interface: "wg0", Policy: types.PolicyStrict}); err != nil {
		t.Fatal(err)
	}

	oa := newFakeOptsAssigner()
	router := NewRouterWithProcRoot(store, oa, procRoot)
	router.SetInterval(time.Hour) // long periodic interval so only TriggerScan can wake quickly

	assigned := make(chan Event, 4)
	router.OnAssign(func(e Event) {
		assigned <- e
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router.Start(ctx)

	// Give Start goroutine a brief moment to run its initial scan.
	time.Sleep(20 * time.Millisecond)

	// Add matching process and trigger multiple non-blocking pokes.
	makeProc(t, procRoot, 8001, "curl", "1000", "/usr/bin/curl\x00")
	for i := 0; i < 10; i++ {
		router.TriggerScan()
	}

	select {
	case ev := <-assigned:
		if ev.PID != 8001 || ev.Interface != "wg0" || ev.Policy != types.PolicyStrict {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("TriggerScan did not wake Start loop within 1s")
	}
}

func TestFastPeriodicScanningWithSetInterval(t *testing.T) {
	procRoot := t.TempDir()
	store := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := store.Add(types.Rule{Match: "wget", Interface: "eno1"}); err != nil {
		t.Fatal(err)
	}

	fa := newFakeAssigner()
	router := NewRouterWithProcRoot(store, fa, procRoot)
	router.SetInterval(25 * time.Millisecond)

	assigned := make(chan Event, 4)
	router.OnAssign(func(e Event) {
		assigned <- e
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router.Start(ctx)

	// Adjust interval while running to verify race-free dynamic reset.
	router.SetInterval(20 * time.Millisecond)
	router.SetInterval(0) // ignored

	makeProc(t, procRoot, 9001, "wget", "1000", "/usr/bin/wget\x00")

	select {
	case ev := <-assigned:
		if ev.PID != 9001 || ev.Interface != "eno1" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("fast periodic scan did not catch new process within 1s")
	}
}
