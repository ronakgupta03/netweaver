package autoroute

import (
	"os"
	"path/filepath"
	"testing"

	"netweaver/internal/rules"
	"netweaver/internal/types"
)

type fakeAssigner struct {
	assigned map[int]string
	calls    []Event
	failFor  map[int]bool
}

func newFakeAssigner() *fakeAssigner {
	return &fakeAssigner{assigned: make(map[int]string), failFor: make(map[int]bool)}
}

func (f *fakeAssigner) Assign(pid int, iface string) error {
	if f.failFor[pid] {
		return os.ErrPermission
	}
	f.assigned[pid] = iface
	f.calls = append(f.calls, Event{PID: pid, Interface: iface})
	return nil
}

func (f *fakeAssigner) Current(pid int) string { return f.assigned[pid] }

func makeProc(t *testing.T, root string, pid int, name string, uid string, cmdline string) {
	t.Helper()
	dir := filepath.Join(root, "1234")
	dir = filepath.Join(root, itoa(pid))
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
