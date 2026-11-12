package failover

import (
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
