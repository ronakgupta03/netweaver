package policy

import (
	"os"
	"path/filepath"
	"testing"

	"netweaver/internal/rules"
	"netweaver/internal/types"
)

func TestDefaultPolicyPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	m := NewManager(path, nil)
	if err := m.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Default() != types.PolicyFailover {
		t.Fatalf("default = %q, want failover", m.Default())
	}
	if err := m.SetDefault(types.PolicyStrict); err != nil {
		t.Fatalf("set default: %v", err)
	}
	if err := m.SetDefault("bogus"); err == nil {
		t.Fatal("expected error for unknown policy")
	}

	reloaded := NewManager(path, nil)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Default() != types.PolicyStrict {
		t.Fatalf("reloaded default = %q, want strict", reloaded.Default())
	}
}

func TestResolvePrecedence(t *testing.T) {
	self := os.Getpid()
	comm, err := os.ReadFile(filepath.Join("/proc", itoa(self), "comm"))
	if err != nil {
		t.Skip("no procfs")
	}
	name := trim(comm)

	store := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := store.Add(types.Rule{Match: name, Interface: "eno1", Policy: types.PolicyStrict}); err != nil {
		t.Fatal(err)
	}

	m := NewManager(filepath.Join(t.TempDir(), "settings.json"), store)
	if got := m.Resolve(self); got != types.PolicyStrict {
		t.Fatalf("rule policy = %q, want strict", got)
	}

	m.Set(self, types.PolicyFailover)
	if got := m.Resolve(self); got != types.PolicyFailover {
		t.Fatalf("explicit policy = %q, want failover", got)
	}

	m.Forget(self)
	if got := m.Resolve(1 << 20); got != types.PolicyFailover {
		t.Fatalf("default policy = %q, want failover", got)
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

func trim(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == '\n' || b[end-1] == ' ') {
		end--
	}
	return string(b[:end])
}
