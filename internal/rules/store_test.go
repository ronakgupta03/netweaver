package rules

import (
	"os"
	"path/filepath"
	"testing"

	"netweaver/internal/types"
)

func TestAddPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")

	s := NewStore(path)
	if err := s.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if err := s.Add(types.Rule{Match: "firefox", Interface: "wlan0"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.Add(types.Rule{Match: "Steam", Interface: "eno1", Policy: types.PolicyStrict}); err != nil {
		t.Fatalf("add strict: %v", err)
	}
	// Updating an existing match replaces it instead of duplicating.
	if err := s.Add(types.Rule{Match: "FIREFOX", Interface: "usb0"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := s.List(); len(got) != 2 {
		t.Fatalf("rule count = %d, want 2", len(got))
	}

	reloaded := NewStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := reloaded.List()
	if len(got) != 2 {
		t.Fatalf("reloaded count = %d, want 2", len(got))
	}
	if got[0].Interface != "usb0" {
		t.Fatalf("firefox interface = %q, want usb0", got[0].Interface)
	}
	if got[1].Policy != types.PolicyStrict {
		t.Fatalf("steam policy = %q, want strict", got[1].Policy)
	}
	if err := reloaded.Remove("steam"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(reloaded.List()) != 1 {
		t.Fatal("remove did not delete rule")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rules file missing: %v", err)
	}
}

func TestAddRejectsInvalidPolicy(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := s.Add(types.Rule{Match: "x", Interface: "wlan0", Policy: "bogus"}); err == nil {
		t.Fatal("expected invalid policy error")
	}
}

func TestMatchNameGlobAndCmdlineBasename(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := s.Add(types.Rule{Match: "fire*", Interface: "wlan0"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(types.Rule{Match: "steam", Interface: "eno1"}); err != nil {
		t.Fatal(err)
	}

	if r, ok := s.Match("firefox", ""); !ok || r.Interface != "wlan0" {
		t.Fatalf("glob name match = %+v ok=%v", r, ok)
	}
	if r, ok := s.Match("steam", "/usr/bin/steam -silent"); !ok || r.Interface != "eno1" {
		t.Fatalf("comm match = %+v ok=%v", r, ok)
	}
	if _, ok := s.Match("Web Content", "/usr/lib/firefox/firefox -contentproc"); ok {
		t.Fatal("helper process must not inherit a comm-based firefox rule")
	}
	if err := s.Add(types.Rule{Match: "bin:firefox", Interface: "wlan0"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Match("Web Content", "/usr/lib/firefox/firefox -contentproc"); !ok {
		t.Fatal("bin: prefix must match argv[0] basename")
	}
	if err := s.Add(types.Rule{Match: "cmd:*-silent", Interface: "eno1"}); err != nil {
		t.Fatal(err)
	}
	if r, ok := s.Match("stub", "/usr/bin/steam -silent"); !ok || r.Interface != "eno1" {
		t.Fatalf("cmd: prefix match = %+v ok=%v", r, ok)
	}
	if _, ok := s.Match("chrome", "/usr/bin/chrome"); ok {
		t.Fatal("unexpected match for chrome")
	}
}

func TestVersionBumpsOnMutation(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "rules.json"))
	v0 := s.Version()
	if err := s.Add(types.Rule{Match: "a", Interface: "wlan0"}); err != nil {
		t.Fatal(err)
	}
	v1 := s.Version()
	if v1 <= v0 {
		t.Fatalf("version did not bump: %d -> %d", v0, v1)
	}
	_ = s.Remove("a")
	if s.Version() <= v1 {
		t.Fatal("version did not bump on remove")
	}
}
