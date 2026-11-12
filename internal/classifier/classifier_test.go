package classifier

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"

	"netweaver/internal/types"
)

func TestEmbeddedObjectParses(t *testing.T) {
	spec, err := Spec()
	if err != nil {
		t.Fatalf("parse object: %v", err)
	}

	prog, ok := spec.Programs["nw_mark"]
	if !ok {
		t.Fatalf("missing nw_mark program, have %v", len(spec.Programs))
	}
	if prog.Type != ebpf.CGroupSKB {
		t.Fatalf("program type = %v, want CGroupSKB", prog.Type)
	}
	if prog.AttachType != ebpf.AttachCGroupInetEgress {
		t.Fatalf("attach type = %v, want egress", prog.AttachType)
	}
	if prog.SectionName != "cgroup_skb/egress" {
		t.Fatalf("section = %q", prog.SectionName)
	}

	m, ok := spec.Maps["nw_targets"]
	if !ok {
		t.Fatalf("missing nw_targets map, have %v", len(spec.Maps))
	}
	if m.Type != ebpf.Hash {
		t.Fatalf("map type = %v, want hash", m.Type)
	}
	if m.ValueSize != 8 {
		t.Fatalf("map value size = %d, want 8 (mark+drop)", m.ValueSize)
	}
}

func TestApplyBeforeStartFails(t *testing.T) {
	c := New(t.TempDir())
	if err := c.Apply(nil); err == nil {
		t.Fatal("Apply must fail before the program is loaded")
	}
	if c.Active() {
		t.Fatal("classifier must report inactive")
	}
}

func TestCgroupIDMatchesInode(t *testing.T) {
	dir := t.TempDir()
	want, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cgroupID(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := want.Sys().(*syscall.Stat_t)
	if got != uint64(st.Ino) {
		t.Fatalf("cgroupID = %d, want inode %d", got, st.Ino)
	}
	if _, err := cgroupID(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected error for missing cgroup")
	}
}

// TestApplySkipsMissingCgroups exercises the reconciliation path without
// privileges: no cgroup directories exist, so nothing is attached and no map
// update is attempted against the nil map.
func TestApplySkipsMissingCgroups(t *testing.T) {
	c := New(t.TempDir())
	c.loaded = true
	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x104}}); err != nil {
		t.Fatalf("Apply with no cgroups = %v, want nil", err)
	}
	if len(c.links) != 0 {
		t.Fatalf("unexpected links: %v", c.links)
	}
}
