package classifier

import (
	"os"
	"path/filepath"
	"strconv"
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

type recordedPut struct {
	key uint64
	val target
}

func fakeClassifier(t *testing.T, root string) (*Classifier, *[]recordedPut, *[]string) {
	t.Helper()
	c := New(root)
	c.loaded = true
	puts := &[]recordedPut{}
	attached := &[]string{}
	c.putFn = func(key, value any) error {
		*puts = append(*puts, recordedPut{key: key.(uint64), val: value.(target)})
		return nil
	}
	c.cgroupIDFn = func(path string) (uint64, error) {
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
		}
		return uint64(info.Sys().(*syscall.Stat_t).Ino), nil
	}
	c.attachFn = func(path string) (attachment, error) {
		name := filepath.Base(path)
		*attached = append(*attached, name)
		return attachment{closeFn: func() error { return nil }}, nil
	}
	return c, puts, attached
}

func mkCgroup(t *testing.T, root, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "netweaver", name), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAttachesMarksAndQuarantine(t *testing.T) {
	root := t.TempDir()
	mkCgroup(t, root, "wlan0")
	mkCgroup(t, root, "eno1")
	mkCgroup(t, root, "blocked")

	c, puts, attached := fakeClassifier(t, root)
	if err := c.Apply([]types.InterfaceInfo{
		{Name: "wlan0", TableID: 0x104},
		{Name: "eno1", TableID: 0x102},
		{Name: "ghost0", TableID: 0x110},
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if len(*attached) != 3 {
		t.Fatalf("attached = %v, want wlan0, eno1, blocked", *attached)
	}
	byName := make(map[string]target, 3)
	for _, p := range *puts {
		byName[strconv.FormatUint(p.key, 10)] = p.val
	}

	blockedInode := inodeOf(t, filepath.Join(root, "netweaver", "blocked"))
	if got := byName[strconv.FormatUint(blockedInode, 10)]; got.Drop != 1 {
		t.Fatalf("blocked target = %+v, want drop", got)
	}
	wlanInode := inodeOf(t, filepath.Join(root, "netweaver", "wlan0"))
	if got := byName[strconv.FormatUint(wlanInode, 10)]; got.Mark != 0x104 || got.Drop != 0 {
		t.Fatalf("wlan0 target = %+v, want mark 0x104", got)
	}
	if _, ok := c.links["ghost0"]; ok {
		t.Fatal("missing cgroup must not be attached")
	}
}

func TestApplyDetachesRemovedInterface(t *testing.T) {
	root := t.TempDir()
	mkCgroup(t, root, "wlan0")
	mkCgroup(t, root, "eno1")
	mkCgroup(t, root, "blocked")

	c, _, _ := fakeClassifier(t, root)
	closed := 0
	c.attachFn = func(path string) (attachment, error) {
		return attachment{closeFn: func() error { closed++; return nil }}, nil
	}
	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x104}, {Name: "eno1", TableID: 0x102}}); err != nil {
		t.Fatal(err)
	}
	if len(c.links) != 3 {
		t.Fatalf("links = %d, want 3", len(c.links))
	}

	// eno1 disappears: its attachment must be released, others kept.
	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x104}}); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("closed = %d, want 1", closed)
	}
	if _, ok := c.links["eno1"]; ok {
		t.Fatal("eno1 link must be removed")
	}
	if _, ok := c.links["wlan0"]; !ok {
		t.Fatal("wlan0 link must be kept")
	}
}

func TestApplyPropagatesAttachFailure(t *testing.T) {
	root := t.TempDir()
	mkCgroup(t, root, "wlan0")
	c, _, _ := fakeClassifier(t, root)
	c.attachFn = func(string) (attachment, error) { return attachment{}, errAttach }
	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x104}}); err == nil {
		t.Fatal("attach failure must surface so the daemon can fall back")
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(info.Sys().(*syscall.Stat_t).Ino)
}

var errAttach = &attachErr{}

type attachErr struct{}

func (*attachErr) Error() string { return "attach refused" }
