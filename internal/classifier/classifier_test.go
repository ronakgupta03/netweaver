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

	ing, ok := spec.Programs["nw_ingress"]
	if !ok {
		t.Fatalf("missing nw_ingress program")
	}
	if ing.Type != ebpf.CGroupSKB {
		t.Fatalf("nw_ingress type = %v, want CGroupSKB", ing.Type)
	}
	if ing.AttachType != ebpf.AttachCGroupInetIngress {
		t.Fatalf("nw_ingress attach type = %v, want ingress", ing.AttachType)
	}
	if ing.SectionName != "cgroup_skb/ingress" {
		t.Fatalf("nw_ingress section = %q", ing.SectionName)
	}

	statsMap, ok := spec.Maps["nw_stats"]
	if !ok {
		t.Fatalf("missing nw_stats map")
	}
	if statsMap.Type != ebpf.Hash || statsMap.KeySize != 8 || statsMap.ValueSize != 32 {
		t.Fatalf("nw_stats spec = type:%v key:%d val:%d, want Hash key:8 val:32", statsMap.Type, statsMap.KeySize, statsMap.ValueSize)
	}

	rlMap, ok := spec.Maps["nw_ratelimits"]
	if !ok {
		t.Fatalf("missing nw_ratelimits map")
	}
	if rlMap.Type != ebpf.Hash || rlMap.KeySize != 8 || rlMap.ValueSize != 24 {
		t.Fatalf("nw_ratelimits spec = type:%v key:%d val:%d, want Hash key:8 val:24", rlMap.Type, rlMap.KeySize, rlMap.ValueSize)
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

func TestIngressAttachmentLifecycle(t *testing.T) {
	root := t.TempDir()
	mkCgroup(t, root, "wlan0")
	mkCgroup(t, root, "eno1")
	mkCgroup(t, root, "blocked")

	c, _, _ := fakeClassifier(t, root)
	egressClosed := 0
	ingressClosed := 0
	c.attachFn = func(path string) (attachment, error) {
		return attachment{closeFn: func() error { egressClosed++; return nil }}, nil
	}
	c.attachIngressFn = func(path string) (attachment, error) {
		return attachment{closeFn: func() error { ingressClosed++; return nil }}, nil
	}

	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x104}, {Name: "eno1", TableID: 0x102}}); err != nil {
		t.Fatal(err)
	}
	if len(c.links) != 3 || len(c.ingressLinks) != 3 {
		t.Fatalf("links=%d ingressLinks=%d, want 3/3", len(c.links), len(c.ingressLinks))
	}

	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x104}}); err != nil {
		t.Fatal(err)
	}
	if egressClosed != 1 || ingressClosed != 1 {
		t.Fatalf("closed egress=%d ingress=%d, want 1/1", egressClosed, ingressClosed)
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if egressClosed != 3 || ingressClosed != 3 {
		t.Fatalf("after Close egress=%d ingress=%d, want 3/3", egressClosed, ingressClosed)
	}
}

func TestReadStatsAndProcessStats(t *testing.T) {
	root := t.TempDir()
	mkCgroup(t, root, "wlan0")
	leaf := filepath.Join(root, "netweaver", "wlan0", "p1234")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}

	c, _, _ := fakeClassifier(t, root)
	statsStore := map[uint64]counters{
		inodeOf(t, filepath.Join(root, "netweaver", "wlan0")): {RxBytes: 1000, TxBytes: 400, RxPkts: 5, TxPkts: 2},
		inodeOf(t, leaf): {RxBytes: 2500, TxBytes: 900, RxPkts: 10, TxPkts: 4},
	}
	c.lookupStatsFn = func(key uint64) (counters, bool, error) {
		cnt, ok := statsStore[key]
		return cnt, ok, nil
	}

	rx, tx, ok := c.ReadStats("wlan0")
	if !ok || rx != 3500 || tx != 1300 {
		t.Fatalf("ReadStats(wlan0) = (%d, %d, %v), want (3500, 1300, true)", rx, tx, ok)
	}

	rx, tx, ok = c.ReadCgroupStats(leaf)
	if !ok || rx != 2500 || tx != 900 {
		t.Fatalf("ReadCgroupStats(leaf) = (%d, %d, %v), want (2500, 900, true)", rx, tx, ok)
	}

	rx, tx, ok = c.ReadProcessStats(1234)
	if !ok || rx != 2500 || tx != 900 {
		t.Fatalf("ReadProcessStats(1234) = (%d, %d, %v), want (2500, 900, true)", rx, tx, ok)
	}

	if _, _, ok := c.ReadStats("missing"); ok {
		t.Fatal("missing interface should return ok=false")
	}
	if _, _, ok := c.ReadProcessStats(9999); ok {
		t.Fatal("missing process should return ok=false")
	}

	c.loaded = false
	if _, _, ok := c.ReadStats("wlan0"); ok {
		t.Fatal("unloaded classifier must return ok=false")
	}
}

func TestSetRateLimitAndTargetSyncsLeaf(t *testing.T) {
	root := t.TempDir()
	mkCgroup(t, root, "wlan0")
	leaf := filepath.Join(root, "netweaver", "wlan0", "p4321")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}

	c, puts, _ := fakeClassifier(t, root)
	rates := make(map[uint64]rateLimit)
	c.putRateFn = func(key uint64, val rateLimit) error {
		rates[key] = val
		return nil
	}
	c.deleteRateFn = func(key uint64) error {
		delete(rates, key)
		return nil
	}

	// Small rate should get minimum 64 KiB burst.
	if err := c.SetRateLimit("wlan0/p4321", 10_000); err != nil {
		t.Fatalf("SetRateLimit small: %v", err)
	}
	leafID := inodeOf(t, leaf)
	got := rates[leafID]
	if got.RateBps != 10_000 || got.Tokens != 64*1024 {
		t.Fatalf("rate entry = %+v, want RateBps=10000 Tokens=65536", got)
	}

	// Large rate gets 1s burst.
	if err := c.SetPathRateLimit(leaf, 500_000); err != nil {
		t.Fatalf("SetPathRateLimit large: %v", err)
	}
	got = rates[leafID]
	if got.RateBps != 500_000 || got.Tokens != 500_000 {
		t.Fatalf("rate entry = %+v, want RateBps=500000 Tokens=500000", got)
	}

	// Clearing with 0 deletes the rate entry.
	if err := c.SetRateLimit(leaf, 0); err != nil {
		t.Fatalf("SetRateLimit clear: %v", err)
	}
	if _, exists := rates[leafID]; exists {
		t.Fatal("rate limit entry must be removed when rateBps == 0")
	}

	// Apply must sync nw_targets for both wlan0 and its leaf p4321.
	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x105}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	foundLeaf := false
	for _, p := range *puts {
		if p.key == leafID && p.val.Mark == 0x105 && p.val.Drop == 0 {
			foundLeaf = true
		}
	}
	if !foundLeaf {
		t.Fatalf("Apply did not populate nw_targets for leaf cgroup %d: %+v", leafID, *puts)
	}

	// Explicit SetTarget works on leaf path.
	if err := c.SetTarget("wlan0/p4321", 0x200, true); err != nil {
		t.Fatalf("SetTarget: %v", err)
	}
	lastPut := (*puts)[len(*puts)-1]
	if lastPut.key != leafID || lastPut.val.Mark != 0x200 || lastPut.val.Drop != 1 {
		t.Fatalf("lastPut = %+v, want leafID=%d mark=0x200 drop=1", lastPut, leafID)
	}
}

func TestApplyAttachesDefaultCgroup(t *testing.T) {
	root := t.TempDir()
	mkCgroup(t, root, "default")
	mkCgroup(t, root, "wlan0")
	mkCgroup(t, root, "blocked")
	defaultLeaf := filepath.Join(root, "netweaver", "default", "p9001")
	if err := os.MkdirAll(defaultLeaf, 0o755); err != nil {
		t.Fatal(err)
	}

	c, puts, attached := fakeClassifier(t, root)
	var ingressAttached []string
	c.attachIngressFn = func(path string) (attachment, error) {
		ingressAttached = append(ingressAttached, filepath.Base(path))
		return attachment{closeFn: func() error { return nil }}, nil
	}

	if err := c.Apply([]types.InterfaceInfo{{Name: "wlan0", TableID: 0x104}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if _, ok := c.links["default"]; !ok {
		t.Fatalf("default cgroup egress link must be attached; attached=%v", *attached)
	}
	if _, ok := c.ingressLinks["default"]; !ok {
		t.Fatalf("default cgroup ingress link must be attached; ingress=%v", ingressAttached)
	}

	defaultID := inodeOf(t, filepath.Join(root, "netweaver", "default"))
	leafID := inodeOf(t, defaultLeaf)
	var sawDefault, sawLeaf bool
	for _, p := range *puts {
		if p.key == defaultID && p.val.Mark == 0 && p.val.Drop == 0 {
			sawDefault = true
		}
		if p.key == leafID && p.val.Mark == 0 && p.val.Drop == 0 {
			sawLeaf = true
		}
	}
	if !sawDefault || !sawLeaf {
		t.Fatalf("nw_targets must contain zeroed entries for default (%v) and leaf (%v); puts=%+v", sawDefault, sawLeaf, *puts)
	}
}
