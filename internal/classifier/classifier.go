// Package classifier attaches an eBPF cgroup_skb program that marks egress
// packets per cgroup and drops quarantined traffic, replacing the nftables
// marking path when the kernel and privileges allow it.
package classifier

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"netweaver/internal/cgroups"
	"netweaver/internal/types"
)

//go:embed netweaver_bpfel.o
var objectBytes []byte

type bpfObjects struct {
	Mark    *ebpf.Program `ebpf:"nw_mark"`
	Targets *ebpf.Map     `ebpf:"nw_targets"`
}

// target mirrors `struct nw_target` in bpf/netweaver.c.
type target struct {
	Mark uint32
	Drop uint32
}

type Classifier struct {
	mu         sync.Mutex
	objs       bpfObjects
	cgroupRoot string
	links      map[string]link.Link
	loaded     bool
}

func New(cgroupRoot string) *Classifier {
	return &Classifier{
		cgroupRoot: cgroupRoot,
		links:      make(map[string]link.Link),
	}
}

// Spec parses the embedded object without touching the kernel. Used by tests
// to validate the compiled program.
func Spec() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
}

// Start loads the BPF programs and maps into the kernel.
func (c *Classifier) Start() error {
	spec, err := Spec()
	if err != nil {
		return fmt.Errorf("parsing BPF object: %w", err)
	}
	// Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK.
	_ = rlimit.RemoveMemlock()
	if err := spec.LoadAndAssign(&c.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	c.loaded = true
	return nil
}

// Active reports whether the BPF programs are loaded.
func (c *Classifier) Active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loaded
}

// Apply reconciles attachments and map entries with the current interface set.
// Interfaces whose cgroup directory is missing are skipped; everything else is
// marked with its routing table ID. The quarantine cgroup drops instead.
func (c *Classifier) Apply(ifaces []types.InterfaceInfo) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		return fmt.Errorf("classifier not loaded")
	}

	desired := make(map[string]target, len(ifaces)+1)
	for _, iface := range ifaces {
		desired[iface.Name] = target{Mark: uint32(iface.TableID)}
	}
	desired[cgroups.BlockedCgroup] = target{Drop: 1}

	for name, l := range c.links {
		if _, keep := desired[name]; keep {
			continue
		}
		_ = l.Close()
		delete(c.links, name)
	}

	for name, t := range desired {
		path := filepath.Join(c.cgroupRoot, "netweaver", name)
		id, err := cgroupID(path)
		if err != nil {
			continue // cgroup not created yet
		}
		if err := c.objs.Targets.Put(id, t); err != nil {
			return fmt.Errorf("updating BPF map for %s: %w", name, err)
		}
		if _, attached := c.links[name]; attached {
			continue
		}
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: c.objs.Mark,
		})
		if err != nil {
			return fmt.Errorf("attaching BPF program to %s: %w", name, err)
		}
		c.links[name] = l
	}
	return nil
}

// Close detaches every program and releases kernel resources.
func (c *Classifier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, l := range c.links {
		_ = l.Close()
		delete(c.links, name)
	}
	if !c.loaded {
		return nil
	}
	c.loaded = false
	err := c.objs.Mark.Close()
	if mapErr := c.objs.Targets.Close(); err == nil {
		err = mapErr
	}
	return err
}

// cgroupID returns the kernfs inode number, which is what
// bpf_get_current_cgroup_id() reports for that cgroup.
func cgroupID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected stat type for %s", path)
	}
	return st.Ino, nil
}
