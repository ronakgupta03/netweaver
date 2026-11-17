// Package classifier attaches eBPF cgroup_skb programs that mark egress
// packets per cgroup, drop quarantined traffic, enforce per-cgroup token-bucket
// rate limits, and collect per-cgroup rx/tx byte and packet counters.
package classifier

import (
	"bytes"
	_ "embed"
	"errors"
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

const minRateBurstBytes uint64 = 64 * 1024

type bpfObjects struct {
	Mark       *ebpf.Program `ebpf:"nw_mark"`
	Ingress    *ebpf.Program `ebpf:"nw_ingress"`
	Targets    *ebpf.Map     `ebpf:"nw_targets"`
	Stats      *ebpf.Map     `ebpf:"nw_stats"`
	RateLimits *ebpf.Map     `ebpf:"nw_ratelimits"`
}

// target mirrors `struct nw_target` in bpf/netweaver.c.
type target struct {
	Mark uint32
	Drop uint32
}

// counters mirrors `struct nw_counters` in bpf/netweaver.c.
type counters struct {
	RxBytes uint64
	TxBytes uint64
	RxPkts  uint64
	TxPkts  uint64
}

// rateLimit mirrors `struct nw_rate` in bpf/netweaver.c.
type rateLimit struct {
	RateBps uint64
	LastNs  uint64
	Tokens  uint64
}

// attachment is the internal handle for one cgroup program attachment.
type attachment struct {
	closeFn func() error
}

func (a attachment) close() error {
	if a.closeFn == nil {
		return nil
	}
	return a.closeFn()
}

type Classifier struct {
	mu           sync.Mutex
	objs         bpfObjects
	cgroupRoot   string
	links        map[string]attachment
	ingressLinks map[string]attachment
	loaded       bool

	// Injected for tests; production values talk to the kernel.
	putFn           func(key, value any) error
	attachFn        func(path string) (attachment, error)
	attachIngressFn func(path string) (attachment, error)
	cgroupIDFn      func(path string) (uint64, error)
	lookupStatsFn   func(key uint64) (counters, bool, error)
	putRateFn       func(key uint64, val rateLimit) error
	deleteRateFn    func(key uint64) error
}

func New(cgroupRoot string) *Classifier {
	c := &Classifier{
		cgroupRoot:   cgroupRoot,
		links:        make(map[string]attachment),
		ingressLinks: make(map[string]attachment),
	}
	c.putFn = func(key, value any) error { return c.objs.Targets.Put(key, value) }
	c.attachFn = func(path string) (attachment, error) {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: c.objs.Mark,
		})
		if err != nil {
			return attachment{}, err
		}
		return attachment{closeFn: l.Close}, nil
	}
	c.attachIngressFn = func(path string) (attachment, error) {
		if c.objs.Ingress == nil {
			return attachment{}, nil
		}
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: c.objs.Ingress,
		})
		if err != nil {
			return attachment{}, err
		}
		return attachment{closeFn: l.Close}, nil
	}
	c.cgroupIDFn = cgroupID
	c.lookupStatsFn = func(key uint64) (counters, bool, error) {
		if c.objs.Stats == nil {
			return counters{}, false, nil
		}
		var cnt counters
		if err := c.objs.Stats.Lookup(key, &cnt); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return counters{}, false, nil
			}
			return counters{}, false, err
		}
		return cnt, true, nil
	}
	c.putRateFn = func(key uint64, val rateLimit) error {
		if c.objs.RateLimits == nil {
			return fmt.Errorf("rate limits map not loaded")
		}
		return c.objs.RateLimits.Put(key, val)
	}
	c.deleteRateFn = func(key uint64) error {
		if c.objs.RateLimits == nil {
			return fmt.Errorf("rate limits map not loaded")
		}
		err := c.objs.RateLimits.Delete(key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	return c
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
	c.mu.Lock()
	defer c.mu.Unlock()
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

	desired := make(map[string]target, len(ifaces)+2)
	desired[cgroups.DefaultCgroup] = target{}
	for _, iface := range ifaces {
		desired[iface.Name] = target{Mark: uint32(iface.TableID)}
	}
	desired[cgroups.BlockedCgroup] = target{Drop: 1}

	for name, l := range c.links {
		if _, keep := desired[name]; keep {
			continue
		}
		_ = l.close()
		delete(c.links, name)
		if il, ok := c.ingressLinks[name]; ok {
			_ = il.close()
			delete(c.ingressLinks, name)
		}
	}

	for name, t := range desired {
		path := filepath.Join(c.cgroupRoot, "netweaver", name)
		id, err := c.cgroupIDFn(path)
		if err != nil {
			continue // cgroup not created yet
		}
		if err := c.putFn(id, t); err != nil {
			return fmt.Errorf("updating BPF map for %s: %w", name, err)
		}
		// Keep leaf child cgroups (e.g. per-PID rate-limit cgroups) in sync.
		if entries, readErr := os.ReadDir(path); readErr == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				subID, subErr := c.cgroupIDFn(filepath.Join(path, entry.Name()))
				if subErr != nil {
					continue
				}
				_ = c.putFn(subID, t)
			}
		}

		if _, attached := c.links[name]; !attached {
			att, err := c.attachFn(path)
			if err != nil {
				return fmt.Errorf("attaching BPF program to %s: %w", name, err)
			}
			c.links[name] = att
		}
		if _, attachedIn := c.ingressLinks[name]; !attachedIn && c.attachIngressFn != nil {
			attIn, err := c.attachIngressFn(path)
			if err != nil {
				return fmt.Errorf("attaching BPF ingress program to %s: %w", name, err)
			}
			if attIn.closeFn != nil {
				c.ingressLinks[name] = attIn
			}
		}
	}
	return nil
}

func (c *Classifier) resolveCgroupPath(nameOrPath string) string {
	if filepath.IsAbs(nameOrPath) {
		return nameOrPath
	}
	return filepath.Join(c.cgroupRoot, "netweaver", nameOrPath)
}

// SetTarget updates the nw_targets entry for a cgroup name (under netweaver/)
// or absolute cgroup path.
func (c *Classifier) SetTarget(cgroupNameOrPath string, mark uint32, drop bool) error {
	return c.SetPathTarget(c.resolveCgroupPath(cgroupNameOrPath), mark, drop)
}

// SetPathTarget updates the nw_targets entry for the specified cgroup directory.
func (c *Classifier) SetPathTarget(cgroupPath string, mark uint32, drop bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		return fmt.Errorf("classifier not loaded")
	}
	id, err := c.cgroupIDFn(cgroupPath)
	if err != nil {
		return err
	}
	var dropVal uint32
	if drop {
		dropVal = 1
	}
	return c.putFn(id, target{Mark: mark, Drop: dropVal})
}

// SetRateLimit sets or clears (when rateBps == 0) the token-bucket egress rate
// limit on a cgroup name (e.g. "wlan0" or "wlan0/p1234") or absolute cgroup path.
func (c *Classifier) SetRateLimit(cgroupNameOrPath string, rateBps uint64) error {
	return c.SetPathRateLimit(c.resolveCgroupPath(cgroupNameOrPath), rateBps)
}

// SetCgroupRateLimit is an alias for SetPathRateLimit.
func (c *Classifier) SetCgroupRateLimit(cgroupPath string, rateBps uint64) error {
	return c.SetPathRateLimit(c.resolveCgroupPath(cgroupPath), rateBps)
}

// SetPathRateLimit sets or clears (when rateBps == 0) the token-bucket egress
// rate limit on the specified cgroup directory.
func (c *Classifier) SetPathRateLimit(cgroupPath string, rateBps uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		return fmt.Errorf("classifier not loaded")
	}
	id, err := c.cgroupIDFn(cgroupPath)
	if err != nil {
		return err
	}
	if rateBps == 0 {
		return c.deleteRateFn(id)
	}
	burst := rateBps
	if burst < minRateBurstBytes {
		burst = minRateBurstBytes
	}
	return c.putRateFn(id, rateLimit{
		RateBps: rateBps,
		LastNs:  0,
		Tokens:  burst,
	})
}

// ReadStats reads cumulative rx/tx byte counters from nw_stats for netweaver/<iface>
// (including any leaf process sub-cgroups under it).
func (c *Classifier) ReadStats(iface string) (rxBytes, txBytes uint64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		return 0, 0, false
	}
	basePath := filepath.Join(c.cgroupRoot, "netweaver", iface)
	var foundAny bool
	if id, err := c.cgroupIDFn(basePath); err == nil {
		if cnt, found, lookupErr := c.lookupStatsFn(id); lookupErr == nil && found {
			rxBytes += cnt.RxBytes
			txBytes += cnt.TxBytes
			foundAny = true
		}
	}
	if entries, err := os.ReadDir(basePath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			subID, subErr := c.cgroupIDFn(filepath.Join(basePath, entry.Name()))
			if subErr != nil {
				continue
			}
			if cnt, found, lookupErr := c.lookupStatsFn(subID); lookupErr == nil && found {
				rxBytes += cnt.RxBytes
				txBytes += cnt.TxBytes
				foundAny = true
			}
		}
	}
	return rxBytes, txBytes, foundAny
}

// ReadCgroupStats reads cumulative rx/tx byte counters from nw_stats for a
// specific cgroup directory path (or name relative to netweaver/).
func (c *Classifier) ReadCgroupStats(cgroupPath string) (rxBytes, txBytes uint64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		return 0, 0, false
	}
	id, err := c.cgroupIDFn(c.resolveCgroupPath(cgroupPath))
	if err != nil {
		return 0, 0, false
	}
	cnt, found, err := c.lookupStatsFn(id)
	if err != nil || !found {
		return 0, 0, false
	}
	return cnt.RxBytes, cnt.TxBytes, true
}

// ReadPathStats is an alias for ReadCgroupStats.
func (c *Classifier) ReadPathStats(cgroupPath string) (rxBytes, txBytes uint64, ok bool) {
	return c.ReadCgroupStats(cgroupPath)
}

// ReadProcessStats looks for a per-process leaf cgroup `netweaver/*/p<pid>` and
// returns its eBPF rx/tx byte counters if present in nw_stats.
func (c *Classifier) ReadProcessStats(pid int) (rxBytes, txBytes uint64, ok bool) {
	if pid <= 0 {
		return 0, 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		return 0, 0, false
	}
	baseDir := filepath.Join(c.cgroupRoot, "netweaver")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return 0, 0, false
	}
	leafName := fmt.Sprintf("p%d", pid)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		leafPath := filepath.Join(baseDir, entry.Name(), leafName)
		id, err := c.cgroupIDFn(leafPath)
		if err != nil {
			continue
		}
		if cnt, found, lookupErr := c.lookupStatsFn(id); lookupErr == nil && found {
			return cnt.RxBytes, cnt.TxBytes, true
		}
	}
	return 0, 0, false
}

// Close detaches every program and releases kernel resources.
func (c *Classifier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, l := range c.links {
		_ = l.close()
		delete(c.links, name)
	}
	for name, l := range c.ingressLinks {
		_ = l.close()
		delete(c.ingressLinks, name)
	}
	if !c.loaded {
		return nil
	}
	c.loaded = false
	var firstErr error
	closeProg := func(p *ebpf.Program) {
		if p != nil {
			if err := p.Close(); firstErr == nil && err != nil {
				firstErr = err
			}
		}
	}
	closeMap := func(m *ebpf.Map) {
		if m != nil {
			if err := m.Close(); firstErr == nil && err != nil {
				firstErr = err
			}
		}
	}
	closeProg(c.objs.Mark)
	closeProg(c.objs.Ingress)
	closeMap(c.objs.Targets)
	closeMap(c.objs.Stats)
	closeMap(c.objs.RateLimits)
	return firstErr
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
