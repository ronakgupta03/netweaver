// internal/autoroute/router.go
package autoroute

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"netweaver/internal/rules"
)

const defaultScanInterval = 500 * time.Millisecond

// Assigner applies interface bindings for a process (and its children).
type Assigner interface {
	Assign(pid int, iface string) error
	Current(pid int) string
}

// OptsAssigner is optionally implemented alongside Assigner by backends that
// apply per-process policy and rate-limit options during auto-routing.
type OptsAssigner interface {
	AssignWithOpts(pid int, iface, policy string, rateLimitBps uint64) error
}

// Event records one auto-applied rule.
type Event struct {
	PID          int
	Name         string
	Interface    string
	Policy       string
	RateLimitBps uint64
}

// Router watches /proc for processes matching persisted rules and binds them.
type Router struct {
	store    *rules.Store
	assigner Assigner
	procRoot string

	scanMu    sync.Mutex
	mu        sync.Mutex
	interval  time.Duration
	handled   map[int]string
	version   uint64
	listeners []func(Event)

	triggerCh chan struct{}
	resetCh   chan struct{}
}

func NewRouter(store *rules.Store, assigner Assigner) *Router {
	return &Router{
		store:     store,
		assigner:  assigner,
		procRoot:  "/proc",
		interval:  defaultScanInterval,
		handled:   make(map[int]string),
		triggerCh: make(chan struct{}, 1),
		resetCh:   make(chan struct{}, 1),
	}
}

func NewRouterWithProcRoot(store *rules.Store, assigner Assigner, procRoot string) *Router {
	r := NewRouter(store, assigner)
	r.procRoot = procRoot
	return r
}

// SetInterval updates the periodic background scan interval (ignoring d <= 0).
func (r *Router) SetInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	r.mu.Lock()
	r.interval = d
	r.mu.Unlock()
	if r.resetCh != nil {
		select {
		case r.resetCh <- struct{}{}:
		default:
		}
	}
}

// TriggerScan wakes a running Router loop immediately without blocking.
func (r *Router) TriggerScan() {
	if r.triggerCh == nil {
		return
	}
	select {
	case r.triggerCh <- struct{}{}:
	default:
	}
}

// OnAssign registers a callback invoked for every newly applied rule.
func (r *Router) OnAssign(fn func(Event)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners = append(r.listeners, fn)
}

func (r *Router) Start(ctx context.Context) {
	r.mu.Lock()
	curInterval := r.interval
	r.mu.Unlock()
	if curInterval <= 0 {
		curInterval = defaultScanInterval
	}

	go func() {
		ticker := time.NewTicker(curInterval)
		defer ticker.Stop()

		r.ScanOnce()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.ScanOnce()
			case <-r.triggerCh:
				r.ScanOnce()
			case <-r.resetCh:
				r.mu.Lock()
				next := r.interval
				r.mu.Unlock()
				if next > 0 && next != curInterval {
					curInterval = next
					ticker.Reset(curInterval)
				}
			}
		}
	}()
}

// ScanOnce applies rules to every not-yet-handled user process.
func (r *Router) ScanOnce() []Event {
	r.scanMu.Lock()
	defer r.scanMu.Unlock()

	version := r.store.Version()

	r.mu.Lock()
	if version != r.version {
		r.version = version
		r.handled = make(map[int]string)
	}
	handled := make(map[int]string, len(r.handled))
	for k, v := range r.handled {
		handled[k] = v
	}
	r.mu.Unlock()

	entries, err := os.ReadDir(r.procRoot)
	if err != nil {
		return nil
	}

	live := make(map[int]bool, len(entries))
	var events []Event
	optsAssigner, hasOpts := r.assigner.(OptsAssigner)

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 100 {
			continue
		}
		live[pid] = true
		if _, done := handled[pid]; done {
			continue
		}

		name := readTrimmed(filepath.Join(r.procRoot, entry.Name(), "comm"))
		if name == "" {
			continue
		}
		uid := readUID(filepath.Join(r.procRoot, entry.Name(), "status"))
		if uid < 1000 {
			continue
		}

		cmdline := readCmdline(filepath.Join(r.procRoot, entry.Name(), "cmdline"))
		rule, ok := r.store.Match(name, cmdline)
		if !ok {
			continue
		}
		if r.assigner.Current(pid) == rule.Interface {
			r.markHandled(pid, rule.Interface)
			continue
		}

		policy := rule.NormalizedPolicy()
		var assignErr error
		if hasOpts {
			assignErr = optsAssigner.AssignWithOpts(pid, rule.Interface, policy, rule.RateLimitBps)
		} else {
			assignErr = r.assigner.Assign(pid, rule.Interface)
		}
		if assignErr != nil {
			continue // retry on the next scan
		}

		r.markHandled(pid, rule.Interface)
		events = append(events, Event{
			PID:          pid,
			Name:         name,
			Interface:    rule.Interface,
			Policy:       policy,
			RateLimitBps: rule.RateLimitBps,
		})
	}

	r.pruneHandled(live)
	r.emit(events)
	return events
}

func (r *Router) markHandled(pid int, iface string) {
	r.mu.Lock()
	r.handled[pid] = iface
	r.mu.Unlock()
}

func (r *Router) pruneHandled(live map[int]bool) {
	r.mu.Lock()
	for pid := range r.handled {
		if !live[pid] {
			delete(r.handled, pid)
		}
	}
	r.mu.Unlock()
}

func (r *Router) emit(events []Event) {
	if len(events) == 0 {
		return
	}
	r.mu.Lock()
	listeners := append([]func(Event){}, r.listeners...)
	r.mu.Unlock()
	for _, ev := range events {
		for _, fn := range listeners {
			fn(ev)
		}
	}
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(data), "\x00", " ")
}

func readUID(statusPath string) uint32 {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		v, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0
		}
		return uint32(v)
	}
	return 0
}
