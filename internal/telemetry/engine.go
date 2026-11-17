// internal/telemetry/engine.go
package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rate is a bytes-per-second sample.
type Rate struct {
	Rx float64
	Tx float64
}

// IfaceUsage is cumulative byte usage for a network interface.
type IfaceUsage struct {
	Rx uint64
	Tx uint64
}

type ifaceRaw struct {
	rx uint64
	tx uint64
}

// Engine samples socket, cgroup eBPF, and interface counters on a fixed
// interval and keeps derived rates plus cumulative usage.
type Engine struct {
	mu sync.RWMutex

	sysNetRoot string
	interval   time.Duration
	now        func() time.Time

	lastSample time.Time

	lastRawProc map[int]ProcBytes
	procUsage   map[int]ProcBytes
	procRate    map[int]Rate
	lastSeen    map[int]time.Time

	lastRawIface map[string]ifaceRaw
	ifaceRate    map[string]Rate

	ssOK bool

	cgroupStatsReader  func(iface string) (rx, tx uint64, ok bool)
	processStatsReader func(pid int) (rx, tx uint64, ok bool)
	procBytesFn        func() (map[int]ProcBytes, error)

	trackedMu     sync.Mutex
	trackedPIDs   map[int]time.Time
	trackedIfaces map[string]struct{}
}

func NewEngine() *Engine {
	return &Engine{
		sysNetRoot:    "/sys/class/net",
		interval:      time.Second,
		now:           time.Now,
		lastRawProc:   make(map[int]ProcBytes),
		procUsage:     make(map[int]ProcBytes),
		procRate:      make(map[int]Rate),
		lastSeen:      make(map[int]time.Time),
		lastRawIface:  make(map[string]ifaceRaw),
		ifaceRate:     make(map[string]Rate),
		ssOK:          true,
		procBytesFn:   collectProcessBytes,
		trackedPIDs:   make(map[int]time.Time),
		trackedIfaces: make(map[string]struct{}),
	}
}

func NewEngineWithRoot(root string) *Engine {
	e := NewEngine()
	e.sysNetRoot = root
	return e
}

// SetCgroupStatsReader configures an eBPF per-interface cgroup stats reader.
// When fn returns ok == true for an interface, Engine uses those exact kernel
// counters instead of sysfs statistics.
func (e *Engine) SetCgroupStatsReader(fn func(iface string) (rx, tx uint64, ok bool)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cgroupStatsReader = fn
}

// SetProcessStatsReader configures an eBPF per-process cgroup stats reader.
// When fn returns ok == true for a PID, Engine uses those exact kernel counters
// (capturing TCP, UDP, QUIC, and ICMP) and falls back to `ss` otherwise.
func (e *Engine) SetProcessStatsReader(fn func(pid int) (rx, tx uint64, ok bool)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.processStatsReader = fn
}

// TrackPID registers a PID to be polled via the processStatsReader on every Sample.
func (e *Engine) TrackPID(pid int) {
	if pid <= 0 {
		return
	}
	e.recordTrackedPIDs(pid)
}

// TrackInterface registers an interface name to be polled via cgroupStatsReader.
func (e *Engine) TrackInterface(iface string) {
	if iface == "" || iface == "lo" {
		return
	}
	e.recordTrackedIface(iface)
}

func (e *Engine) recordTrackedPIDs(pids ...int) {
	now := e.now()
	e.trackedMu.Lock()
	for _, pid := range pids {
		if pid > 0 {
			e.trackedPIDs[pid] = now
		}
	}
	e.trackedMu.Unlock()
}

func (e *Engine) recordTrackedIface(iface string) {
	if iface == "" || iface == "lo" {
		return
	}
	e.trackedMu.Lock()
	e.trackedIfaces[iface] = struct{}{}
	e.trackedMu.Unlock()
}

// Start samples immediately and then on the configured interval until ctx ends.
func (e *Engine) Start(ctx context.Context) {
	e.Sample()
	go func() {
		ticker := time.NewTicker(e.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.Sample()
			}
		}
	}()
}

// Sample reads current counters and updates rates and cumulative usage.
func (e *Engine) Sample() {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()

	elapsed := now.Sub(e.lastSample).Seconds()
	if e.lastSample.IsZero() || elapsed <= 0 {
		elapsed = 1
	}
	e.lastSample = now

	e.sampleProcesses(elapsed, now)
	e.sampleInterfaces(elapsed)
}

func (e *Engine) sampleProcesses(elapsed float64, now time.Time) {
	raw, err := e.procBytesFn()
	if err != nil {
		e.ssOK = false
		if e.processStatsReader == nil {
			return
		}
		raw = make(map[int]ProcBytes)
	} else {
		e.ssOK = true
	}

	if e.processStatsReader != nil {
		candidates := make(map[int]struct{}, len(raw)+len(e.lastRawProc)+len(e.procUsage))
		for pid := range raw {
			candidates[pid] = struct{}{}
		}
		for pid := range e.lastRawProc {
			candidates[pid] = struct{}{}
		}
		for pid := range e.procUsage {
			candidates[pid] = struct{}{}
		}
		e.trackedMu.Lock()
		for pid, seen := range e.trackedPIDs {
			if now.Sub(seen) > 10*time.Minute {
				delete(e.trackedPIDs, pid)
				continue
			}
			candidates[pid] = struct{}{}
		}
		e.trackedMu.Unlock()

		for pid := range candidates {
			if rx, tx, ok := e.processStatsReader(pid); ok {
				raw[pid] = ProcBytes{Rx: rx, Tx: tx}
			}
		}
	}

	for pid, cur := range raw {
		prev := e.lastRawProc[pid]
		var dRx, dTx uint64
		if cur.Rx >= prev.Rx {
			dRx = cur.Rx - prev.Rx
		}
		if cur.Tx >= prev.Tx {
			dTx = cur.Tx - prev.Tx
		}
		usage := e.procUsage[pid]
		usage.Rx += dRx
		usage.Tx += dTx
		e.procUsage[pid] = usage
		e.procRate[pid] = Rate{Rx: float64(dRx) / elapsed, Tx: float64(dTx) / elapsed}
		e.lastSeen[pid] = now
	}

	for pid := range e.lastRawProc {
		if _, ok := raw[pid]; !ok {
			delete(e.procRate, pid)
		}
	}
	e.lastRawProc = raw

	// Drop accounting for processes that have been gone for a while.
	for pid, seen := range e.lastSeen {
		if now.Sub(seen) > 10*time.Minute {
			delete(e.lastSeen, pid)
			delete(e.procUsage, pid)
		}
	}
}

func (e *Engine) sampleInterfaces(elapsed float64) {
	entries, err := os.ReadDir(e.sysNetRoot)
	if err != nil && e.cgroupStatsReader == nil {
		return
	}
	names := make(map[string]struct{}, len(entries)+len(e.lastRawIface))
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		names[name] = struct{}{}
	}
	if e.cgroupStatsReader != nil {
		for name := range e.lastRawIface {
			if name != "lo" {
				names[name] = struct{}{}
			}
		}
		e.trackedMu.Lock()
		for name := range e.trackedIfaces {
			if name != "lo" {
				names[name] = struct{}{}
			}
		}
		e.trackedMu.Unlock()
	}

	current := make(map[string]ifaceRaw, len(names))
	for name := range names {
		if e.cgroupStatsReader != nil {
			if rx, tx, ok := e.cgroupStatsReader(name); ok {
				current[name] = ifaceRaw{rx: rx, tx: tx}
				continue
			}
		}
		rx, okRx := readCounter(filepath.Join(e.sysNetRoot, name, "statistics", "rx_bytes"))
		tx, okTx := readCounter(filepath.Join(e.sysNetRoot, name, "statistics", "tx_bytes"))
		if !okRx || !okTx {
			continue
		}
		current[name] = ifaceRaw{rx: rx, tx: tx}
	}

	for name, cur := range current {
		prev, seen := e.lastRawIface[name]
		if !seen {
			e.ifaceRate[name] = Rate{}
			continue
		}
		var dRx, dTx uint64
		if cur.rx >= prev.rx {
			dRx = cur.rx - prev.rx
		}
		if cur.tx >= prev.tx {
			dTx = cur.tx - prev.tx
		}
		e.ifaceRate[name] = Rate{Rx: float64(dRx) / elapsed, Tx: float64(dTx) / elapsed}
	}

	for name := range e.lastRawIface {
		if _, ok := current[name]; !ok {
			delete(e.ifaceRate, name)
		}
	}
	e.lastRawIface = current
}

func readCounter(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ProcessUsage returns cumulative bytes and the last rate for a PID.
func (e *Engine) ProcessUsage(pid int) (ProcBytes, Rate) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	e.recordTrackedPIDs(pid)
	usage, ok := e.procUsage[pid]
	rate := e.procRate[pid]
	if !ok && e.processStatsReader != nil {
		if rx, tx, found := e.processStatsReader(pid); found {
			usage = ProcBytes{Rx: rx, Tx: tx}
		}
	}
	return usage, rate
}

// InterfaceUsage returns cumulative bytes and the last rate for an interface.
func (e *Engine) InterfaceUsage(name string) (IfaceUsage, Rate) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	e.recordTrackedIface(name)
	raw, seen := e.lastRawIface[name]
	if !seen && e.cgroupStatsReader != nil {
		if rx, tx, ok := e.cgroupStatsReader(name); ok {
			return IfaceUsage{Rx: rx, Tx: tx}, Rate{}
		}
	}
	return IfaceUsage{Rx: raw.rx, Tx: raw.tx}, e.ifaceRate[name]
}

// SocketAccountingAvailable reports whether per-process byte counters could be read.
func (e *Engine) SocketAccountingAvailable() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ssOK || e.processStatsReader != nil
}

// SubtreeUsage aggregates cumulative bytes and rates over a set of PIDs.
func (e *Engine) SubtreeUsage(pids []int) (ProcBytes, Rate) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	e.recordTrackedPIDs(pids...)
	var usage ProcBytes
	var rate Rate
	for _, pid := range pids {
		u, ok := e.procUsage[pid]
		if !ok && e.processStatsReader != nil {
			if rx, tx, found := e.processStatsReader(pid); found {
				u = ProcBytes{Rx: rx, Tx: tx}
			}
		}
		usage.Rx += u.Rx
		usage.Tx += u.Tx
		r := e.procRate[pid]
		rate.Rx += r.Rx
		rate.Tx += r.Tx
	}
	return usage, rate
}
