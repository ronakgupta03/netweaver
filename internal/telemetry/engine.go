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

// Engine samples socket and interface counters on a fixed interval and keeps
// derived rates plus cumulative usage.
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
}

func NewEngine() *Engine {
	return &Engine{
		sysNetRoot:   "/sys/class/net",
		interval:     time.Second,
		now:          time.Now,
		lastRawProc:  make(map[int]ProcBytes),
		procUsage:    make(map[int]ProcBytes),
		procRate:     make(map[int]Rate),
		lastSeen:     make(map[int]time.Time),
		lastRawIface: make(map[string]ifaceRaw),
		ifaceRate:    make(map[string]Rate),
		ssOK:         true,
	}
}

func NewEngineWithRoot(root string) *Engine {
	e := NewEngine()
	e.sysNetRoot = root
	return e
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
	raw, err := collectProcessBytes()
	if err != nil {
		e.ssOK = false
		return
	}
	e.ssOK = true

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
	if err != nil {
		return
	}
	current := make(map[string]ifaceRaw, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
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
	return e.procUsage[pid], e.procRate[pid]
}

// InterfaceUsage returns cumulative bytes and the last rate for an interface.
func (e *Engine) InterfaceUsage(name string) (IfaceUsage, Rate) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	raw := e.lastRawIface[name]
	return IfaceUsage{Rx: raw.rx, Tx: raw.tx}, e.ifaceRate[name]
}

// SocketAccountingAvailable reports whether per-process TCP counters could be read.
func (e *Engine) SocketAccountingAvailable() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ssOK
}

// SubtreeUsage aggregates cumulative bytes and rates over a set of PIDs.
func (e *Engine) SubtreeUsage(pids []int) (ProcBytes, Rate) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var usage ProcBytes
	var rate Rate
	for _, pid := range pids {
		u := e.procUsage[pid]
		usage.Rx += u.Rx
		usage.Tx += u.Tx
		r := e.procRate[pid]
		rate.Rx += r.Rx
		rate.Tx += r.Tx
	}
	return usage, rate
}
