// internal/interfaces/health.go
package interfaces

import (
	"context"
	"errors"
	"math"
	"net"
	"netweaver/internal/types"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	defaultProbeInterval      = 5 * time.Second
	defaultProbeTimeout       = 1500 * time.Millisecond
	defaultProbeFailThreshold = 3
	defaultLatencyAlpha       = 0.3
	defaultJitterAlpha        = 0.25
	defaultLossAlpha          = 0.2
)

var defaultProbeTargetsV4 = []string{"1.1.1.1:443", "8.8.8.8:53"}
var defaultProbeTargetsV6 = []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:53"}

// ProbeFn performs a single reachability and latency probe over iface.
type ProbeFn func(ctx context.Context, iface types.InterfaceInfo) (rtt time.Duration, err error)

// HealthMetrics holds EWMA link-quality and liveness state for one interface.
type HealthMetrics struct {
	LatencyMs    float64
	JitterMs     float64
	PacketLoss   float64
	Healthy      bool
	HealthScore  float64
	ConsecFails  int
	ProbeCount   uint64
	LastProbedAt time.Time
	LastErr      string
}

type probeState struct {
	metrics    HealthMetrics
	hasLatency bool
}

// HealthProberConfig configures a HealthProber instance.
type HealthProberConfig struct {
	Interval          time.Duration
	Timeout           time.Duration
	FailThreshold     int
	LatencyAlpha      float64
	JitterAlpha       float64
	LossAlpha         float64
	Targets           []string
	ProbeFn           ProbeFn
	InterfaceProvider func() []types.InterfaceInfo
	OnChange          func(iface string, healthy bool)
}

// HealthProber actively probes network interfaces to measure EWMA latency,
// jitter, packet loss, and upstream internet liveness.
type HealthProber struct {
	interval      time.Duration
	timeout       time.Duration
	failThreshold int
	latencyAlpha  float64
	jitterAlpha   float64
	lossAlpha     float64
	probeFn       ProbeFn

	mu            sync.RWMutex
	states        map[string]*probeState
	ifaces        []types.InterfaceInfo
	ifaceProvider func() []types.InterfaceInfo
	onChange      func(iface string, healthy bool)
	notifyCh      chan<- struct{}
}

// NewHealthProber constructs a HealthProber with sensible defaults and optional overrides.
func NewHealthProber(cfgs ...HealthProberConfig) *HealthProber {
	var cfg HealthProberConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultProbeInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultProbeTimeout
	}
	if cfg.FailThreshold <= 0 {
		cfg.FailThreshold = defaultProbeFailThreshold
	}
	if cfg.LatencyAlpha <= 0 || cfg.LatencyAlpha > 1 {
		cfg.LatencyAlpha = defaultLatencyAlpha
	}
	if cfg.JitterAlpha <= 0 || cfg.JitterAlpha > 1 {
		cfg.JitterAlpha = defaultJitterAlpha
	}
	if cfg.LossAlpha <= 0 || cfg.LossAlpha > 1 {
		cfg.LossAlpha = defaultLossAlpha
	}
	if cfg.ProbeFn == nil {
		cfg.ProbeFn = DefaultProbe(cfg.Targets, cfg.Timeout)
	}

	return &HealthProber{
		interval:      cfg.Interval,
		timeout:       cfg.Timeout,
		failThreshold: cfg.FailThreshold,
		latencyAlpha:  cfg.LatencyAlpha,
		jitterAlpha:   cfg.JitterAlpha,
		lossAlpha:     cfg.LossAlpha,
		probeFn:       cfg.ProbeFn,
		states:        make(map[string]*probeState),
		ifaceProvider: cfg.InterfaceProvider,
		onChange:      cfg.OnChange,
	}
}

// SetInterfaceProvider configures a callback returning active interfaces to probe during Start.
func (p *HealthProber) SetInterfaceProvider(fn func() []types.InterfaceInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ifaceProvider = fn
}

// SetInterfaces stores a snapshot of interfaces to probe when no InterfaceProvider is set.
func (p *HealthProber) SetInterfaces(ifaces []types.InterfaceInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]types.InterfaceInfo, len(ifaces))
	copy(cp, ifaces)
	p.ifaces = cp
}

// SetOnChange registers a callback invoked when an interface's Healthy status changes.
func (p *HealthProber) SetOnChange(fn func(iface string, healthy bool)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onChange = fn
}

func (p *HealthProber) setNotifyChan(ch chan<- struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notifyCh = ch
}

// Start runs periodic active probing until ctx is cancelled.
func (p *HealthProber) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.probeCurrent(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeCurrent(ctx)
		}
	}
}

func (p *HealthProber) probeCurrent(ctx context.Context) {
	p.mu.RLock()
	provider := p.ifaceProvider
	var snapshot []types.InterfaceInfo
	if provider == nil && len(p.ifaces) > 0 {
		snapshot = make([]types.InterfaceInfo, len(p.ifaces))
		copy(snapshot, p.ifaces)
	}
	p.mu.RUnlock()

	if provider != nil {
		snapshot = provider()
	}
	if len(snapshot) == 0 {
		return
	}
	p.ProbeOnce(ctx, snapshot)
}

// ProbeOnce probes all active interfaces in ifaces concurrently and updates EWMA metrics.
func (p *HealthProber) ProbeOnce(ctx context.Context, ifaces []types.InterfaceInfo) {
	if p == nil || len(ifaces) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		if iface.Name == "" || iface.Name == "lo" || !iface.Up {
			continue
		}
		wg.Add(1)
		go func(info types.InterfaceInfo) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
			defer cancel()

			rtt, err := p.probeFn(probeCtx, info)
			// Do not count probes aborted solely due to parent context cancellation.
			if err != nil && ctx.Err() != nil {
				return
			}
			p.recordSample(info.Name, rtt, err)
		}(iface)
	}
	wg.Wait()
}

func (p *HealthProber) recordSample(name string, rtt time.Duration, probeErr error) {
	now := time.Now()

	p.mu.Lock()
	st, ok := p.states[name]
	if !ok {
		st = &probeState{
			metrics: HealthMetrics{
				Healthy:     true,
				HealthScore: 100,
			},
		}
		p.states[name] = st
	}

	prevHealthy := st.metrics.Healthy
	st.metrics.ProbeCount++
	st.metrics.LastProbedAt = now

	if probeErr == nil {
		rttMs := float64(rtt) / float64(time.Millisecond)
		if rttMs < 0 {
			rttMs = 0
		}
		if !st.hasLatency {
			st.metrics.LatencyMs = rttMs
			st.metrics.JitterMs = 0
			st.hasLatency = true
		} else {
			delta := math.Abs(rttMs - st.metrics.LatencyMs)
			st.metrics.JitterMs = (1-p.jitterAlpha)*st.metrics.JitterMs + p.jitterAlpha*delta
			st.metrics.LatencyMs = (1-p.latencyAlpha)*st.metrics.LatencyMs + p.latencyAlpha*rttMs
		}
		st.metrics.PacketLoss = (1 - p.lossAlpha) * st.metrics.PacketLoss
		if st.metrics.PacketLoss < 1e-9 {
			st.metrics.PacketLoss = 0
		}
		st.metrics.ConsecFails = 0
		st.metrics.Healthy = true
		st.metrics.LastErr = ""
	} else {
		st.metrics.ConsecFails++
		st.metrics.PacketLoss = (1-p.lossAlpha)*st.metrics.PacketLoss + p.lossAlpha*100.0
		if st.metrics.PacketLoss > 100 {
			st.metrics.PacketLoss = 100
		}
		st.metrics.LastErr = probeErr.Error()
		if st.metrics.ConsecFails >= p.failThreshold {
			st.metrics.Healthy = false
		}
	}

	st.metrics.HealthScore = ComputeHealthScore(
		st.metrics.LatencyMs,
		st.metrics.JitterMs,
		st.metrics.PacketLoss,
		st.metrics.Healthy,
	)

	newHealthy := st.metrics.Healthy
	onChange := p.onChange
	notifyCh := p.notifyCh
	p.mu.Unlock()

	if newHealthy != prevHealthy {
		if notifyCh != nil {
			select {
			case notifyCh <- struct{}{}:
			default:
			}
		}
		if onChange != nil {
			onChange(name, newHealthy)
		}
	}
}

// Metrics returns the current health metrics for name. If no probe has completed
// yet for name, Healthy defaults to true and HealthScore defaults to 100.
func (p *HealthProber) Metrics(name string) HealthMetrics {
	if p == nil {
		return HealthMetrics{Healthy: true, HealthScore: 100}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if st, ok := p.states[name]; ok {
		return st.metrics
	}
	return HealthMetrics{Healthy: true, HealthScore: 100}
}

// AllMetrics returns a copy of health metrics for all probed interfaces.
func (p *HealthProber) AllMetrics() map[string]HealthMetrics {
	out := make(map[string]HealthMetrics)
	if p == nil {
		return out
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for name, st := range p.states {
		out[name] = st.metrics
	}
	return out
}

// ComputeHealthScore computes a normalized 0..100 health score from latency, jitter,
// packet loss percentage (0..100), and liveness state.
func ComputeHealthScore(latencyMs, jitterMs, packetLoss float64, healthy bool) float64 {
	if !healthy {
		return 0
	}
	latPenalty := math.Min(math.Max(latencyMs, 0)*0.15, 45.0)
	jitPenalty := math.Min(math.Max(jitterMs, 0)*0.50, 25.0)
	lossPenalty := math.Min(math.Max(packetLoss, 0), 100.0)
	score := 100.0 - latPenalty - jitPenalty - lossPenalty
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// DefaultProbe returns a ProbeFn that dials TCP targets bound strictly to iface
// using SO_BINDTODEVICE (with fallback to source IP binding when unprivileged).
func DefaultProbe(targets []string, timeout time.Duration) ProbeFn {
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	configuredTargets := append([]string(nil), targets...)

	return func(ctx context.Context, iface types.InterfaceInfo) (time.Duration, error) {
		localIP := net.ParseIP(strings.TrimSpace(iface.IP))
		if iface.Name == "" && localIP == nil {
			return 0, errors.New("interface has neither name nor IP")
		}

		network := "tcp4"
		activeTargets := configuredTargets
		if localIP != nil && localIP.To4() == nil {
			network = "tcp6"
			if len(activeTargets) == 0 {
				activeTargets = defaultProbeTargetsV6
			}
		} else if len(activeTargets) == 0 {
			activeTargets = defaultProbeTargetsV4
		}

		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		type probeResult struct {
			rtt time.Duration
			err error
		}
		results := make(chan probeResult, len(activeTargets))

		for _, target := range activeTargets {
			go func(addr string) {
				dialer := &net.Dialer{
					Timeout: timeout,
					Control: func(network, address string, c syscall.RawConn) error {
						if iface.Name == "" {
							return nil
						}
						var bindErr error
						if err := c.Control(func(fd uintptr) {
							bindErr = unix.BindToDevice(int(fd), iface.Name)
						}); err != nil {
							return err
						}
						if bindErr != nil {
							if (errors.Is(bindErr, unix.EPERM) || errors.Is(bindErr, unix.EACCES)) && localIP != nil {
								return nil
							}
							return bindErr
						}
						return nil
					},
				}
				if localIP != nil {
					dialer.LocalAddr = &net.TCPAddr{IP: localIP}
				}

				start := time.Now()
				conn, err := dialer.DialContext(probeCtx, network, addr)
				if err != nil {
					results <- probeResult{err: err}
					return
				}
				rtt := time.Since(start)
				_ = conn.Close()
				results <- probeResult{rtt: rtt}
			}(target)
		}

		var lastErr error
		for range activeTargets {
			res := <-results
			if res.err == nil {
				cancel()
				return res.rtt, nil
			}
			lastErr = res.err
		}
		if lastErr == nil {
			lastErr = errors.New("probe failed")
		}
		return 0, lastErr
	}
}
