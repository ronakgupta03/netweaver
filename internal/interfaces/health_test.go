// internal/interfaces/health_test.go
package interfaces

import (
	"context"
	"errors"
	"math"
	"net"
	"netweaver/internal/types"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func almostEqual(a, b, eps float64) bool {
	return math.Abs(a-b) <= eps
}

func TestHealthProberDefaultMetrics(t *testing.T) {
	p := NewHealthProber()
	m := p.Metrics("eno1")
	if !m.Healthy {
		t.Fatal("expected unprobed interface to default Healthy=true")
	}
	if m.HealthScore != 100 {
		t.Fatalf("expected unprobed HealthScore=100, got %v", m.HealthScore)
	}
	if m.ProbeCount != 0 {
		t.Fatalf("expected ProbeCount=0, got %d", m.ProbeCount)
	}
}

func TestHealthProberEWMALatencyJitterLoss(t *testing.T) {
	var step atomic.Int32
	p := NewHealthProber(HealthProberConfig{
		FailThreshold: 3,
		LatencyAlpha:  0.3,
		JitterAlpha:   0.25,
		LossAlpha:     0.2,
		ProbeFn: func(ctx context.Context, iface types.InterfaceInfo) (time.Duration, error) {
			switch step.Load() {
			case 1:
				return 10 * time.Millisecond, nil
			case 2:
				return 20 * time.Millisecond, nil
			case 3:
				return 30 * time.Millisecond, nil
			default:
				return 0, errors.New("timeout")
			}
		},
	})

	ifaces := []types.InterfaceInfo{
		{Name: "eno1", IP: "192.168.1.50", Up: true},
	}

	// Probe 1: 10ms -> Latency=10, Jitter=0, Loss=0
	step.Store(1)
	p.ProbeOnce(context.Background(), ifaces)
	m := p.Metrics("eno1")
	if !almostEqual(m.LatencyMs, 10.0, 1e-6) || !almostEqual(m.JitterMs, 0.0, 1e-6) || !almostEqual(m.PacketLoss, 0.0, 1e-6) {
		t.Fatalf("after probe 1: %+v", m)
	}
	if !m.Healthy || m.HealthScore <= 95 || m.HealthScore > 100 {
		t.Fatalf("unexpected health after probe 1: %+v", m)
	}

	// Probe 2: 20ms -> delta=|20-10|=10; Jitter=0.25*10=2.5; Latency=0.7*10+0.3*20=13.0
	step.Store(2)
	p.ProbeOnce(context.Background(), ifaces)
	m = p.Metrics("eno1")
	if !almostEqual(m.LatencyMs, 13.0, 1e-6) || !almostEqual(m.JitterMs, 2.5, 1e-6) || !almostEqual(m.PacketLoss, 0.0, 1e-6) {
		t.Fatalf("after probe 2: %+v", m)
	}

	// Probe 3: 30ms -> delta=|30-13|=17; Jitter=0.75*2.5+0.25*17=6.125; Latency=0.7*13+0.3*30=18.1
	step.Store(3)
	p.ProbeOnce(context.Background(), ifaces)
	m = p.Metrics("eno1")
	if !almostEqual(m.LatencyMs, 18.1, 1e-6) || !almostEqual(m.JitterMs, 6.125, 1e-6) || !almostEqual(m.PacketLoss, 0.0, 1e-6) {
		t.Fatalf("after probe 3: %+v", m)
	}
	prevScore := m.HealthScore

	// Probe 4: failure -> PacketLoss = 0.8*0 + 0.2*100 = 20.0, Healthy stays true (1/3 fails)
	step.Store(4)
	p.ProbeOnce(context.Background(), ifaces)
	m = p.Metrics("eno1")
	if !almostEqual(m.PacketLoss, 20.0, 1e-6) {
		t.Fatalf("expected PacketLoss=20.0, got %v", m.PacketLoss)
	}
	if !m.Healthy {
		t.Fatal("expected Healthy=true after single failure below threshold")
	}
	if m.HealthScore >= prevScore {
		t.Fatalf("expected HealthScore to drop after loss, prev=%v cur=%v", prevScore, m.HealthScore)
	}
}

func TestHealthProberConsecutiveFailureThresholdAndRecovery(t *testing.T) {
	var mu sync.Mutex
	shouldFail := true
	var transitions []bool

	p := NewHealthProber(HealthProberConfig{
		FailThreshold: 3,
		LossAlpha:     0.2,
		ProbeFn: func(ctx context.Context, iface types.InterfaceInfo) (time.Duration, error) {
			mu.Lock()
			fail := shouldFail
			mu.Unlock()
			if fail {
				return 0, errors.New("upstream unreachable")
			}
			return 15 * time.Millisecond, nil
		},
		OnChange: func(iface string, healthy bool) {
			mu.Lock()
			transitions = append(transitions, healthy)
			mu.Unlock()
		},
	})

	ifaces := []types.InterfaceInfo{{Name: "wlan0", IP: "10.0.0.5", Up: true}}

	// Failure 1 and 2 must NOT mark unhealthy (anti-flap).
	p.ProbeOnce(context.Background(), ifaces)
	if m := p.Metrics("wlan0"); !m.Healthy || m.ConsecFails != 1 {
		t.Fatalf("after fail 1: %+v", m)
	}
	p.ProbeOnce(context.Background(), ifaces)
	if m := p.Metrics("wlan0"); !m.Healthy || m.ConsecFails != 2 {
		t.Fatalf("after fail 2: %+v", m)
	}

	// Failure 3 reaches FailThreshold=3 -> marks Healthy=false, HealthScore=0.
	p.ProbeOnce(context.Background(), ifaces)
	m := p.Metrics("wlan0")
	if m.Healthy {
		t.Fatalf("expected Healthy=false after 3 consecutive failures: %+v", m)
	}
	if m.ConsecFails != 3 || m.HealthScore != 0 {
		t.Fatalf("expected ConsecFails=3 and HealthScore=0: %+v", m)
	}

	// Single successful probe immediately restores Healthy=true and initializes LatencyMs cleanly.
	mu.Lock()
	shouldFail = false
	mu.Unlock()

	p.ProbeOnce(context.Background(), ifaces)
	m = p.Metrics("wlan0")
	if !m.Healthy || m.ConsecFails != 0 {
		t.Fatalf("expected immediate recovery to Healthy=true: %+v", m)
	}
	if !almostEqual(m.LatencyMs, 15.0, 1e-6) {
		t.Fatalf("expected initial latency sample 15ms without zero-bias, got %v", m.LatencyMs)
	}
	if m.HealthScore <= 0 {
		t.Fatalf("expected positive HealthScore after recovery, got %v", m.HealthScore)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 2 || transitions[0] != false || transitions[1] != true {
		t.Fatalf("unexpected health transitions: %v", transitions)
	}
}

func TestHealthProberStartLoop(t *testing.T) {
	var calls atomic.Int32
	p := NewHealthProber(HealthProberConfig{
		Interval: 15 * time.Millisecond,
		Timeout:  200 * time.Millisecond,
		ProbeFn: func(ctx context.Context, iface types.InterfaceInfo) (time.Duration, error) {
			calls.Add(1)
			return 5 * time.Millisecond, nil
		},
		InterfaceProvider: func() []types.InterfaceInfo {
			return []types.InterfaceInfo{{Name: "eth0", IP: "192.168.1.10", Up: true}}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Start(ctx)
		close(done)
	}()

	deadline := time.After(500 * time.Millisecond)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("expected at least 2 probe calls, got %d", calls.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start did not exit promptly on cancel")
	}

	m := p.Metrics("eth0")
	if !m.Healthy || m.ProbeCount < 2 || !almostEqual(m.LatencyMs, 5.0, 1e-6) {
		t.Fatalf("unexpected metrics after Start loop: %+v", m)
	}
}

func TestDefaultProbeLoopbackTCP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	probe := DefaultProbe([]string{ln.Addr().String()}, 500*time.Millisecond)
	rtt, err := probe(context.Background(), types.InterfaceInfo{
		Name: "lo",
		IP:   "127.0.0.1",
		Up:   true,
	})
	if err != nil {
		t.Fatalf("expected loopback probe to succeed, got %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("expected positive RTT, got %v", rtt)
	}

	// Closed port should fail cleanly.
	closedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen temp: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	failProbe := DefaultProbe([]string{closedAddr}, 300*time.Millisecond)
	if _, err := failProbe(context.Background(), types.InterfaceInfo{
		Name: "lo",
		IP:   "127.0.0.1",
		Up:   true,
	}); err == nil {
		t.Fatal("expected probe to closed port to return an error")
	}
}
