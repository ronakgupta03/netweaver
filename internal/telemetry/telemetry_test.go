package telemetry

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const ssFixture = `State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 0 10.0.0.5:51000 93.184.216.34:443 users:(("firefox",pid=1725,fd=217))
	 cubic wscale:8,10 bytes_sent:3345 bytes_acked:3346 bytes_received:2356
ESTAB 0 0 10.0.0.5:51002 93.184.216.34:443 users:(("firefox",pid=1725,fd=219))
	 cubic wscale:8,10 bytes_sent:100 bytes_acked:100 bytes_received:900
ESTAB 0 0 127.0.0.1:51003 127.0.0.1:8080 users:(("omp",pid=8360,fd=74))
	 cubic wscale:8,10 bytes_sent:999999 bytes_acked:999999 bytes_received:888888
ESTAB 0 0 10.0.0.5:51004 140.82.113.4:443 users:(("Discord",pid=3403,fd=32),("firefox",pid=1725,fd=300))
	 cubic wscale:8,10 bytes_sent:10 bytes_acked:20 bytes_received:40
`

func TestParseSSAggregatesPerPID(t *testing.T) {
	got := ParseSS(ssFixture)

	firefox := got[1725]
	if firefox.Rx != 2356+900+40 {
		t.Fatalf("firefox rx = %d, want 3296", firefox.Rx)
	}
	if firefox.Tx != 3346+100+20 {
		t.Fatalf("firefox tx = %d, want 3466", firefox.Tx)
	}
	if _, ok := got[8360]; ok {
		t.Fatal("loopback-only socket must not be accounted")
	}
	if got[3403].Rx != 40 {
		t.Fatalf("discord rx = %d, want 40", got[3403].Rx)
	}
}

func writeCounter(t *testing.T, root, iface, file string, v string) {
	t.Helper()
	dir := filepath.Join(root, iface, "statistics")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(v), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInterfaceRatesAndUsage(t *testing.T) {
	root := t.TempDir()
	writeCounter(t, root, "wlan0", "rx_bytes", "1000")
	writeCounter(t, root, "wlan0", "tx_bytes", "500")

	e := NewEngineWithRoot(root)
	clock := time.Unix(1700000000, 0)
	e.now = func() time.Time { return clock }

	e.Sample()
	usage, rate := e.InterfaceUsage("wlan0")
	if usage.Rx != 1000 || usage.Tx != 500 {
		t.Fatalf("usage = %+v, want rx=1000 tx=500", usage)
	}
	if rate.Rx != 0 || rate.Tx != 0 {
		t.Fatalf("first sample must report zero rate, got %+v", rate)
	}

	writeCounter(t, root, "wlan0", "rx_bytes", "4096")
	writeCounter(t, root, "wlan0", "tx_bytes", "500")
	clock = clock.Add(time.Second)
	e.Sample()

	usage, rate = e.InterfaceUsage("wlan0")
	if usage.Rx != 4096 {
		t.Fatalf("usage rx = %d, want 4096", usage.Rx)
	}
	if rate.Rx != 3096 {
		t.Fatalf("rx rate = %v, want 3096 B/s", rate.Rx)
	}
	if rate.Tx != 0 {
		t.Fatalf("tx rate = %v, want 0", rate.Tx)
	}
}

func TestFormatBytesAndRate(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1024, "1.0 KiB"},
		{1536 * 1024, "1.5 MiB"},
		{3 * 1024 * 1024 * 1024, "3.0 GiB"},
	}
	for _, c := range cases {
		if got := FormatBytes(c.in); got != c.want {
			t.Fatalf("FormatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := FormatRate(0); got != "0 B/s" {
		t.Fatalf("FormatRate(0) = %q", got)
	}
	if got := FormatRate(2048); got != "2.0 KiB/s" {
		t.Fatalf("FormatRate(2048) = %q", got)
	}
}

func TestParseSSWithNetidAndUDPQUIC(t *testing.T) {
	fixture := `tcp ESTAB 0 0 10.0.0.5:51000 93.184.216.34:443 users:(("firefox",pid=1725,fd=217))
	 cubic wscale:8,10 bytes_acked:2000 bytes_received:4000
tcp ESTAB 0 0 127.0.0.1:51003 127.0.0.1:8080 users:(("local",pid=8360,fd=74))
	 cubic bytes_acked:999999 bytes_received:888888
udp ESTAB 0 0 10.0.0.5:49632 162.159.137.232:443 users:(("Discord",pid=3403,fd=18))
udp UNCONN 0 0 0.0.0.0:41488 0.0.0.0:* users:(("wireguard",pid=4444,fd=7))
`
	got := ParseSS(fixture)
	if got[1725].Rx != 4000 || got[1725].Tx != 2000 {
		t.Fatalf("pid 1725 = %+v, want Rx=4000 Tx=2000", got[1725])
	}
	if _, ok := got[8360]; ok {
		t.Fatal("loopback-only socket with netid column must be skipped")
	}
	if _, ok := got[3403]; !ok {
		t.Fatal("connected UDP/QUIC socket PID 3403 should be tracked")
	}

	socks := ParseSSSockets(fixture)
	if len(socks) != 3 {
		t.Fatalf("len(sockets) = %d, want 3: %+v", len(socks), socks)
	}
	var sawTCP, sawQUIC, sawUDP bool
	for _, s := range socks {
		switch {
		case s.PID == 1725 && s.Proto == "tcp" && s.RxBytes == 4000 && s.TxBytes == 2000:
			sawTCP = true
		case s.PID == 3403 && s.Proto == "quic" && s.State == "ESTAB":
			sawQUIC = true
		case s.PID == 4444 && s.Proto == "udp" && s.State == "UNCONN":
			sawUDP = true
		}
	}
	if !sawTCP || !sawQUIC || !sawUDP {
		t.Fatalf("unexpected socket classification: %+v", socks)
	}
}

func TestCgroupStatsReaderOverridesAndFallsBack(t *testing.T) {
	root := t.TempDir()
	writeCounter(t, root, "wlan0", "rx_bytes", "100")
	writeCounter(t, root, "wlan0", "tx_bytes", "50")
	writeCounter(t, root, "eno1", "rx_bytes", "3000")
	writeCounter(t, root, "eno1", "tx_bytes", "1500")

	e := NewEngineWithRoot(root)
	e.procBytesFn = func() (map[int]ProcBytes, error) { return map[int]ProcBytes{}, nil }
	clock := time.Unix(1700000000, 0)
	e.now = func() time.Time { return clock }

	wlanRx, wlanTx := uint64(5000), uint64(2000)
	e.SetCgroupStatsReader(func(iface string) (uint64, uint64, bool) {
		if iface == "wlan0" {
			return wlanRx, wlanTx, true
		}
		return 0, 0, false // eno1 falls back to sysfs
	})

	e.Sample()
	uWlan, rWlan := e.InterfaceUsage("wlan0")
	if uWlan.Rx != 5000 || uWlan.Tx != 2000 || rWlan.Rx != 0 {
		t.Fatalf("tick1 wlan0 = %+v rate=%+v", uWlan, rWlan)
	}
	uEno, _ := e.InterfaceUsage("eno1")
	if uEno.Rx != 3000 || uEno.Tx != 1500 {
		t.Fatalf("tick1 eno1 sysfs fallback = %+v", uEno)
	}

	wlanRx, wlanTx = 9000, 3500
	writeCounter(t, root, "eno1", "rx_bytes", "4000")
	clock = clock.Add(2 * time.Second)
	e.Sample()

	uWlan, rWlan = e.InterfaceUsage("wlan0")
	if uWlan.Rx != 9000 || uWlan.Tx != 3500 {
		t.Fatalf("tick2 wlan0 = %+v", uWlan)
	}
	if rWlan.Rx != 2000 || rWlan.Tx != 750 {
		t.Fatalf("tick2 wlan0 rate = %+v, want Rx=2000 Tx=750", rWlan)
	}
	uEno, rEno := e.InterfaceUsage("eno1")
	if uEno.Rx != 4000 || rEno.Rx != 500 {
		t.Fatalf("tick2 eno1 = %+v rate=%+v", uEno, rEno)
	}
}

func TestProcessStatsReaderMergesAndFallsBackToSS(t *testing.T) {
	e := NewEngineWithRoot(t.TempDir())
	clock := time.Unix(1700000000, 0)
	e.now = func() time.Time { return clock }

	ssData := map[int]ProcBytes{
		100: {Rx: 500, Tx: 200}, // no eBPF leaf cgroup -> ss fallback
		200: {Rx: 100, Tx: 50},  // also in eBPF -> eBPF overrides with TCP+UDP+QUIC
	}
	var ssErr error
	e.procBytesFn = func() (map[int]ProcBytes, error) {
		if ssErr != nil {
			return nil, ssErr
		}
		out := make(map[int]ProcBytes, len(ssData))
		for k, v := range ssData {
			out[k] = v
		}
		return out, nil
	}

	ebpfStats := map[int]ProcBytes{
		200: {Rx: 4000, Tx: 1200},
		300: {Rx: 800, Tx: 300}, // pure UDP/QUIC/ICMP PID absent from ss
	}
	e.SetProcessStatsReader(func(pid int) (uint64, uint64, bool) {
		v, ok := ebpfStats[pid]
		return v.Rx, v.Tx, ok
	})
	e.TrackPID(300)

	e.Sample()
	u100, _ := e.ProcessUsage(100)
	if u100.Rx != 500 || u100.Tx != 200 {
		t.Fatalf("pid 100 fallback = %+v, want Rx=500 Tx=200", u100)
	}
	u200, _ := e.ProcessUsage(200)
	if u200.Rx != 4000 || u200.Tx != 1200 {
		t.Fatalf("pid 200 ebpf = %+v, want Rx=4000 Tx=1200", u200)
	}
	u300, _ := e.ProcessUsage(300)
	if u300.Rx != 800 || u300.Tx != 300 {
		t.Fatalf("pid 300 ebpf = %+v, want Rx=800 Tx=300", u300)
	}

	// Simulate second sample with ss unavailable; eBPF must keep working.
	ssErr = errors.New("ss missing")
	ebpfStats[200] = ProcBytes{Rx: 6000, Tx: 2200}
	ebpfStats[300] = ProcBytes{Rx: 1800, Tx: 700}
	clock = clock.Add(time.Second)
	e.Sample()

	if !e.SocketAccountingAvailable() {
		t.Fatal("SocketAccountingAvailable must remain true when processStatsReader is set")
	}
	u200, r200 := e.ProcessUsage(200)
	if u200.Rx != 6000 || r200.Rx != 2000 || r200.Tx != 1000 {
		t.Fatalf("pid 200 tick2 = %+v rate=%+v", u200, r200)
	}
	subU, subR := e.SubtreeUsage([]int{200, 300})
	if subU.Rx != 7800 || subU.Tx != 2900 || subR.Rx != 3000 || subR.Tx != 1400 {
		t.Fatalf("SubtreeUsage = %+v rate=%+v", subU, subR)
	}
}
