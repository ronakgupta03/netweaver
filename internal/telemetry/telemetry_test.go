package telemetry

import (
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
