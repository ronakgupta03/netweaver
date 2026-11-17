// cmd/netweaver/main_test.go
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"netweaver/internal/types"
)

func TestParseByteSizeAndRateLimit(t *testing.T) {
	cases := []struct {
		input string
		want  uint64
	}{
		{"0", 0},
		{"1024", 1024},
		{"500B", 500},
		{"256K", 256 * 1024},
		{"256KiB", 256 * 1024},
		{"500KB", 500_000},
		{"1.5GB", 1_500_000_000},
		{"2GiB", 2 * 1024 * 1024 * 1024},
		{"10MB", 10_000_000},
		{"1MiB", 1024 * 1024},
		{"  2.5 TiB ", 2748779069440},
	}
	for _, tc := range cases {
		got, err := ParseByteSize(tc.input)
		if err != nil {
			t.Fatalf("ParseByteSize(%q) unexpected err: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseByteSize(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}

	rateCases := []struct {
		input string
		want  uint64
	}{
		{"0", 0},
		{"unlimited", 0},
		{"256KiB/s", 256 * 1024},
		{"500KB/s", 500_000},
		{"1.5MB/sec", 1_500_000},
		{"2M", 2 * 1024 * 1024},
	}
	for _, tc := range rateCases {
		got, err := ParseRateLimit(tc.input)
		if err != nil {
			t.Fatalf("ParseRateLimit(%q) unexpected err: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseRateLimit(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}

	bad := []string{"", "-5MB", "abc", "10XB", "NaN", "Inf"}
	for _, s := range bad {
		if _, err := ParseByteSize(s); err == nil {
			t.Fatalf("expected error for ParseByteSize(%q)", s)
		}
	}
}

func TestParseAssignArgs(t *testing.T) {
	opts, err := parseAssignArgs([]string{"1234", "@low-latency", "strict", "--rate", "1MiB/s"})
	if err != nil {
		t.Fatalf("parseAssignArgs: %v", err)
	}
	if opts.pid != 1234 || opts.target != "@low-latency" || opts.policy != types.PolicyStrict || opts.rateLimitBps != 1024*1024 {
		t.Fatalf("unexpected opts: %+v", opts)
	}

	opts2, err := parseAssignArgs([]string{"--failover", "--rate=500KB", "42", "wlan0"})
	if err != nil {
		t.Fatalf("parseAssignArgs interleaved: %v", err)
	}
	if opts2.pid != 42 || opts2.target != "wlan0" || opts2.policy != types.PolicyFailover || opts2.rateLimitBps != 500_000 {
		t.Fatalf("unexpected opts2: %+v", opts2)
	}

	if _, err := parseAssignArgs([]string{"1234", "wlan0", "strict", "--failover"}); err == nil {
		t.Fatal("expected error for conflicting policy and flag")
	}
	if _, err := parseAssignArgs([]string{"0", "wlan0"}); err == nil {
		t.Fatal("expected error for PID 0")
	}
	if _, err := parseAssignArgs([]string{"1234", "@unknown"}); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestParseRuleAddArgs(t *testing.T) {
	rule, err := parseRuleAddArgs([]string{
		"firefox", "@unmetered", "strict",
		"--domains", "example.com, *.corp.internal",
		"--rate=2MiB/s",
		"--background",
	})
	if err != nil {
		t.Fatalf("parseRuleAddArgs: %v", err)
	}
	if rule.Match != "firefox" || rule.Interface != "@unmetered" || rule.Policy != types.PolicyStrict {
		t.Fatalf("unexpected rule core: %+v", rule)
	}
	if !rule.Background || rule.RateLimitBps != 2*1024*1024 || len(rule.Domains) != 2 || rule.Domains[1] != "*.corp.internal" {
		t.Fatalf("unexpected rule extras: %+v", rule)
	}

	if _, err := parseRuleAddArgs([]string{"firefox", "wlan0", "--strict", "--failover"}); err == nil {
		t.Fatal("expected error when both --strict and --failover given")
	}
}

func TestParseQuotaSetArgs(t *testing.T) {
	cfg, err := parseQuotaSetArgs([]string{"wwan0", "1.5GB", "--warn", "75", "--metered"})
	if err != nil {
		t.Fatalf("parseQuotaSetArgs: %v", err)
	}
	if cfg.Interface != "wwan0" || cfg.DailyLimitBytes != 1_500_000_000 || cfg.WarnPercent != 75 || !cfg.Metered {
		t.Fatalf("unexpected quota cfg: %+v", cfg)
	}

	if _, err := parseQuotaSetArgs([]string{"wwan0", "1GB", "--warn", "150"}); err == nil {
		t.Fatal("expected error for warn > 100")
	}
}

func TestParseDNSServersArg(t *testing.T) {
	servers, err := parseDNSServersArg("1.1.1.1, 2606:4700:4700::1111")
	if err != nil {
		t.Fatalf("parseDNSServersArg: %v", err)
	}
	if len(servers) != 2 || servers[0] != "1.1.1.1" {
		t.Fatalf("unexpected servers: %+v", servers)
	}
	cleared, err := parseDNSServersArg("clear")
	if err != nil || len(cleared) != 0 {
		t.Fatalf("expected clear to return nil, got %+v err=%v", cleared, err)
	}
	if _, err := parseDNSServersArg("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid DNS IP")
	}
}

func TestBuildWaybarStatusJSON(t *testing.T) {
	// Offline state
	off := buildWaybarStatus(nil, nil, "", errors.New("dial unix: no such file"))
	rawOff, err := json.Marshal(off)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawOff), "\n") || off.Class != "offline" {
		t.Fatalf("invalid offline waybar JSON: %s", string(rawOff))
	}

	// Healthy ok state
	ifaces := []types.InterfaceInfo{
		{Name: "eno1", IP: "10.0.0.2", Up: true, Healthy: true, LatencyMs: 8, RxRate: 2048, TxRate: 1024},
	}
	procs := []types.ProcessInfo{
		{PID: 1001, Name: "firefox", AssignedInterface: "eno1"},
	}
	okStatus := buildWaybarStatus(ifaces, procs, types.PolicyFailover, nil)
	rawOK, err := json.Marshal(okStatus)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawOK), "\n") {
		t.Fatalf("waybar JSON must be single-line: %s", string(rawOK))
	}
	var decoded WaybarStatus
	if err := json.Unmarshal(rawOK, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.Class != "ok" || !strings.Contains(decoded.Text, "eno1") || !strings.Contains(decoded.Tooltip, "10.0.0.2") {
		t.Fatalf("unexpected ok waybar status: %+v", decoded)
	}

	// Warning state (unhealthy interface while another is up)
	ifacesWarn := append(ifaces, types.InterfaceInfo{Name: "wlan0", IP: "192.168.1.5", Up: true, Healthy: false})
	warnStatus := buildWaybarStatus(ifacesWarn, procs, types.PolicyStrict, nil)
	if warnStatus.Class != "warning" {
		t.Fatalf("expected warning class, got %q", warnStatus.Class)
	}

	// Critical state (blocked process or quota exceeded)
	procs[0].Blocked = true
	critStatus := buildWaybarStatus(ifaces, procs, types.PolicyStrict, nil)
	if critStatus.Class != "critical" || !strings.Contains(critStatus.Text, "[BLK:1]") {
		t.Fatalf("expected critical class with BLK tag, got %+v", critStatus)
	}
}

func TestRunCommandZeroLeakAndExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var gotPID int
	var gotIface, gotPol string
	var gotRate uint64
	assignedBeforeStart := false

	// Successful run with child exit code 7; verify assignFn ran BEFORE child executed.
	marker := t.TempDir() + "/ran"
	code := runCommand(
		[]string{"-i", "wlan0", "--strict", "--rate", "256KiB", "sh", "-c", "test -f " + marker + " && exit 7 || exit 99"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(pid int, iface, policy string, rateLimitBps uint64) error {
			gotPID = pid
			gotIface = iface
			gotPol = policy
			gotRate = rateLimitBps
			// Create marker BEFORE child starts so child can prove assignFn ran first.
			if err := os.WriteFile(marker, []byte("ok"), 0o644); err != nil {
				return err
			}
			assignedBeforeStart = true
			return nil
		},
	)
	if !assignedBeforeStart || gotPID != os.Getpid() || gotIface != "wlan0" || gotPol != types.PolicyStrict || gotRate != 256*1024 {
		t.Fatalf("unexpected assign call: before=%v pid=%d iface=%q pol=%q rate=%d", assignedBeforeStart, gotPID, gotIface, gotPol, gotRate)
	}
	if code != 7 {
		t.Fatalf("runCommand exit code = %d, want 7 (stderr: %s)", code, stderr.String())
	}

	// If assignFn fails, child MUST NOT run (zero-leak guarantee).
	leakFile := t.TempDir() + "/leaked"
	stderr.Reset()
	code = runCommand(
		[]string{"-i", "@unmetered", "--strict", "touch", leakFile},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(pid int, iface, policy string, rateLimitBps uint64) error {
			return errors.New("no unmetered interface")
		},
	)
	if code == 0 {
		t.Fatal("expected non-zero exit when pre-launch assign fails")
	}
	if _, err := os.Stat(leakFile); !os.IsNotExist(err) {
		t.Fatal("child process ran despite pre-launch assign failure!")
	}
}

func TestRenderTablesAndEvents(t *testing.T) {
	var buf bytes.Buffer
	renderProcessList(&buf, []types.ProcessInfo{
		{PID: 1234, Name: "firefox", AssignedInterface: "wlan0", Profile: "@low-latency", Policy: "strict", RateLimitBps: 1024 * 1024, RxRate: 2048, TxRate: 512, RxBytes: 4096, Blocked: true},
	})
	out := buf.String()
	for _, want := range []string{"PID", "POLICY", "RATE CAP", "wlan0 (@low-latency)", "strict", "1.0 MiB/s", "[BLOCKED]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("renderProcessList missing %q in:\n%s", want, out)
		}
	}

	buf.Reset()
	renderInterfaceList(&buf, []types.InterfaceInfo{
		{Name: "wg0", IP: "10.8.0.2", TableID: 263, Up: true, Healthy: true, IsTunnel: true, LatencyMs: 18.4, Metered: true, DailyQuotaBytes: 1000, DailyUsedBytes: 1200, QuotaExceeded: true, DNSServers: []string{"1.1.1.1"}},
	})
	out = buf.String()
	for _, want := range []string{"wg0 [VPN]", "UP 18.4ms", "EXCEEDED", "1.1.1.1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("renderInterfaceList missing %q in:\n%s", want, out)
		}
	}

	buf.Reset()
	renderRulesList(&buf, []types.Rule{
		{Match: "steam", Interface: "@high-bandwidth", Policy: "failover", RateLimitBps: 5 * 1024 * 1024, Background: true, Domains: []string{"steampowered.com"}},
	})
	out = buf.String()
	for _, want := range []string{"steam", "@high-bandwidth", "5.0 MiB/s", "yes", "steampowered.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("renderRulesList missing %q in:\n%s", want, out)
		}
	}

	buf.Reset()
	renderQuotaList(&buf, []types.QuotaConfig{
		{Interface: "wwan0", Metered: true, UsedBytes: 900, DailyLimitBytes: 1000, WarnPercent: 80},
	})
	if !strings.Contains(buf.String(), "WARNING") {
		t.Fatalf("expected WARNING in quota table, got:\n%s", buf.String())
	}
}
