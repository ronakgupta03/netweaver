// internal/process/scanner_test.go
package process

import (
	"testing"
)

func TestScanUserApplications(t *testing.T) {
	scanner := NewScanner()
	procs, err := scanner.ScanProcesses()
	if err != nil {
		t.Fatalf("failed to scan processes: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("expected at least one user process to be scanned")
	}
}

func TestIgnoredServicesExcluded(t *testing.T) {
	scanner := NewScanner()
	procs, err := scanner.ScanProcesses()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.Name == "systemd" || p.Name == "pipewire" || p.Name == "wireplumber" || p.Name == "waybar" {
			t.Fatalf("unexpected system service in user app list: %s", p.Name)
		}
	}
}

func TestParseCgroupAssignment(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantIface   string
		wantBlocked bool
	}{
		{
			name:        "flat interface path",
			content:     "0::/netweaver/wlan0\n",
			wantIface:   "wlan0",
			wantBlocked: false,
		},
		{
			name:        "leaf per-process cgroup path",
			content:     "0::/netweaver/wlan0/p1234\n",
			wantIface:   "wlan0",
			wantBlocked: false,
		},
		{
			name:        "multi-line cgroup file with leaf subpath",
			content:     "1:name=systemd:/user.slice/user-1000.slice\n0::/netweaver/enp0s31f6/p9876/sub\n",
			wantIface:   "enp0s31f6",
			wantBlocked: false,
		},
		{
			name:        "flat blocked cgroup path",
			content:     "0::/netweaver/blocked\n",
			wantIface:   "blocked",
			wantBlocked: true,
		},
		{
			name:        "leaf blocked cgroup path",
			content:     "0::/netweaver/blocked/p123\n",
			wantIface:   "blocked",
			wantBlocked: true,
		},
		{
			name:        "default cgroup path",
			content:     "0::/netweaver/default\n",
			wantIface:   "default",
			wantBlocked: false,
		},
		{
			name:        "default cgroup leaf path",
			content:     "0::/netweaver/default/p42\n",
			wantIface:   "default",
			wantBlocked: false,
		},
		{
			name:        "unrelated cgroup path",
			content:     "0::/user.slice/user-1000.slice/session-1.scope\n",
			wantIface:   "",
			wantBlocked: false,
		},
		{
			name:        "empty netweaver root path",
			content:     "0::/netweaver/\n",
			wantIface:   "",
			wantBlocked: false,
		},
		{
			name:        "empty content",
			content:     "",
			wantIface:   "",
			wantBlocked: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iface, blocked := parseCgroupAssignment(tc.content)
			if iface != tc.wantIface || blocked != tc.wantBlocked {
				t.Fatalf("parseCgroupAssignment(%q) = (%q, %v), want (%q, %v)",
					tc.content, iface, blocked, tc.wantIface, tc.wantBlocked)
			}
		})
	}
}

func TestAssignedInterfaceNonexistentPID(t *testing.T) {
	scanner := NewScanner()
	if got := scanner.AssignedInterface(-1); got != "" {
		t.Fatalf("AssignedInterface(-1) = %q, want empty", got)
	}
	if got := scanner.AssignedInterface(999999999); got != "" {
		t.Fatalf("AssignedInterface(999999999) = %q, want empty", got)
	}
}
