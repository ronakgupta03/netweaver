// internal/quota/manager_test.go
package quota

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"netweaver/internal/types"
)

func TestManagerPersistenceAndCRUD(t *testing.T) {
	if got := NewManager("").path; got != DefaultPath {
		t.Fatalf("default path = %q, want %q", got, DefaultPath)
	}

	path := filepath.Join(t.TempDir(), "nested", "quotas.json")
	m := NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if len(m.List()) != 0 {
		t.Fatalf("expected empty list, got %+v", m.List())
	}

	if err := m.SetQuota(types.QuotaConfig{Interface: "bad name!", DailyLimitBytes: 100}); err == nil {
		t.Fatal("expected error for invalid interface name")
	}
	if err := m.SetQuota(types.QuotaConfig{Interface: "usb0", DailyLimitBytes: 100, WarnPercent: 101}); err == nil {
		t.Fatal("expected error for invalid warn_percent")
	}

	if err := m.SetQuota(types.QuotaConfig{
		Interface:       "usb0",
		Metered:         true,
		DailyLimitBytes: 1000,
	}); err != nil {
		t.Fatalf("SetQuota usb0: %v", err)
	}
	if err := m.SetQuota(types.QuotaConfig{
		Interface:       "eno1",
		Metered:         false,
		DailyLimitBytes: 5000,
		WarnPercent:     90,
	}); err != nil {
		t.Fatalf("SetQuota eno1: %v", err)
	}

	// Reload from disk into a fresh Manager instance.
	m2 := NewManager(path)
	if err := m2.Load(); err != nil {
		t.Fatalf("Load persisted file: %v", err)
	}
	list := m2.List()
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2: %+v", len(list), list)
	}
	if list[0].Interface != "eno1" || list[0].WarnPercent != 90 {
		t.Fatalf("unexpected eno1 entry: %+v", list[0])
	}
	if list[1].Interface != "usb0" || list[1].WarnPercent != DefaultWarnPercent || !list[1].Metered {
		t.Fatalf("unexpected usb0 entry: %+v", list[1])
	}

	got, ok := m2.Get("usb0")
	if !ok || got.DailyLimitBytes != 1000 {
		t.Fatalf("Get(usb0) = %+v, %v", got, ok)
	}
	if _, ok := m2.Get("missing0"); ok {
		t.Fatal("expected Get(missing0) == false")
	}

	if err := m2.RemoveQuota("eno1"); err != nil {
		t.Fatalf("RemoveQuota: %v", err)
	}
	if err := m2.RemoveQuota("eno1"); err == nil {
		t.Fatal("expected error removing missing quota")
	}

	m3 := NewManager(path)
	if err := m3.Load(); err != nil {
		t.Fatalf("Load after remove: %v", err)
	}
	if len(m3.List()) != 1 {
		t.Fatalf("expected 1 quota after remove, got %+v", m3.List())
	}

	// Temp file must not linger after atomic rename.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("unexpected leftover temp file: %v", err)
	}
}

func TestUpdateUsageDeltaWarnAndExceedTriggers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.Local)

	m := NewManager(path)
	m.SetNowFunc(func() time.Time { return now })
	if err := m.SetQuota(types.QuotaConfig{
		Interface:       "usb0",
		Metered:         true,
		DailyLimitBytes: 1000,
	}); err != nil {
		t.Fatal(err)
	}

	// Unconfigured interface returns zero status.
	if st := m.UpdateUsage("wlan0", 500, 500); st.Exceeded || st.Percent != 0 {
		t.Fatalf("unconfigured interface status = %+v", st)
	}

	// 1. Initial sample sets baseline without adding lifetime kernel counters.
	st := m.UpdateUsage("usb0", 5000, 5000)
	if st.Config.UsedBytes != 0 || st.Percent != 0 || st.JustWarned || st.JustExceeded || st.Exceeded {
		t.Fatalf("baseline status = %+v", st)
	}

	// 2. +799 bytes -> 79.9%, below 80% warn threshold.
	st = m.UpdateUsage("usb0", 5500, 5299)
	if st.Config.UsedBytes != 799 || st.JustWarned || st.JustExceeded || st.Exceeded {
		t.Fatalf("79.9%% status = %+v", st)
	}

	// 3. +1 byte -> exact 80.0%, JustWarned edge trigger fires once.
	st = m.UpdateUsage("usb0", 5501, 5299)
	if st.Config.UsedBytes != 800 || st.Percent != 80.0 || !st.JustWarned || st.JustExceeded || st.Exceeded {
		t.Fatalf("80.0%% status = %+v", st)
	}

	// 4. +100 bytes -> 90.0%, JustWarned must NOT fire again.
	st = m.UpdateUsage("usb0", 5551, 5349)
	if st.Config.UsedBytes != 900 || st.Percent != 90.0 || st.JustWarned || st.JustExceeded || st.Exceeded {
		t.Fatalf("90.0%% status = %+v", st)
	}

	// 5. +100 bytes -> 100.0%, JustExceeded fires once and Exceeded becomes true.
	st = m.UpdateUsage("usb0", 5601, 5399)
	if st.Config.UsedBytes != 1000 || st.Percent != 100.0 || st.JustWarned || !st.JustExceeded || !st.Exceeded {
		t.Fatalf("100.0%% status = %+v", st)
	}

	// 6. +250 bytes -> 125.0%, JustExceeded must NOT fire again, Exceeded stays true.
	st = m.UpdateUsage("usb0", 5751, 5499)
	if st.Config.UsedBytes != 1250 || st.Percent != 125.0 || st.JustWarned || st.JustExceeded || !st.Exceeded {
		t.Fatalf("125.0%% status = %+v", st)
	}

	// Verify persistence preserves usage & baseline across reload.
	m2 := NewManager(path)
	m2.SetNowFunc(func() time.Time { return now })
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	st = m2.UpdateUsage("usb0", 5801, 5499) // +50 bytes
	if st.Config.UsedBytes != 1300 || st.JustWarned || st.JustExceeded || !st.Exceeded {
		t.Fatalf("post-reload status = %+v", st)
	}
}

func TestUpdateUsageCounterResetAndSingleJump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.Local)

	m := NewManager(path)
	m.SetNowFunc(func() time.Time { return now })
	if err := m.SetQuota(types.QuotaConfig{
		Interface:       "wwan0",
		Metered:         true,
		DailyLimitBytes: 1000,
		WarnPercent:     75,
	}); err != nil {
		t.Fatal(err)
	}

	// Baseline at 1000 total bytes, then +400 -> UsedBytes = 400.
	m.UpdateUsage("wwan0", 600, 400)
	st := m.UpdateUsage("wwan0", 800, 600)
	if st.Config.UsedBytes != 400 || st.JustWarned || st.JustExceeded {
		t.Fatalf("pre-reset status = %+v", st)
	}

	// Simulate kernel/USB tether counter reset (e.g. replug/reboot): total drops from 1400 to 700!
	// Delta must be 700, bringing UsedBytes = 400 + 700 = 1100 (jumping past both 75% warn and 100% exceed).
	st = m.UpdateUsage("wwan0", 500, 200)
	if st.Config.UsedBytes != 1100 {
		t.Fatalf("UsedBytes after counter reset = %d, want 1100", st.Config.UsedBytes)
	}
	if !st.JustWarned || !st.JustExceeded || !st.Exceeded {
		t.Fatalf("expected JustWarned, JustExceeded, Exceeded after jump: %+v", st)
	}

	// Next monotonic increment adds +50 cleanly from the new baseline 700.
	st = m.UpdateUsage("wwan0", 525, 225)
	if st.Config.UsedBytes != 1150 || st.JustWarned || st.JustExceeded || !st.Exceeded {
		t.Fatalf("post-reset follow-up status = %+v", st)
	}
}

func TestMidnightDateRollover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	now := time.Date(2026, 11, 18, 23, 55, 0, 0, time.Local)

	m := NewManager(path)
	m.SetNowFunc(func() time.Time { return now })
	if err := m.SetQuota(types.QuotaConfig{
		Interface:       "usb0",
		Metered:         true,
		DailyLimitBytes: 1000,
	}); err != nil {
		t.Fatal(err)
	}

	m.UpdateUsage("usb0", 100, 100) // baseline 200
	st := m.UpdateUsage("usb0", 600, 600) // +1000 -> 100% exceeded
	if !st.Exceeded || st.Config.UsedBytes != 1000 {
		t.Fatalf("day 1 status = %+v", st)
	}

	// Cross midnight to 2026-11-19.
	now = time.Date(2026, 11, 19, 0, 1, 0, 0, time.Local)

	// Get/List should reflect the reset immediately.
	cfg, ok := m.Get("usb0")
	if !ok || cfg.UsedBytes != 0 {
		t.Fatalf("expected UsedBytes=0 after midnight in Get(), got %+v", cfg)
	}

	// New day traffic (+800 from yesterday's counter 1200 -> 2000) re-triggers 80% warn.
	st = m.UpdateUsage("usb0", 1000, 1000)
	if st.Config.UsedBytes != 800 || st.Percent != 80.0 || !st.JustWarned || st.Exceeded {
		t.Fatalf("day 2 80%% status = %+v", st)
	}

	// Reloading persisted file on yet another day (2026-11-20) also resets daily usage.
	now = time.Date(2026, 11, 20, 8, 0, 0, 0, time.Local)
	m2 := NewManager(path)
	m2.SetNowFunc(func() time.Time { return now })
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	cfg, ok = m2.Get("usb0")
	if !ok || cfg.UsedBytes != 0 {
		t.Fatalf("expected UsedBytes=0 on Load() after date rollover, got %+v", cfg)
	}
}

func TestManagerConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	m := NewManager(path)
	if err := m.SetQuota(types.QuotaConfig{
		Interface:       "usb0",
		Metered:         true,
		DailyLimitBytes: 100000,
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				m.UpdateUsage("usb0", uint64(id*100+j*10), uint64(j*5))
				_ = m.List()
				_, _ = m.Get("usb0")
			}
		}(i)
	}
	wg.Wait()
}
