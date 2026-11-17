// internal/quota/manager.go
package quota

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"netweaver/internal/types"
)

const (
	// DefaultPath is the default on-disk persistence path for daily quotas.
	DefaultPath = "/etc/netweaver/quotas.json"
	// DefaultWarnPercent is the default usage percentage that triggers a warning.
	DefaultWarnPercent = 80
)

// QuotaStatus reports current daily usage and threshold edge transitions for an interface.
type QuotaStatus struct {
	Config       types.QuotaConfig `json:"config"`
	Percent      float64           `json:"percent"`
	JustWarned   bool              `json:"just_warned"`
	JustExceeded bool              `json:"just_exceeded"`
	Exceeded     bool              `json:"exceeded"`
}

type quotaEntry struct {
	types.QuotaConfig
	LastTotalBytes uint64 `json:"last_total_bytes,omitempty"`
	HasSample      bool   `json:"has_sample,omitempty"`
	Warned         bool   `json:"warned,omitempty"`
	Exceeded       bool   `json:"exceeded,omitempty"`
}

type fileFormat struct {
	Date   string       `json:"date"`
	Quotas []quotaEntry `json:"quotas"`
}

// Manager tracks and persists daily metered interface quotas.
type Manager struct {
	mu      sync.RWMutex
	path    string
	date    string
	entries map[string]*quotaEntry
	nowFn   func() time.Time
}

// NewManager creates a quota Manager persisted at path (defaulting to DefaultPath if empty).
func NewManager(path string) *Manager {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	now := time.Now
	return &Manager{
		path:    path,
		date:    formatDate(now()),
		entries: make(map[string]*quotaEntry),
		nowFn:   now,
	}
}

// SetNowFunc overrides the clock function used for daily midnight rollover checks.
func (m *Manager) SetNowFunc(fn func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fn == nil {
		m.nowFn = time.Now
	} else {
		m.nowFn = fn
	}
	if len(m.entries) == 0 {
		m.date = formatDate(m.now())
	}
}

// Load reads persisted quotas from disk; a missing file initializes an empty set.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	today := formatDate(m.now())
	data, err := os.ReadFile(m.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			m.entries = make(map[string]*quotaEntry)
			m.date = today
			return nil
		}
		return fmt.Errorf("reading quotas: %w", err)
	}

	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing quotas: %w", err)
	}

	loaded := make(map[string]*quotaEntry, len(f.Quotas))
	for _, raw := range f.Quotas {
		iface := strings.TrimSpace(raw.Interface)
		if !types.ValidInterfaceName(iface) {
			continue
		}
		entry := raw
		entry.Interface = iface
		if entry.WarnPercent <= 0 || entry.WarnPercent > 100 {
			entry.WarnPercent = DefaultWarnPercent
		}
		if f.Date != "" && f.Date != today {
			entry.UsedBytes = 0
			entry.Warned = false
			entry.Exceeded = false
		} else {
			if reachedWarnPercent(entry.UsedBytes, entry.DailyLimitBytes, entry.WarnPercent) {
				entry.Warned = true
			}
			if entry.DailyLimitBytes > 0 && entry.UsedBytes >= entry.DailyLimitBytes {
				entry.Exceeded = true
			}
		}
		cp := entry
		loaded[iface] = &cp
	}

	m.entries = loaded
	m.date = today
	if f.Date != "" && f.Date != today && len(m.entries) > 0 {
		_ = m.saveLocked()
	}
	return nil
}

// SetQuota creates or updates a daily quota configuration for an interface.
func (m *Manager) SetQuota(cfg types.QuotaConfig) error {
	cfg.Interface = strings.TrimSpace(cfg.Interface)
	if !types.ValidInterfaceName(cfg.Interface) {
		return fmt.Errorf("invalid interface name: %q", cfg.Interface)
	}
	if cfg.WarnPercent < 0 || cfg.WarnPercent > 100 {
		return fmt.Errorf("warn_percent must be between 1 and 100 (got %d)", cfg.WarnPercent)
	}
	if cfg.WarnPercent == 0 {
		cfg.WarnPercent = DefaultWarnPercent
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.rolloverLocked(formatDate(m.now()))

	var entry quotaEntry
	if existing, ok := m.entries[cfg.Interface]; ok {
		entry = *existing
		if cfg.UsedBytes == 0 {
			cfg.UsedBytes = existing.UsedBytes
		}
	}
	entry.QuotaConfig = cfg
	entry.Warned = reachedWarnPercent(cfg.UsedBytes, cfg.DailyLimitBytes, cfg.WarnPercent)
	entry.Exceeded = cfg.DailyLimitBytes > 0 && cfg.UsedBytes >= cfg.DailyLimitBytes

	m.entries[cfg.Interface] = &entry
	return m.saveLocked()
}

// RemoveQuota deletes the configured quota for iface.
func (m *Manager) RemoveQuota(iface string) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return errors.New("interface name is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.entries[iface]; !ok {
		return fmt.Errorf("no quota configured for %q", iface)
	}
	delete(m.entries, iface)
	return m.saveLocked()
}

// List returns all configured quotas sorted by interface name.
func (m *Manager) List() []types.QuotaConfig {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.rolloverLocked(formatDate(m.now())) {
		_ = m.saveLocked()
	}

	if len(m.entries) == 0 {
		return nil
	}
	out := make([]types.QuotaConfig, 0, len(m.entries))
	for _, entry := range m.entries {
		out = append(out, entry.QuotaConfig)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

// Get returns the configured quota for iface and whether it exists.
func (m *Manager) Get(iface string) (types.QuotaConfig, bool) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return types.QuotaConfig{}, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.rolloverLocked(formatDate(m.now())) {
		_ = m.saveLocked()
	}

	entry, ok := m.entries[iface]
	if !ok {
		return types.QuotaConfig{}, false
	}
	return entry.QuotaConfig, true
}

// UpdateUsage updates daily byte accounting for iface from monotonic cumulative
// rx/tx interface counters, detecting counter resets/reboots and midnight date
// rollovers cleanly.
func (m *Manager) UpdateUsage(iface string, totalRx, totalTx uint64) QuotaStatus {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return QuotaStatus{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	dirty := m.rolloverLocked(formatDate(m.now()))

	entry, ok := m.entries[iface]
	if !ok {
		if dirty {
			_ = m.saveLocked()
		}
		return QuotaStatus{}
	}

	curTotal := safeAdd(totalRx, totalTx)
	var delta uint64
	switch {
	case !entry.HasSample:
		entry.LastTotalBytes = curTotal
		entry.HasSample = true
		dirty = true
	case curTotal >= entry.LastTotalBytes:
		delta = curTotal - entry.LastTotalBytes
		entry.LastTotalBytes = curTotal
		if delta > 0 {
			dirty = true
		}
	default:
		// Counter wrapped or reset (reboot, USB replug, driver reload).
		delta = curTotal
		entry.LastTotalBytes = curTotal
		dirty = true
	}

	entry.UsedBytes = safeAdd(entry.UsedBytes, delta)

	warnPct := entry.WarnPercent
	if warnPct <= 0 || warnPct > 100 {
		warnPct = DefaultWarnPercent
	}

	pct := computePercent(entry.UsedBytes, entry.DailyLimitBytes)
	isWarned := reachedWarnPercent(entry.UsedBytes, entry.DailyLimitBytes, warnPct)
	isExceeded := entry.DailyLimitBytes > 0 && entry.UsedBytes >= entry.DailyLimitBytes

	justWarned := isWarned && !entry.Warned
	justExceeded := isExceeded && !entry.Exceeded
	if justWarned {
		entry.Warned = true
		dirty = true
	}
	if justExceeded {
		entry.Exceeded = true
		dirty = true
	}

	if dirty {
		_ = m.saveLocked()
	}

	return QuotaStatus{
		Config:       entry.QuotaConfig,
		Percent:      pct,
		JustWarned:   justWarned,
		JustExceeded: justExceeded,
		Exceeded:     isExceeded,
	}
}

func (m *Manager) now() time.Time {
	if m.nowFn != nil {
		return m.nowFn()
	}
	return time.Now()
}

func formatDate(t time.Time) string {
	return t.Format("2006-01-02")
}

func (m *Manager) rolloverLocked(today string) bool {
	if m.date == "" {
		m.date = today
		return false
	}
	if m.date == today {
		return false
	}
	m.date = today
	changed := false
	for _, entry := range m.entries {
		if entry.UsedBytes != 0 || entry.Warned || entry.Exceeded {
			changed = true
		}
		entry.UsedBytes = 0
		entry.Warned = false
		entry.Exceeded = false
	}
	return changed
}

func (m *Manager) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := fileFormat{
		Date:   m.date,
		Quotas: make([]quotaEntry, 0, len(keys)),
	}
	for _, k := range keys {
		out.Quotas = append(out.Quotas, *m.entries[k])
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func safeAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

func computePercent(used, limit uint64) float64 {
	if limit == 0 {
		return 0
	}
	return (float64(used) / float64(limit)) * 100.0
}

func reachedWarnPercent(used, limit uint64, warnPct int) bool {
	if limit == 0 || warnPct <= 0 {
		return false
	}
	hi1, lo1 := bits.Mul64(used, 100)
	hi2, lo2 := bits.Mul64(limit, uint64(warnPct))
	return hi1 > hi2 || (hi1 == hi2 && lo1 >= lo2)
}
