// internal/types/models.go
package types

import (
	"errors"
	"fmt"
	"regexp"
)

var validIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,16}$`)

type InterfaceInfo struct {
	Name            string   `json:"name"`
	Index           int      `json:"index"`
	IP              string   `json:"ip"`
	Gateway         string   `json:"gateway"`
	Gateway6        string   `json:"gateway6,omitempty"`
	TableID         int      `json:"table_id"`
	Up              bool     `json:"up"`
	RxBytes         uint64   `json:"rx_bytes"`
	TxBytes         uint64   `json:"tx_bytes"`
	RxRate          float64  `json:"rx_rate"`
	TxRate          float64  `json:"tx_rate"`
	IsTunnel        bool     `json:"is_tunnel,omitempty"`
	LatencyMs       float64  `json:"latency_ms,omitempty"`
	JitterMs        float64  `json:"jitter_ms,omitempty"`
	PacketLoss      float64  `json:"packet_loss,omitempty"`
	Healthy         bool     `json:"healthy"`
	HealthScore     float64  `json:"health_score,omitempty"`
	Metered         bool     `json:"metered,omitempty"`
	DailyQuotaBytes uint64   `json:"daily_quota_bytes,omitempty"`
	DailyUsedBytes  uint64   `json:"daily_used_bytes,omitempty"`
	QuotaExceeded   bool     `json:"quota_exceeded,omitempty"`
	DNSServers      []string `json:"dns_servers,omitempty"`
}

// ValidInterfaceName reports whether name is a valid Linux interface name.
func ValidInterfaceName(name string) bool {
	return validIfaceRegex.MatchString(name)
}

func (i InterfaceInfo) Validate() error {
	if !ValidInterfaceName(i.Name) {
		return fmt.Errorf("invalid interface name: %q", i.Name)
	}
	if i.TableID <= 0 {
		return errors.New("table ID must be positive")
	}
	return nil
}

type ProcessInfo struct {
	PID               int     `json:"pid"`
	Name              string  `json:"name"`
	Cmdline           string  `json:"cmdline"`
	UID               uint32  `json:"uid"`
	AssignedInterface string  `json:"assigned_interface"`
	Policy            string  `json:"policy,omitempty"`
	RxBytes           uint64  `json:"rx_bytes"`
	TxBytes           uint64  `json:"tx_bytes"`
	RxRate            float64 `json:"rx_rate"`
	TxRate            float64 `json:"tx_rate"`
	Blocked           bool    `json:"blocked,omitempty"`
	RateLimitBps      uint64  `json:"rate_limit_bps,omitempty"`
	Profile           string  `json:"profile,omitempty"`
}

type RouteRule struct {
	PID       int    `json:"pid"`
	AppName   string `json:"app_name"`
	Interface string `json:"interface"`
}

type DaemonStatus struct {
	UptimeSeconds uint64 `json:"uptime_seconds"`
	ActiveIfaces  int    `json:"active_ifaces"`
	ManagedProcs  int    `json:"managed_procs"`
}

// Policy selects how assigned traffic behaves when its interface goes away.
const (
	PolicyFailover = "failover" // migrate to the best remaining interface
	PolicyStrict   = "strict"   // block traffic instead of leaking elsewhere
)

// Rule is a persisted auto-routing rule matched against process names.
type Rule struct {
	Match        string   `json:"match"`
	Interface    string   `json:"interface"`
	Policy       string   `json:"policy,omitempty"`
	Domains      []string `json:"domains,omitempty"`
	RateLimitBps uint64   `json:"rate_limit_bps,omitempty"`
	Background   bool     `json:"background,omitempty"`
}

// Virtual profile targets resolved dynamically against interface telemetry.
const (
	ProfileLowLatency    = "@low-latency"
	ProfileHighBandwidth = "@high-bandwidth"
	ProfileUnmetered     = "@unmetered"
	ProfileBulk          = "@bulk"
)

// IsVirtualProfile reports whether target names a supported virtual routing profile.
func IsVirtualProfile(target string) bool {
	switch target {
	case ProfileLowLatency, ProfileHighBandwidth, ProfileUnmetered, ProfileBulk:
		return true
	default:
		return false
	}
}

// QuotaConfig defines metered and daily byte quota settings for an interface.
type QuotaConfig struct {
	Interface       string `json:"interface"`
	Metered         bool   `json:"metered"`
	DailyLimitBytes uint64 `json:"daily_limit_bytes"`
	UsedBytes       uint64 `json:"used_bytes"`
	WarnPercent     int    `json:"warn_percent,omitempty"`
}

// Event records a daemon routing, failover, quota, or policy event.
type Event struct {
	ID            uint64 `json:"id"`
	Timestamp     int64  `json:"timestamp"`
	Type          string `json:"type"`
	PID           int    `json:"pid,omitempty"`
	App           string `json:"app,omitempty"`
	Interface     string `json:"interface,omitempty"`
	FromInterface string `json:"from_interface,omitempty"`
	Policy        string `json:"policy,omitempty"`
	Message       string `json:"message"`
}

func (r Rule) NormalizedPolicy() string {
	if r.Policy == PolicyStrict {
		return PolicyStrict
	}
	return PolicyFailover
}

func ValidPolicy(p string) bool {
	return p == PolicyFailover || p == PolicyStrict || p == ""
}
