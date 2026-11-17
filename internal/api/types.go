// internal/api/types.go
package api

import "netweaver/internal/types"

type Backend interface {
	ListInterfaces() ([]types.InterfaceInfo, error)
	ListProcesses() ([]types.ProcessInfo, error)
	AssignRoute(pid int, iface string) error
	ResetRoute(pid int) error
	ListRules() []types.Rule
	AddRule(rule types.Rule) error
	RemoveRule(match string) error
	GetPolicy() string
	SetPolicy(policy string) error
}

// ExtendedBackend is optionally implemented by backends supporting per-process
// policies, blocking, rate limits, interface switching, quotas, DNS, and events.
type ExtendedBackend interface {
	AssignRouteWithOpts(pid int, iface string, policy string, rateLimitBps uint64) error
	SetProcessPolicy(pid int, policy string) error
	BlockProcess(pid int, blocked bool) error
	SetProcessRateLimit(pid int, bps uint64) error
	SwitchInterface(fromIface, toIface string) (int, error)
	ListQuotas() []types.QuotaConfig
	SetQuota(cfg types.QuotaConfig) error
	RemoveQuota(iface string) error
	SetInterfaceDNS(iface string, servers []string) error
	ListEvents(since uint64) []types.Event
}

type Request struct {
	Method        string             `json:"method"`
	PID           int                `json:"pid,omitempty"`
	Interface     string             `json:"interface,omitempty"`
	Match         string             `json:"match,omitempty"`
	Policy        string             `json:"policy,omitempty"`
	Rule          *types.Rule        `json:"rule,omitempty"`
	RateLimitBps  uint64             `json:"rate_limit_bps,omitempty"`
	Blocked       bool               `json:"blocked,omitempty"`
	FromInterface string             `json:"from_interface,omitempty"`
	ToInterface   string             `json:"to_interface,omitempty"`
	Quota         *types.QuotaConfig `json:"quota,omitempty"`
	DNSServers    []string           `json:"dns_servers,omitempty"`
	Since         uint64             `json:"since,omitempty"`
}

type Response struct {
	Success    bool                  `json:"success"`
	Error      string                `json:"error,omitempty"`
	Interfaces []types.InterfaceInfo `json:"interfaces,omitempty"`
	Processes  []types.ProcessInfo   `json:"processes,omitempty"`
	Rules      []types.Rule          `json:"rules,omitempty"`
	Policy     string                `json:"policy,omitempty"`
	Quotas     []types.QuotaConfig   `json:"quotas,omitempty"`
	Events     []types.Event         `json:"events,omitempty"`
	MovedCount int                   `json:"moved_count,omitempty"`
}
