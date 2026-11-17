// internal/failover/failover.go
package failover

import (
	"math"
	"sort"
	"strings"

	"netweaver/internal/interfaces"
	"netweaver/internal/types"
)

// Mover is the cgroup/policy surface the failover engine needs.
type Mover interface {
	PIDs(iface string) ([]int, error)
	Assign(iface string, pid int) error
	Block(pid int, from string) error
	Policy(pid int) string
}

// Action records what happened to one process when its interface vanished.
type Action struct {
	PID     int
	From    string
	To      string // empty when the process was left in place
	Blocked bool
	Policy  string
}

// HandleLoss reacts to interfaces that disappeared.
//
// Strict processes are quarantined in the blocked cgroup (traffic dropped by
// nftables); failover processes move to the best surviving interface. When no
// interface survives, failover processes stay put and simply have no route.
func HandleLoss(lost []string, remaining []string, m Mover) []Action {
	target := BestInterface(remaining)
	var actions []Action

	for _, iface := range lost {
		pids, err := m.PIDs(iface)
		if err != nil {
			continue
		}
		for _, pid := range pids {
			pol := m.Policy(pid)
			action := Action{PID: pid, From: iface, Policy: pol}
			if pol == types.PolicyStrict {
				if err := m.Block(pid, iface); err == nil {
					action.Blocked = true
					actions = append(actions, action)
				}
				continue
			}
			if target == "" {
				actions = append(actions, action)
				continue
			}
			if err := m.Assign(target, pid); err == nil {
				action.To = target
				actions = append(actions, action)
			}
		}
	}
	return actions
}

// BestInterface picks the highest-priority surviving interface.
func BestInterface(remaining []string) string {
	candidates := make([]string, 0, len(remaining))
	for _, name := range remaining {
		if name == "" || name == "lo" {
			continue
		}
		candidates = append(candidates, name)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		pi, pj := interfaces.Priority(candidates[i]), interfaces.Priority(candidates[j])
		if pi != pj {
			return pi < pj
		}
		return candidates[i] < candidates[j]
	})
	return candidates[0]
}

// UnhealthyInterfaces returns the names of interfaces that have carrier/link UP
// but failed active upstream health probing (Up && !Healthy).
func UnhealthyInterfaces(ifaces []types.InterfaceInfo) []string {
	var unhealthy []string
	for _, iface := range ifaces {
		if iface.Name == "" || iface.Name == "lo" {
			continue
		}
		if iface.Up && !iface.Healthy {
			unhealthy = append(unhealthy, iface.Name)
		}
	}
	return unhealthy
}

// ResolveSmartProfile selects the best active, healthy interface name matching a
// virtual routing profile (@low-latency, @high-bandwidth, @bulk, @unmetered).
// Returns "" if no suitable interface exists or if profile is unknown.
func ResolveSmartProfile(profile string, ifaces []types.InterfaceInfo) string {
	prof := strings.TrimSpace(strings.ToLower(profile))

	healthy := make([]types.InterfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Name == "" || iface.Name == "lo" {
			continue
		}
		if iface.Up && iface.Healthy {
			healthy = append(healthy, iface)
		}
	}
	if len(healthy) == 0 {
		return ""
	}

	switch prof {
	case types.ProfileLowLatency:
		sort.SliceStable(healthy, func(i, j int) bool {
			a, b := healthy[i], healthy[j]
			if a.QuotaExceeded != b.QuotaExceeded {
				return !a.QuotaExceeded
			}
			if a.IsTunnel != b.IsTunnel {
				return !a.IsTunnel
			}
			sa, sb := effectiveHealthScore(a), effectiveHealthScore(b)
			if math.Abs(sa-sb) > 1e-6 {
				return sa > sb
			}
			la, lb := a.LatencyMs+a.JitterMs, b.LatencyMs+b.JitterMs
			if math.Abs(la-lb) > 1e-6 {
				return la < lb
			}
			if math.Abs(a.PacketLoss-b.PacketLoss) > 1e-6 {
				return a.PacketLoss < b.PacketLoss
			}
			pa, pb := interfaces.Priority(a.Name), interfaces.Priority(b.Name)
			if pa != pb {
				return pa < pb
			}
			return a.Name < b.Name
		})
		return healthy[0].Name

	case types.ProfileHighBandwidth, types.ProfileBulk:
		sort.SliceStable(healthy, func(i, j int) bool {
			a, b := healthy[i], healthy[j]
			ra, rb := highBandwidthTier(a), highBandwidthTier(b)
			if ra != rb {
				return ra < rb
			}
			pa, pb := interfaces.Priority(a.Name), interfaces.Priority(b.Name)
			if pa != pb {
				return pa < pb
			}
			sa, sb := effectiveHealthScore(a), effectiveHealthScore(b)
			if math.Abs(sa-sb) > 1e-6 {
				return sa > sb
			}
			la, lb := a.LatencyMs+a.JitterMs, b.LatencyMs+b.JitterMs
			if math.Abs(la-lb) > 1e-6 {
				return la < lb
			}
			return a.Name < b.Name
		})
		return healthy[0].Name

	case types.ProfileUnmetered:
		unmetered := make([]types.InterfaceInfo, 0, len(healthy))
		for _, iface := range healthy {
			if !iface.Metered && !iface.QuotaExceeded {
				unmetered = append(unmetered, iface)
			}
		}
		if len(unmetered) == 0 {
			return ""
		}
		sort.SliceStable(unmetered, func(i, j int) bool {
			a, b := unmetered[i], unmetered[j]
			pa, pb := interfaces.Priority(a.Name), interfaces.Priority(b.Name)
			if pa != pb {
				return pa < pb
			}
			sa, sb := effectiveHealthScore(a), effectiveHealthScore(b)
			if math.Abs(sa-sb) > 1e-6 {
				return sa > sb
			}
			la, lb := a.LatencyMs+a.JitterMs, b.LatencyMs+b.JitterMs
			if math.Abs(la-lb) > 1e-6 {
				return la < lb
			}
			return a.Name < b.Name
		})
		return unmetered[0].Name

	default:
		return ""
	}
}

func highBandwidthTier(iface types.InterfaceInfo) int {
	switch {
	case !iface.Metered && !iface.QuotaExceeded:
		return 0
	case !iface.QuotaExceeded:
		return 1
	case !iface.Metered:
		return 2
	default:
		return 3
	}
}

func effectiveHealthScore(iface types.InterfaceInfo) float64 {
	if iface.HealthScore > 0 {
		return iface.HealthScore
	}
	return interfaces.ComputeHealthScore(iface.LatencyMs, iface.JitterMs, iface.PacketLoss, iface.Healthy)
}
