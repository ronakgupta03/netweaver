// internal/failover/failover.go
package failover

import (
	"sort"

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
