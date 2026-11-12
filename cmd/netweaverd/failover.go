// cmd/netweaverd/failover.go
package main

import (
	"fmt"
	"log"
	"os"

	"netweaver/internal/failover"
	"netweaver/internal/types"
)

// handleInterfaceChanges applies routing for new/changed interfaces and reacts
// to interfaces that disappeared (cable unplugged, tethering stopped).
func (d *DaemonService) handleInterfaceChanges(prev, cur []types.InterfaceInfo) {
	present := make(map[string]bool, len(cur))
	prevByName := make(map[string]types.InterfaceInfo, len(prev))
	for _, iface := range prev {
		prevByName[iface.Name] = iface
	}

	for _, iface := range cur {
		present[iface.Name] = true
		old, known := prevByName[iface.Name]
		if known && old.Gateway == iface.Gateway && old.Gateway6 == iface.Gateway6 && old.IP == iface.IP && old.TableID == iface.TableID {
			continue
		}
		_ = d.cgMgr.EnsureInterfaceCgroup(iface.Name)
		if err := d.engine.SetupInterfaceRoute(iface); err != nil {
			log.Printf("[netweaverd] route setup failed for %s: %v", iface.Name, err)
		}
	}

	var lost []string
	for _, iface := range prev {
		if !present[iface.Name] {
			lost = append(lost, iface.Name)
		}
	}

	if len(lost) > 0 {
		remaining := make([]string, 0, len(cur))
		for _, iface := range cur {
			remaining = append(remaining, iface.Name)
		}
		log.Printf("[netweaverd] interface(s) lost: %v; surviving: %v", lost, remaining)
		for _, action := range failover.HandleLoss(lost, remaining, daemonMover{d: d}) {
			switch {
			case action.Blocked:
				log.Printf("[netweaverd] kill-switch: pid %d quarantined (was %s, policy strict)", action.PID, action.From)
			case action.To != "":
				log.Printf("[netweaverd] failover: pid %d moved %s -> %s", action.PID, action.From, action.To)
			default:
				log.Printf("[netweaverd] failover: pid %d left without a route (no surviving interface)", action.PID)
			}
		}
		for _, name := range lost {
			_ = d.engine.RemoveInterface(name)
		}
	}

	d.restoreBlocked(present)

	if d.classifier != nil {
		if err := d.classifier.Apply(cur); err != nil {
			d.disableClassifier("attach failed: " + err.Error())
		}
	}
}

// disableClassifier falls back to nftables packet marking and keeps routing
// functional when eBPF attachment stops working.
func (d *DaemonService) disableClassifier(reason string) {
	if d.classifier == nil {
		return
	}
	_ = d.classifier.Close()
	d.classifier = nil
	d.engine.SetMarking(true)
	if err := d.engine.ApplyNftables(); err != nil {
		log.Printf("[netweaverd] nftables fallback failed: %v", err)
		return
	}
	log.Printf("[netweaverd] eBPF classifier disabled (%s); nftables marking restored", reason)
}

// restoreBlocked returns quarantined processes to their interface once it is
// usable again, and forgets processes that exited.
func (d *DaemonService) restoreBlocked(present map[string]bool) {
	d.blockedMu.Lock()
	defer d.blockedMu.Unlock()

	for pid, iface := range d.blocked {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			delete(d.blocked, pid)
			continue
		}
		if !present[iface] {
			continue
		}
		if err := d.cgMgr.AssignPID(iface, pid); err != nil {
			continue
		}
		log.Printf("[netweaverd] kill-switch released: pid %d restored to %s", pid, iface)
		delete(d.blocked, pid)
	}
}

// daemonMover adapts DaemonService to failover.Mover.
type daemonMover struct{ d *DaemonService }

func (m daemonMover) PIDs(iface string) ([]int, error) {
	return m.d.cgMgr.PIDs(iface)
}

func (m daemonMover) Assign(iface string, pid int) error {
	return m.d.cgMgr.AssignPID(iface, pid)
}

func (m daemonMover) Block(pid int, from string) error {
	if err := m.d.cgMgr.Block(pid); err != nil {
		return err
	}
	m.d.blockedMu.Lock()
	m.d.blocked[pid] = from
	m.d.blockedMu.Unlock()
	return nil
}

func (m daemonMover) Policy(pid int) string {
	return m.d.policy.Resolve(pid)
}
