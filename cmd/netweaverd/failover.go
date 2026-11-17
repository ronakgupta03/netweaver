// cmd/netweaverd/failover.go
package main

import (
	"fmt"
	"log"
	"os"

	"netweaver/internal/cgroups"
	"netweaver/internal/classifier"
	"netweaver/internal/failover"
	"netweaver/internal/types"
)

// handleInterfaceChanges applies routing for new/changed interfaces, reacts to
// lost or upstream-unhealthy interfaces, restores eligible quarantined processes,
// re-evaluates virtual @profile assignments, and cleans up dead process state.
func (d *DaemonService) handleInterfaceChanges(prev, cur []types.InterfaceInfo) {
	cur = d.syncAndEnrichInterfaces(cur)

	present := make(map[string]bool, len(cur))
	healthy := make(map[string]bool, len(cur))
	quotaExceeded := make(map[string]bool, len(cur))
	prevByName := make(map[string]types.InterfaceInfo, len(prev))
	for _, iface := range prev {
		prevByName[iface.Name] = iface
	}

	for _, iface := range cur {
		present[iface.Name] = true
		healthy[iface.Name] = iface.Up && iface.Healthy
		quotaExceeded[iface.Name] = iface.QuotaExceeded
		if d.telemetry != nil {
			d.telemetry.TrackInterface(iface.Name)
		}

		old, known := prevByName[iface.Name]
		if known &&
			old.Gateway == iface.Gateway &&
			old.Gateway6 == iface.Gateway6 &&
			old.IP == iface.IP &&
			old.TableID == iface.TableID &&
			old.IsTunnel == iface.IsTunnel &&
			equalStringSlices(old.DNSServers, iface.DNSServers) {
			continue
		}
		_ = d.cgMgr.EnsureInterfaceCgroup(iface.Name)
		if d.engine != nil {
			if err := d.engine.SetupInterfaceRoute(iface); err != nil {
				log.Printf("[netweaverd] route setup failed for %s: %v", iface.Name, err)
			}
		}
	}

	var lost []string
	for _, iface := range prev {
		if !present[iface.Name] {
			lost = append(lost, iface.Name)
		}
	}

	// Clear evacuation flags for interfaces that disappeared or recovered health.
	d.stateMu.Lock()
	for _, name := range lost {
		delete(d.evacuated, name)
	}
	for _, iface := range cur {
		if iface.Up && iface.Healthy {
			delete(d.evacuated, iface.Name)
		}
	}

	unhealthyList := failover.UnhealthyInterfaces(cur)
	var newlyUnhealthy []string
	for _, name := range unhealthyList {
		if !d.evacuated[name] {
			d.evacuated[name] = true
			newlyUnhealthy = append(newlyUnhealthy, name)
		}
	}
	d.stateMu.Unlock()

	healthyRemaining := make([]string, 0, len(cur))
	for _, iface := range cur {
		if iface.Up && iface.Healthy {
			healthyRemaining = append(healthyRemaining, iface.Name)
		}
	}

	toEvacuate := make([]string, 0, len(lost)+len(newlyUnhealthy))
	toEvacuate = append(toEvacuate, lost...)
	toEvacuate = append(toEvacuate, newlyUnhealthy...)

	if len(toEvacuate) > 0 {
		log.Printf("[netweaverd] interface(s) degraded/lost (lost=%v unhealthy=%v); healthy surviving: %v",
			lost, newlyUnhealthy, healthyRemaining)
		mover := daemonMover{d: d, ifaces: cur}
		for _, action := range failover.HandleLoss(toEvacuate, healthyRemaining, mover) {
			app := procComm(action.PID)
			switch {
			case action.Blocked:
				msg := fmt.Sprintf("kill-switch: pid %d quarantined (was %s, policy strict)", action.PID, action.From)
				log.Printf("[netweaverd] %s", msg)
				d.publishEvent(types.Event{
					Type:          "killswitch",
					PID:           action.PID,
					App:           app,
					FromInterface: action.From,
					Policy:        action.Policy,
					Message:       msg,
				})
				d.notifyDesktop("NetWeaver Kill-Switch", msg)
			case action.To != "":
				msg := fmt.Sprintf("failover: pid %d moved %s -> %s", action.PID, action.From, action.To)
				log.Printf("[netweaverd] %s", msg)
				d.publishEvent(types.Event{
					Type:          "failover",
					PID:           action.PID,
					App:           app,
					FromInterface: action.From,
					Interface:     action.To,
					Policy:        action.Policy,
					Message:       msg,
				})
				d.notifyDesktop("NetWeaver Failover", msg)
			default:
				log.Printf("[netweaverd] failover: pid %d left without a route (no healthy surviving interface)", action.PID)
			}
		}
		for _, name := range lost {
			if d.engine != nil {
				_ = d.engine.RemoveInterface(name)
			}
		}
	}

	d.restoreBlocked(present, healthy, quotaExceeded, cur)
	d.reEvaluateProfiles(cur)
	_ = d.cgMgr.CleanupDeadProcessCgroups()
	d.pruneDeadPIDs()

	d.applyClassifier(cur)
}

func (d *DaemonService) reconcileQuotasAndProfiles(cur []types.InterfaceInfo) {
	present := make(map[string]bool, len(cur))
	healthy := make(map[string]bool, len(cur))
	quotaExceeded := make(map[string]bool, len(cur))
	for _, iface := range cur {
		present[iface.Name] = true
		healthy[iface.Name] = iface.Up && iface.Healthy
		quotaExceeded[iface.Name] = iface.QuotaExceeded
	}
	d.restoreBlocked(present, healthy, quotaExceeded, cur)
	d.reEvaluateProfiles(cur)
}

func (d *DaemonService) quarantineBackgroundProcesses(iface string) {
	if d.rules == nil || d.cgMgr == nil {
		return
	}
	pids, err := d.cgMgr.PIDs(iface)
	if err != nil || len(pids) == 0 {
		return
	}
	for _, pid := range pids {
		if pid <= 100 {
			continue
		}
		d.stateMu.Lock()
		_, alreadyManual := d.manualBlocked[pid]
		_, alreadyBlocked := d.blocked[pid]
		d.stateMu.Unlock()
		if alreadyManual || alreadyBlocked {
			continue
		}
		name := procComm(pid)
		cmdline := procCmdline(pid)
		rule, matched := d.rules.Match(name, cmdline)
		if !matched || !rule.Background {
			continue
		}
		tree, _ := d.getProcessTreeOrSelf(pid)
		_ = d.cgMgr.EnsureBlockedCgroup()
		for _, p := range tree {
			if p <= 100 {
				continue
			}
			_ = d.cgMgr.Block(p)
		}
		d.withClassifier(func(clf *classifier.Classifier) {
			_ = clf.SetTarget(cgroups.BlockedCgroup, 0, true)
		})
		d.cleanupStaleCgroups(tree, cgroups.BlockedCgroup)

		d.stateMu.Lock()
		d.blocked[pid] = iface
		d.quotaBlocked[pid] = true
		d.stateMu.Unlock()

		msg := fmt.Sprintf("auto-quarantined background process %s (pid %d) on %s: daily quota exceeded", name, pid, iface)
		log.Printf("[netweaverd] %s", msg)
		d.publishEvent(types.Event{
			Type:          "killswitch",
			PID:           pid,
			App:           name,
			FromInterface: iface,
			Policy:        d.policy.Resolve(pid),
			Message:       msg,
		})
		d.notifyDesktop("NetWeaver Quota Quarantine", msg)
	}
}

func (d *DaemonService) hasClassifier() bool {
	d.clfMu.RLock()
	defer d.clfMu.RUnlock()
	return d.classifier != nil
}

func (d *DaemonService) setClassifier(clf *classifier.Classifier) {
	d.clfMu.Lock()
	d.classifier = clf
	d.clfMu.Unlock()
}

func (d *DaemonService) withClassifier(fn func(*classifier.Classifier)) {
	d.clfMu.RLock()
	defer d.clfMu.RUnlock()
	if d.classifier != nil {
		fn(d.classifier)
	}
}

func (d *DaemonService) applyClassifier(ifaces []types.InterfaceInfo) {
	d.clfMu.Lock()
	if d.classifier == nil {
		d.clfMu.Unlock()
		return
	}
	err := d.classifier.Apply(ifaces)
	d.clfMu.Unlock()
	if err != nil {
		d.disableClassifier("attach failed: " + err.Error())
	}
}

func (d *DaemonService) closeClassifier() {
	d.clfMu.Lock()
	clf := d.classifier
	d.classifier = nil
	d.clfMu.Unlock()
	if clf != nil {
		_ = clf.Close()
	}
}

// disableClassifier falls back to nftables packet marking and keeps routing
// functional when eBPF attachment stops working.
func (d *DaemonService) disableClassifier(reason string) {
	d.clfMu.Lock()
	clf := d.classifier
	if clf == nil {
		d.clfMu.Unlock()
		return
	}
	d.classifier = nil
	d.clfMu.Unlock()

	_ = clf.Close()
	if d.telemetry != nil {
		d.telemetry.SetCgroupStatsReader(nil)
		d.telemetry.SetProcessStatsReader(nil)
	}
	if d.engine != nil {
		d.engine.SetMarking(true)
		if err := d.applyNftables(); err != nil {
			log.Printf("[netweaverd] nftables fallback failed: %v", err)
			return
		}
	}
	log.Printf("[netweaverd] eBPF classifier disabled (%s); nftables marking restored", reason)
}

// restoreBlocked returns failover/quota quarantined processes to their interface
// once it is present, healthy, and within quota. Manual blocks are never auto-released.
func (d *DaemonService) restoreBlocked(present, healthy, quotaExceeded map[string]bool, cur []types.InterfaceInfo) {
	type restoreItem struct {
		pid   int
		iface string
		rate  uint64
	}

	d.stateMu.Lock()
	var candidates []restoreItem
	for pid, iface := range d.blocked {
		if _, isManual := d.manualBlocked[pid]; isManual {
			continue
		}
		if !pidExists(pid) {
			delete(d.blocked, pid)
			delete(d.quotaBlocked, pid)
			continue
		}
		if iface == "" {
			continue // virtual-profile strict quarantine handled by reEvaluateProfiles
		}
		if !present[iface] || !healthy[iface] {
			continue
		}
		if d.quotaBlocked[pid] && quotaExceeded[iface] {
			continue
		}
		candidates = append(candidates, restoreItem{
			pid:   pid,
			iface: iface,
			rate:  d.rateLimits[pid],
		})
	}
	d.stateMu.Unlock()

	for _, item := range candidates {
		tableID := d.lookupTableID(item.iface, cur)
		if err := d.moveProcessToInterface(item.pid, item.iface, tableID, item.rate); err != nil {
			continue
		}
		d.stateMu.Lock()
		delete(d.blocked, item.pid)
		delete(d.quotaBlocked, item.pid)
		d.stateMu.Unlock()

		msg := fmt.Sprintf("kill-switch released: pid %d restored to %s", item.pid, item.iface)
		log.Printf("[netweaverd] %s", msg)
		d.publishEvent(types.Event{
			Type:      "restore",
			PID:       item.pid,
			App:       procComm(item.pid),
			Interface: item.iface,
			Policy:    d.policy.Resolve(item.pid),
			Message:   msg,
		})
		d.notifyDesktop("NetWeaver Link Restored", msg)
	}
}

// reEvaluateProfiles re-resolves active virtual @profile bindings whenever
// interfaces, health, or quotas change.
func (d *DaemonService) reEvaluateProfiles(cur []types.InterfaceInfo) {
	type profileEntry struct {
		pid     int
		profile string
		rate    uint64
	}

	d.stateMu.Lock()
	entries := make([]profileEntry, 0, len(d.profiles))
	for pid, prof := range d.profiles {
		if _, isManual := d.manualBlocked[pid]; isManual {
			continue
		}
		entries = append(entries, profileEntry{
			pid:     pid,
			profile: prof,
			rate:    d.rateLimits[pid],
		})
	}
	d.stateMu.Unlock()

	for _, entry := range entries {
		if !pidExists(entry.pid) {
			continue
		}
		curIface := d.currentAssignedInterface(entry.pid)
		target := failover.ResolveSmartProfile(entry.profile, cur)
		pol := d.policy.Resolve(entry.pid)

		if target == "" {
			if pol == types.PolicyStrict && curIface != cgroups.BlockedCgroup {
				pids, _ := d.getProcessTreeOrSelf(entry.pid)
				_ = d.cgMgr.EnsureBlockedCgroup()
				for _, p := range pids {
					if p <= 100 {
						continue
					}
					_ = d.cgMgr.Block(p)
				}
				d.withClassifier(func(clf *classifier.Classifier) {
					_ = clf.SetTarget(cgroups.BlockedCgroup, 0, true)
				})
				d.cleanupStaleCgroups(pids, cgroups.BlockedCgroup)

				d.stateMu.Lock()
				d.blocked[entry.pid] = ""
				d.stateMu.Unlock()

				msg := fmt.Sprintf("quarantined pid %d: no healthy interface matching %s (strict policy)", entry.pid, entry.profile)
				d.publishEvent(types.Event{
					Type:          "killswitch",
					PID:           entry.pid,
					App:           procComm(entry.pid),
					FromInterface: curIface,
					Policy:        pol,
					Message:       msg,
				})
				d.notifyDesktop("NetWeaver Kill-Switch", msg)
			}
			continue
		}

		if target == curIface {
			continue
		}

		tableID := d.lookupTableID(target, cur)
		if err := d.moveProcessToInterface(entry.pid, target, tableID, entry.rate); err != nil {
			continue
		}

		wasBlocked := curIface == cgroups.BlockedCgroup
		d.stateMu.Lock()
		if _, inBlocked := d.blocked[entry.pid]; inBlocked {
			wasBlocked = true
		}
		delete(d.blocked, entry.pid)
		delete(d.quotaBlocked, entry.pid)
		d.stateMu.Unlock()

		evType := "failover"
		msg := fmt.Sprintf("profile %s re-routed pid %d: %s -> %s", entry.profile, entry.pid, curIface, target)
		if wasBlocked || curIface == "" || curIface == "default" {
			evType = "restore"
			msg = fmt.Sprintf("profile %s assigned pid %d to %s", entry.profile, entry.pid, target)
		}
		d.publishEvent(types.Event{
			Type:          evType,
			PID:           entry.pid,
			App:           procComm(entry.pid),
			FromInterface: curIface,
			Interface:     target,
			Policy:        pol,
			Message:       msg,
		})
	}
}

func (d *DaemonService) pruneDeadPIDs() {
	d.stateMu.Lock()
	var dead []int
	seen := make(map[int]bool)
	collect := func(pid int) {
		if seen[pid] {
			return
		}
		seen[pid] = true
		if !pidExists(pid) {
			dead = append(dead, pid)
		}
	}
	for pid := range d.blocked {
		collect(pid)
	}
	for pid := range d.manualBlocked {
		collect(pid)
	}
	for pid := range d.profiles {
		collect(pid)
	}
	for pid := range d.rateLimits {
		collect(pid)
	}
	for _, pid := range dead {
		delete(d.blocked, pid)
		delete(d.quotaBlocked, pid)
		delete(d.manualBlocked, pid)
		delete(d.profiles, pid)
		delete(d.rateLimits, pid)
	}
	d.stateMu.Unlock()

	if d.policy != nil {
		for _, pid := range dead {
			d.policy.Forget(pid)
		}
	}
}

func pidExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// daemonMover adapts DaemonService to failover.Mover.
type daemonMover struct {
	d      *DaemonService
	ifaces []types.InterfaceInfo
}

func (m daemonMover) PIDs(iface string) ([]int, error) {
	return m.d.cgMgr.PIDs(iface)
}

func (m daemonMover) Assign(iface string, pid int) error {
	tableID := m.d.lookupTableID(iface, m.ifaces)
	rate := m.d.getRateLimit(pid)
	return m.d.moveProcessToInterface(pid, iface, tableID, rate)
}

func (m daemonMover) Block(pid int, from string) error {
	pids, err := m.d.getProcessTreeOrSelf(pid)
	if err != nil {
		return err
	}
	_ = m.d.cgMgr.EnsureBlockedCgroup()
	for _, p := range pids {
		if p <= 100 {
			continue
		}
		if err := m.d.cgMgr.Block(p); err != nil && p == pid {
			return err
		}
	}
	m.d.withClassifier(func(clf *classifier.Classifier) {
		_ = clf.SetTarget(cgroups.BlockedCgroup, 0, true)
	})
	m.d.cleanupStaleCgroups(pids, cgroups.BlockedCgroup)

	m.d.stateMu.Lock()
	m.d.blocked[pid] = from
	m.d.stateMu.Unlock()
	return nil
}

func (m daemonMover) Policy(pid int) string {
	return m.d.policy.Resolve(pid)
}
