// cmd/netweaverd/main.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"netweaver/internal/api"
	"netweaver/internal/autoroute"
	"netweaver/internal/cgroups"
	"netweaver/internal/classifier"
	"netweaver/internal/events"
	"netweaver/internal/failover"
	"netweaver/internal/interfaces"
	"netweaver/internal/policy"
	"netweaver/internal/process"
	"netweaver/internal/quota"
	"netweaver/internal/routing"
	"netweaver/internal/rules"
	"netweaver/internal/telemetry"
	"netweaver/internal/types"
)

const defaultCgroupRoot = "/sys/fs/cgroup"

var (
	_ api.Backend          = (*DaemonService)(nil)
	_ api.ExtendedBackend  = (*DaemonService)(nil)
	_ autoroute.Assigner   = routerAssigner{}
	_ autoroute.OptsAssigner = routerAssigner{}
)

type DaemonService struct {
	cgMgr      *cgroups.Manager
	engine     *routing.Engine
	monitor    *interfaces.Monitor
	scanner    *process.Scanner
	telemetry  *telemetry.Engine
	rules      *rules.Store
	policy     *policy.Manager
	clfMu      sync.RWMutex
	classifier *classifier.Classifier
	quotas     *quota.Manager
	events     *events.Bus
	router     *autoroute.Router

	cgroupRoot string

	// Optional test hooks; when nil, production methods are used.
	discoverIfacesFn func() ([]types.InterfaceInfo, error)
	snapshotIfacesFn func() []types.InterfaceInfo
	applyNftFn       func() error

	stateMu       sync.Mutex
	blocked       map[int]string  // PID -> interface quarantined from by failover/quota
	quotaBlocked  map[int]bool    // PID -> quarantined due to Background quota exceedance
	manualBlocked map[int]string  // PID -> previous interface ("" if unassigned) before manual block
	profiles      map[int]string  // PID -> virtual profile (@low-latency, etc.)
	rateLimits    map[int]uint64  // PID -> egress rate limit in bytes/sec
	evacuated     map[string]bool // interface -> already evacuated due to unhealthy upstream
}

func newDaemonService(
	cgMgr *cgroups.Manager,
	engine *routing.Engine,
	monitor *interfaces.Monitor,
	scanner *process.Scanner,
	telemetryEngine *telemetry.Engine,
	ruleStore *rules.Store,
	policyMgr *policy.Manager,
	quotaMgr *quota.Manager,
	eventBus *events.Bus,
	cgroupRoot string,
) *DaemonService {
	if cgroupRoot == "" {
		cgroupRoot = defaultCgroupRoot
	}
	return &DaemonService{
		cgMgr:         cgMgr,
		engine:        engine,
		monitor:       monitor,
		scanner:       scanner,
		telemetry:     telemetryEngine,
		rules:         ruleStore,
		policy:        policyMgr,
		quotas:        quotaMgr,
		events:        eventBus,
		cgroupRoot:    cgroupRoot,
		blocked:       make(map[int]string),
		quotaBlocked:  make(map[int]bool),
		manualBlocked: make(map[int]string),
		profiles:      make(map[int]string),
		rateLimits:    make(map[int]uint64),
		evacuated:     make(map[string]bool),
	}
}

func (d *DaemonService) discoverIfaces() ([]types.InterfaceInfo, error) {
	if d.discoverIfacesFn != nil {
		return d.discoverIfacesFn()
	}
	return d.monitor.DiscoverInterfaces()
}

func (d *DaemonService) currentInterfaces() []types.InterfaceInfo {
	var ifaces []types.InterfaceInfo
	if d.snapshotIfacesFn != nil {
		ifaces = d.snapshotIfacesFn()
	} else if d.monitor != nil {
		ifaces = d.monitor.SnapshotInterfaces()
	}
	if len(ifaces) == 0 {
		if discovered, err := d.discoverIfaces(); err == nil {
			ifaces = discovered
		}
	}
	return d.enrichInterfaces(ifaces)
}

func (d *DaemonService) applyNftables() error {
	if d.applyNftFn != nil {
		return d.applyNftFn()
	}
	return d.engine.ApplyNftables()
}

func (d *DaemonService) publishEvent(ev types.Event) {
	if d.events != nil {
		d.events.Publish(ev)
	}
}

func (d *DaemonService) notifyDesktop(title, body string) {
	if d.events != nil {
		d.events.NotifyDesktop(title, body)
	}
}

func (d *DaemonService) getRateLimit(pid int) uint64 {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	return d.rateLimits[pid]
}

func (d *DaemonService) getProcessTreeOrSelf(pid int) ([]int, error) {
	pids, err := d.scanner.GetProcessTree(pid)
	if err != nil {
		if pid <= 100 {
			return nil, err
		}
		return []int{pid}, nil
	}
	if len(pids) == 0 {
		return []int{pid}, nil
	}
	return pids, nil
}

func (d *DaemonService) currentAssignedInterface(pid int) string {
	if d.scanner != nil {
		if iface := d.scanner.AssignedInterface(pid); iface != "" {
			return iface
		}
	}
	if d.cgMgr != nil {
		return d.cgMgr.AssignedCgroup(pid)
	}
	return ""
}

func (d *DaemonService) lookupTableID(iface string, ifaces []types.InterfaceInfo) int {
	if iface == "" || iface == "default" || iface == cgroups.BlockedCgroup {
		return 0
	}
	for _, info := range ifaces {
		if info.Name == iface {
			return info.TableID
		}
	}
	if netIf, err := net.InterfaceByName(iface); err == nil && netIf.Index > 0 {
		return 0x100 + netIf.Index
	}
	return 0
}

func (d *DaemonService) enrichInterfaces(ifaces []types.InterfaceInfo) []types.InterfaceInfo {
	out := make([]types.InterfaceInfo, len(ifaces))
	copy(out, ifaces)
	for i := range out {
		if d.telemetry != nil {
			usage, rate := d.telemetry.InterfaceUsage(out[i].Name)
			out[i].RxBytes = usage.Rx
			out[i].TxBytes = usage.Tx
			out[i].RxRate = rate.Rx
			out[i].TxRate = rate.Tx
		}
		if d.engine != nil {
			if dns := d.engine.InterfaceDNS(out[i].Name); len(dns) > 0 {
				out[i].DNSServers = dns
			}
		}
		if d.quotas != nil {
			if cfg, ok := d.quotas.Get(out[i].Name); ok {
				out[i].Metered = out[i].Metered || cfg.Metered
				out[i].DailyQuotaBytes = cfg.DailyLimitBytes
				out[i].DailyUsedBytes = cfg.UsedBytes
				out[i].QuotaExceeded = cfg.DailyLimitBytes > 0 && cfg.UsedBytes >= cfg.DailyLimitBytes
			}
		}
	}
	return out
}

func (d *DaemonService) syncAndEnrichInterfaces(ifaces []types.InterfaceInfo) []types.InterfaceInfo {
	out := make([]types.InterfaceInfo, len(ifaces))
	copy(out, ifaces)
	for i := range out {
		var usage telemetry.IfaceUsage
		if d.telemetry != nil {
			var rate telemetry.Rate
			usage, rate = d.telemetry.InterfaceUsage(out[i].Name)
			out[i].RxBytes = usage.Rx
			out[i].TxBytes = usage.Tx
			out[i].RxRate = rate.Rx
			out[i].TxRate = rate.Tx
		}
		if d.engine != nil {
			if dns := d.engine.InterfaceDNS(out[i].Name); len(dns) > 0 {
				out[i].DNSServers = dns
			}
		}
		if d.quotas != nil {
			status := d.quotas.UpdateUsage(out[i].Name, usage.Rx, usage.Tx)
			if cfg, ok := d.quotas.Get(out[i].Name); ok {
				out[i].Metered = out[i].Metered || cfg.Metered
				out[i].DailyQuotaBytes = cfg.DailyLimitBytes
				out[i].DailyUsedBytes = cfg.UsedBytes
				out[i].QuotaExceeded = status.Exceeded || (cfg.DailyLimitBytes > 0 && cfg.UsedBytes >= cfg.DailyLimitBytes)
			}
			if status.JustWarned {
				msg := fmt.Sprintf("Interface %s reached %.0f%% of daily quota (%s / %s)",
					out[i].Name, status.Percent,
					telemetry.FormatBytes(status.Config.UsedBytes),
					telemetry.FormatBytes(status.Config.DailyLimitBytes))
				log.Printf("[netweaverd] %s", msg)
				d.publishEvent(types.Event{
					Type:      "quota_warn",
					Interface: out[i].Name,
					Message:   msg,
				})
				d.notifyDesktop("NetWeaver Quota Warning", msg)
			}
			if status.JustExceeded {
				msg := fmt.Sprintf("Interface %s exceeded daily quota (%s / %s)",
					out[i].Name,
					telemetry.FormatBytes(status.Config.UsedBytes),
					telemetry.FormatBytes(status.Config.DailyLimitBytes))
				log.Printf("[netweaverd] %s", msg)
				d.publishEvent(types.Event{
					Type:      "quota_exceeded",
					Interface: out[i].Name,
					Message:   msg,
				})
				d.notifyDesktop("NetWeaver Quota Exceeded", msg)
				d.quarantineBackgroundProcesses(out[i].Name)
			}
		}
	}
	return out
}

func (d *DaemonService) ListInterfaces() ([]types.InterfaceInfo, error) {
	ifaces, err := d.discoverIfaces()
	if err != nil {
		return nil, err
	}
	return d.syncAndEnrichInterfaces(ifaces), nil
}

func (d *DaemonService) ListProcesses() ([]types.ProcessInfo, error) {
	procs, err := d.scanner.ScanProcesses()
	if err != nil {
		return nil, err
	}
	d.stateMu.Lock()
	blockedCopy := make(map[int]bool, len(d.blocked)+len(d.manualBlocked))
	for pid := range d.blocked {
		blockedCopy[pid] = true
	}
	for pid := range d.manualBlocked {
		blockedCopy[pid] = true
	}
	ratesCopy := make(map[int]uint64, len(d.rateLimits))
	for pid, r := range d.rateLimits {
		ratesCopy[pid] = r
	}
	profilesCopy := make(map[int]string, len(d.profiles))
	for pid, prof := range d.profiles {
		profilesCopy[pid] = prof
	}
	d.stateMu.Unlock()

	for i := range procs {
		pid := procs[i].PID
		if procs[i].AssignedInterface == "" && d.cgMgr != nil {
			if cg := d.cgMgr.AssignedCgroup(pid); cg != "" {
				procs[i].AssignedInterface = cg
				if cg == cgroups.BlockedCgroup {
					procs[i].Blocked = true
				}
			}
		}
		if procs[i].AssignedInterface == "default" {
			procs[i].AssignedInterface = ""
		}

		pids, treeErr := d.scanner.GetProcessTree(pid)
		if treeErr != nil || len(pids) == 0 {
			pids = []int{pid}
		}
		procs[i].Policy = d.policy.Resolve(pid)
		procs[i].Blocked = procs[i].Blocked || blockedCopy[pid] || (d.cgMgr != nil && d.cgMgr.IsBlocked(pid))
		procs[i].RateLimitBps = ratesCopy[pid]
		procs[i].Profile = profilesCopy[pid]

		usage, rate := d.telemetry.SubtreeUsage(pids)
		procs[i].RxBytes = usage.Rx
		procs[i].TxBytes = usage.Tx
		procs[i].RxRate = rate.Rx
		procs[i].TxRate = rate.Tx
	}
	return procs, nil
}

func (d *DaemonService) AssignRoute(pid int, iface string) error {
	existingRate := d.getRateLimit(pid)
	return d.assignRouteInternal(pid, iface, "", existingRate, true, true)
}

func (d *DaemonService) AssignRouteWithOpts(pid int, iface string, pol string, rateLimitBps uint64) error {
	return d.assignRouteInternal(pid, iface, pol, rateLimitBps, true, true)
}

func (d *DaemonService) assignRouteInternal(pid int, iface string, pol string, rateLimitBps uint64, updateProfile bool, emitEvent bool) error {
	if pid <= 100 {
		return fmt.Errorf("cannot assign system process PID %d", pid)
	}
	iface = strings.TrimSpace(iface)
	if !types.IsVirtualProfile(iface) && !types.ValidInterfaceName(iface) {
		return fmt.Errorf("invalid interface or virtual profile %q", iface)
	}
	pol = strings.ToLower(strings.TrimSpace(pol))
	if !types.ValidPolicy(pol) {
		return fmt.Errorf("unknown policy %q (use failover or strict)", pol)
	}

	effPol := pol
	if effPol == "" {
		effPol = d.policy.Resolve(pid)
	}

	ifaces := d.currentInterfaces()
	isProfile := types.IsVirtualProfile(iface)
	targetIface := iface

	if isProfile {
		targetIface = failover.ResolveSmartProfile(iface, ifaces)
		if targetIface == "" {
			if effPol == types.PolicyStrict {
				pids, err := d.getProcessTreeOrSelf(pid)
				if err != nil {
					return err
				}
				_ = d.cgMgr.EnsureBlockedCgroup()
				for _, p := range pids {
					if err := d.cgMgr.Block(p); err != nil && p == pid {
						return err
					}
				}
				d.cleanupStaleCgroups(pids, cgroups.BlockedCgroup)

				d.policy.Set(pid, effPol)
				d.stateMu.Lock()
				d.profiles[pid] = iface
				if rateLimitBps > 0 {
					d.rateLimits[pid] = rateLimitBps
				} else {
					delete(d.rateLimits, pid)
				}
				d.blocked[pid] = ""
				delete(d.quotaBlocked, pid)
				delete(d.manualBlocked, pid)
				d.stateMu.Unlock()

				if emitEvent {
					msg := fmt.Sprintf("quarantined pid %d: no healthy interface matching %s (strict policy)", pid, iface)
					d.publishEvent(types.Event{
						Type:    "killswitch",
						PID:     pid,
						App:     procComm(pid),
						Policy:  effPol,
						Message: msg,
					})
					d.notifyDesktop("NetWeaver Kill-Switch", msg)
				}
				return nil
			}
			return fmt.Errorf("no healthy interface matches virtual profile %s", iface)
		}
	}

	tableID := d.lookupTableID(targetIface, ifaces)
	if err := d.moveProcessToInterface(pid, targetIface, tableID, rateLimitBps); err != nil {
		return err
	}

	d.policy.Set(pid, effPol)
	d.stateMu.Lock()
	if isProfile {
		d.profiles[pid] = iface
	} else if updateProfile {
		delete(d.profiles, pid)
	}
	if rateLimitBps > 0 {
		d.rateLimits[pid] = rateLimitBps
	} else {
		delete(d.rateLimits, pid)
	}
	delete(d.blocked, pid)
	delete(d.quotaBlocked, pid)
	delete(d.manualBlocked, pid)
	d.stateMu.Unlock()

	if emitEvent {
		msg := fmt.Sprintf("assigned pid %d to %s", pid, targetIface)
		if isProfile {
			msg = fmt.Sprintf("assigned pid %d to %s via %s", pid, targetIface, iface)
		}
		if rateLimitBps > 0 {
			msg += fmt.Sprintf(" (cap %s)", telemetry.FormatRate(float64(rateLimitBps)))
		}
		d.publishEvent(types.Event{
			Type:      "assign",
			PID:       pid,
			App:       procComm(pid),
			Interface: targetIface,
			Policy:    effPol,
			Message:   msg,
		})
	}
	return nil
}

func (d *DaemonService) moveProcessToInterface(pid int, targetIface string, tableID int, rateLimitBps uint64) error {
	if err := d.cgMgr.EnsureInterfaceCgroup(targetIface); err != nil {
		return err
	}
	d.ensureFakeProcsFile(targetIface)
	pids, err := d.getProcessTreeOrSelf(pid)
	if err != nil {
		return err
	}

	useLeaf := rateLimitBps > 0 || d.hasClassifier()
	if useLeaf {
		for _, p := range pids {
			if p <= 100 {
				continue
			}
			leafPath, err := d.cgMgr.EnsureProcessCgroup(targetIface, p)
			if err != nil {
				if p == pid {
					return err
				}
				continue
			}
			if err := d.cgMgr.AssignPIDToPath(leafPath, p); err != nil {
				if p == pid {
					return err
				}
				continue
			}
			if d.telemetry != nil {
				d.telemetry.TrackPID(p)
			}
			d.withClassifier(func(clf *classifier.Classifier) {
				_ = clf.SetPathTarget(leafPath, uint32(tableID), false)
				_ = clf.SetPathRateLimit(leafPath, rateLimitBps)
			})
		}
	} else {
		for _, p := range pids {
			if p <= 100 {
				continue
			}
			if err := d.cgMgr.AssignPID(targetIface, p); err != nil {
				if p == pid {
					return err
				}
				continue
			}
			if d.telemetry != nil {
				d.telemetry.TrackPID(p)
			}
		}
	}
	if d.telemetry != nil && targetIface != "default" && targetIface != cgroups.BlockedCgroup {
		d.telemetry.TrackInterface(targetIface)
	}
	d.cleanupStaleCgroups(pids, targetIface)
	return nil
}

func (d *DaemonService) ensureFakeProcsFile(iface string) {
	if d.cgroupRoot == defaultCgroupRoot {
		return
	}
	procsPath := filepath.Join(d.cgroupRoot, "netweaver", iface, "cgroup.procs")
	if _, err := os.Stat(procsPath); os.IsNotExist(err) {
		_ = os.WriteFile(procsPath, nil, 0o644)
	}
}

// cleanupStaleCgroups removes empty per-PID leaf directories on real cgroupfs
// after a process moves to keep ReadProcessStats accurate, and in temp-dir test
// environments removes PID entries from previous fake cgroup.procs files.
func (d *DaemonService) cleanupStaleCgroups(pids []int, keepIface string) {
	baseDir := filepath.Join(d.cgroupRoot, "netweaver")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return
	}
	pidSet := make(map[int]bool, len(pids))
	for _, p := range pids {
		pidSet[p] = true
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == keepIface {
			continue
		}
		ifaceDir := filepath.Join(baseDir, entry.Name())
		for _, p := range pids {
			leafPath := filepath.Join(ifaceDir, fmt.Sprintf("p%d", p))
			if d.cgroupRoot == defaultCgroupRoot {
				_ = os.Remove(leafPath)
			} else {
				removePIDsFromFakeProcsFile(filepath.Join(leafPath, "cgroup.procs"), pidSet)
				_ = os.RemoveAll(leafPath)
			}
		}
		if d.cgroupRoot != defaultCgroupRoot {
			removePIDsFromFakeProcsFile(filepath.Join(ifaceDir, "cgroup.procs"), pidSet)
		}
	}
}

func removePIDsFromFakeProcsFile(procsPath string, drop map[int]bool) {
	data, err := os.ReadFile(procsPath)
	if err != nil {
		return
	}
	var kept []string
	changed := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		p, err := strconv.Atoi(trimmed)
		if err == nil && drop[p] {
			changed = true
			continue
		}
		kept = append(kept, trimmed)
	}
	if !changed {
		return
	}
	content := ""
	if len(kept) > 0 {
		content = strings.Join(kept, "\n") + "\n"
	}
	_ = os.WriteFile(procsPath, []byte(content), 0o644)
}

func (d *DaemonService) SetProcessPolicy(pid int, pol string) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID %d", pid)
	}
	norm := strings.ToLower(strings.TrimSpace(pol))
	if norm != types.PolicyFailover && norm != types.PolicyStrict {
		return fmt.Errorf("unknown policy %q (use failover or strict)", pol)
	}
	d.policy.Set(pid, norm)
	d.publishEvent(types.Event{
		Type:    "policy",
		PID:     pid,
		App:     procComm(pid),
		Policy:  norm,
		Message: fmt.Sprintf("policy for pid %d set to %s", pid, norm),
	})
	return nil
}

func (d *DaemonService) BlockProcess(pid int, blocked bool) error {
	if pid <= 100 {
		return fmt.Errorf("cannot block system process PID %d", pid)
	}
	pids, err := d.getProcessTreeOrSelf(pid)
	if err != nil {
		return err
	}

	if blocked {
		cur := d.currentAssignedInterface(pid)
		prevIface := cur
		if prevIface == cgroups.BlockedCgroup || prevIface == "default" {
			prevIface = ""
		}

		d.stateMu.Lock()
		if prevIface == "" {
			if existing, ok := d.manualBlocked[pid]; ok {
				prevIface = existing
			} else if existing, ok := d.blocked[pid]; ok {
				prevIface = existing
			}
		}
		d.stateMu.Unlock()

		_ = d.cgMgr.EnsureBlockedCgroup()
		for _, p := range pids {
			if p <= 100 {
				continue
			}
			if err := d.cgMgr.Block(p); err != nil && p == pid {
				return err
			}
		}
		d.withClassifier(func(clf *classifier.Classifier) {
			_ = clf.SetTarget(cgroups.BlockedCgroup, 0, true)
		})
		d.cleanupStaleCgroups(pids, cgroups.BlockedCgroup)

		d.stateMu.Lock()
		d.manualBlocked[pid] = prevIface
		delete(d.blocked, pid)
		delete(d.quotaBlocked, pid)
		d.stateMu.Unlock()

		msg := fmt.Sprintf("blocked pid %d", pid)
		if prevIface != "" {
			msg = fmt.Sprintf("blocked pid %d (was on %s)", pid, prevIface)
		}
		d.publishEvent(types.Event{
			Type:          "block",
			PID:           pid,
			App:           procComm(pid),
			FromInterface: prevIface,
			Message:       msg,
		})
		return nil
	}

	// Unblocking: capture prior interface / profile / rate limit
	d.stateMu.Lock()
	prevIface, hadManual := d.manualBlocked[pid]
	if !hadManual {
		prevIface = d.blocked[pid]
	}
	prof := d.profiles[pid]
	rate := d.rateLimits[pid]
	delete(d.manualBlocked, pid)
	delete(d.blocked, pid)
	delete(d.quotaBlocked, pid)
	d.stateMu.Unlock()

	ifaces := d.currentInterfaces()
	target := ""
	if prof != "" {
		target = failover.ResolveSmartProfile(prof, ifaces)
	}
	if target == "" && prevIface != "" {
		for _, info := range ifaces {
			if info.Name == prevIface && info.Up && info.Healthy {
				target = prevIface
				break
			}
		}
		if target == "" {
			healthyNames := make([]string, 0, len(ifaces))
			for _, info := range ifaces {
				if info.Up && info.Healthy {
					healthyNames = append(healthyNames, info.Name)
				}
			}
			target = failover.BestInterface(healthyNames)
		}
	}

	if target == "" {
		if rate > 0 {
			if err := d.moveProcessToInterface(pid, "default", 0, rate); err != nil {
				return err
			}
		} else {
			if err := d.cgMgr.EnsureInterfaceCgroup("default"); err != nil {
				return err
			}
			for _, p := range pids {
				if p <= 100 {
					continue
				}
				if err := d.cgMgr.ResetPID(p); err != nil && p == pid {
					return err
				}
			}
			d.cleanupStaleCgroups(pids, "default")
		}
		d.publishEvent(types.Event{
			Type:    "unblock",
			PID:     pid,
			App:     procComm(pid),
			Message: fmt.Sprintf("unblocked pid %d (restored to default route)", pid),
		})
		return nil
	}

	tableID := d.lookupTableID(target, ifaces)
	if err := d.moveProcessToInterface(pid, target, tableID, rate); err != nil {
		return err
	}
	d.publishEvent(types.Event{
		Type:      "unblock",
		PID:       pid,
		App:       procComm(pid),
		Interface: target,
		Message:   fmt.Sprintf("unblocked pid %d (restored to %s)", pid, target),
	})
	return nil
}

func (d *DaemonService) SetProcessRateLimit(pid int, bps uint64) error {
	if pid <= 100 {
		return fmt.Errorf("cannot rate-limit system process PID %d", pid)
	}
	pids, err := d.getProcessTreeOrSelf(pid)
	if err != nil {
		return err
	}

	d.stateMu.Lock()
	if bps > 0 {
		d.rateLimits[pid] = bps
	} else {
		delete(d.rateLimits, pid)
	}
	_, inManual := d.manualBlocked[pid]
	_, inBlocked := d.blocked[pid]
	d.stateMu.Unlock()

	iface := d.currentAssignedInterface(pid)
	if iface == "" {
		iface = "default"
	}

	if iface == cgroups.BlockedCgroup || inManual || inBlocked {
		// Keep blocked processes quarantined; only update stored rate cap.
		d.publishRateLimitEvent(pid, cgroups.BlockedCgroup, bps)
		return nil
	}

	if err := d.cgMgr.EnsureInterfaceCgroup(iface); err != nil {
		return err
	}
	d.ensureFakeProcsFile(iface)
	ifaces := d.currentInterfaces()
	tableID := d.lookupTableID(iface, ifaces)

	for _, p := range pids {
		if p <= 100 {
			continue
		}
		leafPath, err := d.cgMgr.EnsureProcessCgroup(iface, p)
		if err != nil {
			if p == pid {
				return err
			}
			continue
		}
		if err := d.cgMgr.AssignPIDToPath(leafPath, p); err != nil {
			if p == pid {
				return err
			}
			continue
		}
		if d.telemetry != nil {
			d.telemetry.TrackPID(p)
		}
		d.withClassifier(func(clf *classifier.Classifier) {
			_ = clf.SetPathTarget(leafPath, uint32(tableID), false)
			_ = clf.SetPathRateLimit(leafPath, bps)
		})
	}
	d.cleanupStaleCgroups(pids, iface)
	d.publishRateLimitEvent(pid, iface, bps)
	return nil
}

func (d *DaemonService) publishRateLimitEvent(pid int, iface string, bps uint64) {
	msg := fmt.Sprintf("cleared rate limit for pid %d", pid)
	if bps > 0 {
		msg = fmt.Sprintf("rate limit for pid %d set to %s", pid, telemetry.FormatRate(float64(bps)))
	}
	d.publishEvent(types.Event{
		Type:      "ratelimit",
		PID:       pid,
		App:       procComm(pid),
		Interface: iface,
		Message:   msg,
	})
}

func (d *DaemonService) SwitchInterface(fromIface, toIface string) (int, error) {
	fromIface = strings.TrimSpace(fromIface)
	toIface = strings.TrimSpace(toIface)
	if !types.ValidInterfaceName(fromIface) {
		return 0, fmt.Errorf("invalid source interface %q", fromIface)
	}
	if toIface != "" && !types.IsVirtualProfile(toIface) && !types.ValidInterfaceName(toIface) {
		return 0, fmt.Errorf("invalid target interface or profile %q", toIface)
	}

	ifaces := d.currentInterfaces()
	if toIface == "" {
		healthyCandidates := make([]string, 0, len(ifaces))
		allCandidates := make([]string, 0, len(ifaces))
		for _, info := range ifaces {
			if info.Name == fromIface {
				continue
			}
			allCandidates = append(allCandidates, info.Name)
			if info.Up && info.Healthy {
				healthyCandidates = append(healthyCandidates, info.Name)
			}
		}
		toIface = failover.BestInterface(healthyCandidates)
		if toIface == "" {
			toIface = failover.BestInterface(allCandidates)
		}
		if toIface == "" {
			return 0, fmt.Errorf("no target interface available to switch from %s", fromIface)
		}
	}

	pids, err := d.cgMgr.PIDs(fromIface)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			d.publishEvent(types.Event{
				Type:          "switch",
				FromInterface: fromIface,
				Interface:     toIface,
				Message:       fmt.Sprintf("switched 0 process(es) from %s to %s", fromIface, toIface),
			})
			return 0, nil
		}
		return 0, err
	}
	if len(pids) == 0 || fromIface == toIface {
		d.publishEvent(types.Event{
			Type:          "switch",
			FromInterface: fromIface,
			Interface:     toIface,
			Message:       fmt.Sprintf("switched 0 process(es) from %s to %s", fromIface, toIface),
		})
		return 0, nil
	}

	sort.Ints(pids)
	pidSet := make(map[int]bool, len(pids))
	for _, p := range pids {
		pidSet[p] = true
	}

	// Move root processes first so child processes inherit their parent's policy & rate limit.
	ordered := make([]int, 0, len(pids))
	for _, p := range pids {
		ppid := readPPID(p)
		if !pidSet[ppid] {
			ordered = append(ordered, p)
		}
	}
	for _, p := range pids {
		ppid := readPPID(p)
		if pidSet[ppid] {
			ordered = append(ordered, p)
		}
	}

	movedSet := make(map[int]bool, len(pids))
	for _, p := range ordered {
		if movedSet[p] {
			continue
		}
		pol := d.policy.Resolve(p)
		rate := d.getRateLimit(p)
		if err := d.assignRouteInternal(p, toIface, pol, rate, true, false); err != nil {
			return len(movedSet), err
		}
		movedSet[p] = true
		if tree, treeErr := d.getProcessTreeOrSelf(p); treeErr == nil {
			for _, tp := range tree {
				if pidSet[tp] {
					movedSet[tp] = true
				}
			}
		}
	}

	moved := len(movedSet)
	d.publishEvent(types.Event{
		Type:          "switch",
		FromInterface: fromIface,
		Interface:     toIface,
		Message:       fmt.Sprintf("switched %d process(es) from %s to %s", moved, fromIface, toIface),
	})
	return moved, nil
}

func (d *DaemonService) ListQuotas() []types.QuotaConfig {
	if d.quotas == nil {
		return nil
	}
	return d.quotas.List()
}

func (d *DaemonService) SetQuota(cfg types.QuotaConfig) error {
	if d.quotas == nil {
		return errors.New("quota manager not initialized")
	}
	if err := d.quotas.SetQuota(cfg); err != nil {
		return err
	}
	cur := d.currentInterfaces()
	d.reconcileQuotasAndProfiles(cur)
	d.publishEvent(types.Event{
		Type:      "quota",
		Interface: cfg.Interface,
		Message: fmt.Sprintf("quota updated for %s (limit %s, metered=%v)",
			cfg.Interface, telemetry.FormatBytes(cfg.DailyLimitBytes), cfg.Metered),
	})
	return nil
}

func (d *DaemonService) RemoveQuota(iface string) error {
	if d.quotas == nil {
		return errors.New("quota manager not initialized")
	}
	if err := d.quotas.RemoveQuota(iface); err != nil {
		return err
	}
	cur := d.currentInterfaces()
	d.reconcileQuotasAndProfiles(cur)
	d.publishEvent(types.Event{
		Type:      "quota",
		Interface: iface,
		Message:   fmt.Sprintf("quota removed for %s", iface),
	})
	return nil
}

func (d *DaemonService) SetInterfaceDNS(iface string, servers []string) error {
	iface = strings.TrimSpace(iface)
	if !types.ValidInterfaceName(iface) {
		return fmt.Errorf("invalid interface name: %q", iface)
	}
	if d.monitor != nil {
		d.monitor.SetDNSOverride(iface, servers)
	}
	if d.engine != nil {
		d.engine.SetInterfaceDNS(iface, servers)
	}
	if err := d.applyNftables(); err != nil {
		return err
	}
	msg := fmt.Sprintf("DNS override cleared for %s", iface)
	if len(servers) > 0 {
		msg = fmt.Sprintf("DNS for %s set to %s", iface, strings.Join(servers, ", "))
	}
	d.publishEvent(types.Event{
		Type:      "dns",
		Interface: iface,
		Message:   msg,
	})
	return nil
}

func (d *DaemonService) ListEvents(since uint64) []types.Event {
	if d.events == nil {
		return []types.Event{}
	}
	return d.events.ListSince(since)
}

func (d *DaemonService) GetPolicy() string {
	return d.policy.Default()
}

func (d *DaemonService) SetPolicy(p string) error {
	if err := d.policy.SetDefault(p); err != nil {
		return err
	}
	def := d.policy.Default()
	d.publishEvent(types.Event{
		Type:    "policy",
		Policy:  def,
		Message: fmt.Sprintf("global default policy set to %s", def),
	})
	return nil
}

func (d *DaemonService) ListRules() []types.Rule {
	return d.rules.List()
}

func (d *DaemonService) AddRule(rule types.Rule) error {
	if err := d.rules.Add(rule); err != nil {
		return err
	}
	if d.engine != nil {
		d.engine.SetDestinationRules(d.rules.List())
		if err := d.applyNftables(); err != nil {
			log.Printf("[netweaverd] warning: applying nftables after rule add: %v", err)
		}
	}
	if d.router != nil {
		d.router.TriggerScan()
	}
	return nil
}

func (d *DaemonService) RemoveRule(match string) error {
	if err := d.rules.Remove(match); err != nil {
		return err
	}
	if d.engine != nil {
		d.engine.SetDestinationRules(d.rules.List())
		if err := d.applyNftables(); err != nil {
			log.Printf("[netweaverd] warning: applying nftables after rule remove: %v", err)
		}
	}
	if d.router != nil {
		d.router.TriggerScan()
	}
	return nil
}

func (d *DaemonService) ResetRoute(pid int) error {
	if pid <= 100 {
		return fmt.Errorf("cannot reset system process PID %d", pid)
	}
	pids, err := d.getProcessTreeOrSelf(pid)
	if err != nil {
		return err
	}
	_ = d.cgMgr.EnsureInterfaceCgroup("default")
	for _, p := range pids {
		if p <= 100 {
			continue
		}
		_ = d.cgMgr.ResetPID(p)
	}
	d.cleanupStaleCgroups(pids, "default")
	d.policy.Forget(pid)

	d.stateMu.Lock()
	for _, p := range pids {
		delete(d.blocked, p)
		delete(d.quotaBlocked, p)
		delete(d.manualBlocked, p)
		delete(d.profiles, p)
		delete(d.rateLimits, p)
	}
	d.stateMu.Unlock()

	d.publishEvent(types.Event{
		Type:    "reset",
		PID:     pid,
		App:     procComm(pid),
		Message: fmt.Sprintf("reset pid %d to default route", pid),
	})
	return nil
}

func procComm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func procCmdline(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

func readPPID(pid int) int {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	s := string(data)
	closeIdx := strings.LastIndex(s, ")")
	if closeIdx == -1 || closeIdx+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[closeIdx+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("netweaverd must run as root")
	}

	log.Println("[netweaverd] Starting NetWeaver root networking daemon...")

	cgMgr := cgroups.NewManager()
	if err := cgMgr.InitHierarchy(); err != nil {
		log.Fatalf("cgroup init error: %v", err)
	}

	engine := routing.NewEngine()
	prober := interfaces.NewHealthProber()
	monitor := interfaces.NewMonitorWithProber(prober)
	scanner := process.NewScanner()
	telemetryEngine := telemetry.NewEngine()
	eventBus := events.NewBus(256)

	rulesPath := os.Getenv("NETWEAVER_RULES")
	if rulesPath == "" {
		rulesPath = "/etc/netweaver/rules.json"
	}
	ruleStore := rules.NewStore(rulesPath)
	if err := ruleStore.Load(); err != nil {
		log.Printf("[netweaverd] WARNING: %v", err)
	}
	engine.SetDestinationRules(ruleStore.List())

	settingsPath := os.Getenv("NETWEAVER_SETTINGS")
	if settingsPath == "" {
		settingsPath = "/etc/netweaver/settings.json"
	}
	policyMgr := policy.NewManager(settingsPath, ruleStore)
	if err := policyMgr.Load(); err != nil {
		log.Printf("[netweaverd] WARNING: %v", err)
	}

	quotaPath := os.Getenv("NETWEAVER_QUOTAS")
	if quotaPath == "" {
		quotaPath = quota.DefaultPath
	}
	quotaMgr := quota.NewManager(quotaPath)
	if err := quotaMgr.Load(); err != nil {
		log.Printf("[netweaverd] WARNING: %v", err)
	}

	daemon := newDaemonService(
		cgMgr,
		engine,
		monitor,
		scanner,
		telemetryEngine,
		ruleStore,
		policyMgr,
		quotaMgr,
		eventBus,
		defaultCgroupRoot,
	)

	_ = cgMgr.EnsureBlockedCgroup()

	clf := classifier.New(defaultCgroupRoot)
	if err := clf.Start(); err != nil {
		log.Printf("[netweaverd] eBPF classifier unavailable, using nftables marking: %v", err)
	} else {
		engine.SetMarking(false)
		daemon.setClassifier(clf)
		telemetryEngine.SetCgroupStatsReader(clf.ReadStats)
		telemetryEngine.SetProcessStatsReader(clf.ReadProcessStats)
		log.Println("[netweaverd] eBPF classifier active (cgroup_skb/egress+ingress marking)")
	}

	// Initial interface discovery & routing setup
	ifaces, err := monitor.DiscoverInterfaces()
	if err == nil {
		for _, iface := range ifaces {
			log.Printf("[netweaverd] Discovered interface: %s (table %d)", iface.Name, iface.TableID)
			telemetryEngine.TrackInterface(iface.Name)
			if err := cgMgr.EnsureInterfaceCgroup(iface.Name); err != nil {
				log.Printf("[netweaverd] cgroup setup failed for %s: %v", iface.Name, err)
			}
			if err := engine.SetupInterfaceRoute(iface); err != nil {
				log.Printf("[netweaverd] route setup failed for %s: %v", iface.Name, err)
			}
		}
	}

	daemon.applyClassifier(ifaces)

	ctx, cancelMonitor := context.WithCancel(context.Background())
	defer cancelMonitor()

	telemetryEngine.Start(ctx)
	if telemetryEngine.SocketAccountingAvailable() {
		log.Println("[netweaverd] Per-process socket accounting active")
	} else {
		log.Println("[netweaverd] WARNING: socket accounting unavailable (ss missing?)")
	}

	notifyChan := make(chan []types.InterfaceInfo, 10)
	go monitor.StartWatch(ctx, notifyChan)
	prevIfaces := ifaces
	go func() {
		for updatedIfaces := range notifyChan {
			daemon.handleInterfaceChanges(prevIfaces, updatedIfaces)
			prevIfaces = updatedIfaces
		}
	}()

	router := autoroute.NewRouter(ruleStore, routerAssigner{daemon})
	daemon.router = router
	router.OnAssign(func(ev autoroute.Event) {
		log.Printf("[netweaverd] auto-routed %s (pid %d) -> %s [%s]", ev.Name, ev.PID, ev.Interface, ev.Policy)
	})
	router.Start(ctx)

	sockPath := "/run/netweaver/netweaver.sock"
	srv := api.NewServer(sockPath, daemon)
	if err := srv.Start(); err != nil {
		log.Fatalf("failed starting IPC server: %v", err)
	}
	log.Printf("[netweaverd] Listening on %s", sockPath)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[netweaverd] Shutting down, cleaning up rules...")
	cancelMonitor()
	srv.Stop()
	daemon.closeClassifier()
	_ = engine.Teardown()
	_ = cgMgr.Teardown()
	log.Println("[netweaverd] Clean exit.")
}

// routerAssigner adapts DaemonService to autoroute.Assigner and autoroute.OptsAssigner.
type routerAssigner struct{ d *DaemonService }

func (r routerAssigner) Assign(pid int, iface string) error {
	return r.d.AssignRoute(pid, iface)
}

func (r routerAssigner) AssignWithOpts(pid int, iface string, pol string, rateLimitBps uint64) error {
	return r.d.AssignRouteWithOpts(pid, iface, pol, rateLimitBps)
}

func (r routerAssigner) Current(pid int) string {
	r.d.stateMu.Lock()
	prof := r.d.profiles[pid]
	r.d.stateMu.Unlock()
	if prof != "" {
		return prof
	}
	return r.d.currentAssignedInterface(pid)
}
