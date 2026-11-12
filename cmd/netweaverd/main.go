// cmd/netweaverd/main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"netweaver/internal/api"
	"netweaver/internal/autoroute"
	"netweaver/internal/cgroups"
	"netweaver/internal/interfaces"
	"netweaver/internal/policy"
	"netweaver/internal/process"
	"netweaver/internal/routing"
	"netweaver/internal/rules"
	"netweaver/internal/telemetry"
	"netweaver/internal/types"
)

type DaemonService struct {
	cgMgr     *cgroups.Manager
	engine    *routing.Engine
	monitor   *interfaces.Monitor
	scanner   *process.Scanner
	telemetry *telemetry.Engine
	rules     *rules.Store
	policy    *policy.Manager

	blockedMu sync.Mutex
	blocked   map[int]string // PID -> interface it was quarantined away from
}

func (d *DaemonService) ListInterfaces() ([]types.InterfaceInfo, error) {
	ifaces, err := d.monitor.DiscoverInterfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		usage, rate := d.telemetry.InterfaceUsage(ifaces[i].Name)
		ifaces[i].RxBytes = usage.Rx
		ifaces[i].TxBytes = usage.Tx
		ifaces[i].RxRate = rate.Rx
		ifaces[i].TxRate = rate.Tx
	}
	return ifaces, nil
}

func (d *DaemonService) ListProcesses() ([]types.ProcessInfo, error) {
	procs, err := d.scanner.ScanProcesses()
	if err != nil {
		return nil, err
	}
	for i := range procs {
		pids, treeErr := d.scanner.GetProcessTree(procs[i].PID)
		if treeErr != nil || len(pids) == 0 {
			pids = []int{procs[i].PID}
		}
		procs[i].Policy = d.policy.Resolve(procs[i].PID)
		usage, rate := d.telemetry.SubtreeUsage(pids)
		procs[i].RxBytes = usage.Rx
		procs[i].TxBytes = usage.Tx
		procs[i].RxRate = rate.Rx
		procs[i].TxRate = rate.Tx
	}
	return procs, nil
}

func (d *DaemonService) AssignRoute(pid int, iface string) error {
	if err := d.cgMgr.EnsureInterfaceCgroup(iface); err != nil {
		return err
	}
	// Migrate PID and all children
	pids, err := d.scanner.GetProcessTree(pid)
	if err != nil {
		pids = []int{pid}
	}
	pol := d.policy.Resolve(pid)
	for _, p := range pids {
		_ = d.cgMgr.AssignPID(iface, p)
	}
	d.policy.Set(pid, pol)
	return nil
}

func (d *DaemonService) GetPolicy() string {
	return d.policy.Default()
}

func (d *DaemonService) SetPolicy(p string) error {
	return d.policy.SetDefault(p)
}

func (d *DaemonService) ListRules() []types.Rule {
	return d.rules.List()
}

func (d *DaemonService) AddRule(rule types.Rule) error {
	return d.rules.Add(rule)
}

func (d *DaemonService) RemoveRule(match string) error {
	return d.rules.Remove(match)
}

func (d *DaemonService) ResetRoute(pid int) error {
	pids, _ := d.scanner.GetProcessTree(pid)
	if len(pids) == 0 {
		pids = []int{pid}
	}
	for _, p := range pids {
		_ = d.cgMgr.ResetPID(p)
	}
	d.policy.Forget(pid)
	return nil
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
	monitor := interfaces.NewMonitor()
	scanner := process.NewScanner()
	telemetryEngine := telemetry.NewEngine()

	rulesPath := os.Getenv("NETWEAVER_RULES")
	if rulesPath == "" {
		rulesPath = "/etc/netweaver/rules.json"
	}
	ruleStore := rules.NewStore(rulesPath)
	if err := ruleStore.Load(); err != nil {
		log.Printf("[netweaverd] WARNING: %v", err)
	}

	settingsPath := os.Getenv("NETWEAVER_SETTINGS")
	if settingsPath == "" {
		settingsPath = "/etc/netweaver/settings.json"
	}
	policyMgr := policy.NewManager(settingsPath, ruleStore)
	if err := policyMgr.Load(); err != nil {
		log.Printf("[netweaverd] WARNING: %v", err)
	}

	daemon := &DaemonService{
		cgMgr:     cgMgr,
		engine:    engine,
		monitor:   monitor,
		scanner:   scanner,
		telemetry: telemetryEngine,
		rules:     ruleStore,
		policy:    policyMgr,
		blocked:   make(map[int]string),
	}

	_ = cgMgr.EnsureBlockedCgroup()

	// Initial interface discovery & routing setup
	ifaces, err := monitor.DiscoverInterfaces()
	if err == nil {
		for _, iface := range ifaces {
			log.Printf("[netweaverd] Discovered interface: %s (table %d)", iface.Name, iface.TableID)
			if err := cgMgr.EnsureInterfaceCgroup(iface.Name); err != nil {
				log.Printf("[netweaverd] cgroup setup failed for %s: %v", iface.Name, err)
			}
			if err := engine.SetupInterfaceRoute(iface); err != nil {
				log.Printf("[netweaverd] route setup failed for %s: %v", iface.Name, err)
			}
		}
	}

	// Start background watcher for interface hotplug and carrier status
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
	_ = engine.Teardown()
	_ = cgMgr.Teardown()
	log.Println("[netweaverd] Clean exit.")
}

// routerAssigner adapts DaemonService to the autoroute.Assigner contract.
type routerAssigner struct{ d *DaemonService }

func (r routerAssigner) Assign(pid int, iface string) error {
	return r.d.AssignRoute(pid, iface)
}

func (r routerAssigner) Current(pid int) string {
	return r.d.scanner.AssignedInterface(pid)
}
