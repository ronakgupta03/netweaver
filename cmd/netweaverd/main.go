// cmd/netweaverd/main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"netweaver/internal/api"
	"netweaver/internal/cgroups"
	"netweaver/internal/interfaces"
	"netweaver/internal/process"
	"netweaver/internal/routing"
	"netweaver/internal/types"
)

type DaemonService struct {
	cgMgr   *cgroups.Manager
	engine  *routing.Engine
	monitor *interfaces.Monitor
	scanner *process.Scanner
}

func (d *DaemonService) ListInterfaces() ([]types.InterfaceInfo, error) {
	return d.monitor.DiscoverInterfaces()
}

func (d *DaemonService) ListProcesses() ([]types.ProcessInfo, error) {
	return d.scanner.ScanProcesses()
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
	for _, p := range pids {
		_ = d.cgMgr.AssignPID(iface, p)
	}
	return nil
}

func (d *DaemonService) ResetRoute(pid int) error {
	pids, _ := d.scanner.GetProcessTree(pid)
	if len(pids) == 0 {
		pids = []int{pid}
	}
	for _, p := range pids {
		_ = d.cgMgr.ResetPID(p)
	}
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

	// Initial interface discovery & routing setup
	ifaces, err := monitor.DiscoverInterfaces()
	if err == nil {
		for _, iface := range ifaces {
			log.Printf("[netweaverd] Discovered interface: %s (table %d)", iface.Name, iface.TableID)
			_ = cgMgr.EnsureInterfaceCgroup(iface.Name)
			_ = engine.SetupInterfaceRoute(iface)
		}
	}

	// Start background watcher for interface hotplug and carrier status
	ctx, cancelMonitor := context.WithCancel(context.Background())
	defer cancelMonitor()

	notifyChan := make(chan []types.InterfaceInfo, 10)
	go monitor.StartWatch(ctx, notifyChan)
	go func() {
		for updatedIfaces := range notifyChan {
			for _, iface := range updatedIfaces {
				_ = cgMgr.EnsureInterfaceCgroup(iface.Name)
				_ = engine.SetupInterfaceRoute(iface)
			}
		}
	}()

	daemon := &DaemonService{
		cgMgr:   cgMgr,
		engine:  engine,
		monitor: monitor,
		scanner: scanner,
	}

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
