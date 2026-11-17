// cmd/netweaver/main.go
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"netweaver/internal/api"
	"netweaver/internal/telemetry"
	"netweaver/internal/tui"
	"netweaver/internal/types"
)

// defaultSock resolves the daemon socket path; NETWEAVER_SOCK overrides it for
// unprivileged test harnesses and alternate daemon instances.
var defaultSock = func() string {
	if v := os.Getenv("NETWEAVER_SOCK"); v != "" {
		return v
	}
	return "/run/netweaver/netweaver.sock"
}()

func main() {
	if len(os.Args) < 2 {
		// Launch interactive Bubbletea TUI
		if err := tui.Run(defaultSock); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	client := api.NewClient(defaultSock)

	switch os.Args[1] {
	case "list":
		procs, err := client.ListProcesses()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		renderProcessList(os.Stdout, procs)

	case "interfaces":
		ifaces, err := client.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		renderInterfaceList(os.Stdout, ifaces)

	case "assign":
		opts, err := parseAssignArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if opts.policy != "" || opts.rateLimitBps > 0 {
			err = client.AssignRouteWithOpts(opts.pid, opts.target, opts.policy, opts.rateLimitBps)
		} else {
			err = client.AssignRoute(opts.pid, opts.target)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Assigned PID %d to %s\n", opts.pid, opts.target)

	case "reset":
		if len(os.Args) < 3 {
			fmt.Println("Usage: netweaver reset <PID>")
			os.Exit(1)
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil || pid <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid PID: %s\n", os.Args[2])
			os.Exit(1)
		}
		if err := client.ResetRoute(pid); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Reset PID %d to default route\n", pid)

	case "block":
		if len(os.Args) < 3 {
			fmt.Println("Usage: netweaver block <PID>")
			os.Exit(1)
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil || pid <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid PID: %s\n", os.Args[2])
			os.Exit(1)
		}
		if err := client.BlockProcess(pid, true); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Blocked PID %d\n", pid)

	case "unblock":
		if len(os.Args) < 3 {
			fmt.Println("Usage: netweaver unblock <PID>")
			os.Exit(1)
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil || pid <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid PID: %s\n", os.Args[2])
			os.Exit(1)
		}
		if err := client.BlockProcess(pid, false); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Unblocked PID %d\n", pid)

	case "switch":
		if len(os.Args) < 3 {
			fmt.Println("Usage: netweaver switch <from-iface> [to-iface]")
			os.Exit(1)
		}
		fromIface := os.Args[2]
		toIface := ""
		if len(os.Args) > 3 {
			toIface = os.Args[3]
		}
		moved, err := client.SwitchInterface(fromIface, toIface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		target := toIface
		if target == "" {
			target = "best available"
		}
		fmt.Printf("Switched %d process(es) from %s -> %s\n", moved, fromIface, target)

	case "rules":
		handleRules(client, os.Args[2:])

	case "policy":
		handlePolicy(client, os.Args[2:])

	case "quota":
		handleQuota(client, os.Args[2:])

	case "dns":
		handleDNS(client, os.Args[2:])

	case "status":
		handleStatus(client, os.Args[2:])

	case "events":
		handleEvents(client, os.Args[2:])

	case "web":
		handleWeb(os.Args[2:], defaultSock)

	case "run":
		handleRun(os.Args[2:], defaultSock)

	case "help", "--help", "-h":
		printUsage(os.Stdout)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage(os.Stdout)
		os.Exit(1)
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "Commands: list, interfaces, assign, reset, block, unblock, switch, rules, policy, quota, dns, status, events, web, run")
}

func renderProcessList(out io.Writer, procs []types.ProcessInfo) {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tAPP\tINTERFACE/PROFILE\tPOLICY\tRATE CAP\tDOWN\tUP\tUSED\tSTATUS")
	for _, p := range procs {
		iface := p.AssignedInterface
		switch {
		case p.Profile != "" && iface != "" && iface != "blocked":
			iface = fmt.Sprintf("%s (%s)", iface, p.Profile)
		case p.Profile != "":
			iface = p.Profile
		case iface == "":
			iface = "(default)"
		}
		pol := p.Policy
		if pol == "" {
			pol = "-"
		}
		rateCap := "unlimited"
		if p.RateLimitBps > 0 {
			rateCap = telemetry.FormatRate(float64(p.RateLimitBps))
		}
		status := "active"
		if p.Blocked {
			status = "[BLOCKED]"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			p.PID,
			p.Name,
			iface,
			pol,
			rateCap,
			telemetry.FormatRate(p.RxRate),
			telemetry.FormatRate(p.TxRate),
			telemetry.FormatBytes(p.RxBytes+p.TxBytes),
			status,
		)
	}
	_ = w.Flush()
}

func renderInterfaceList(out io.Writer, ifaces []types.InterfaceInfo) {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tIP\tGATEWAY\tTABLE\tHEALTH/RTT/LOSS\tQUOTA\tDNS")
	for _, iface := range ifaces {
		name := iface.Name
		if iface.IsTunnel {
			name += " [VPN]"
		}
		gw := iface.Gateway
		if gw == "" {
			gw = "-"
		}
		health := "UP"
		if !iface.Healthy {
			health = fmt.Sprintf("DOWN (%.0f%% loss)", iface.PacketLoss)
		} else if iface.LatencyMs > 0 || iface.PacketLoss > 0 {
			health = fmt.Sprintf("UP %.1fms (%.0f%% loss)", iface.LatencyMs, iface.PacketLoss)
		}
		quotaStr := "unmetered"
		if iface.DailyQuotaBytes > 0 {
			quotaStr = fmt.Sprintf("%s/%s", telemetry.FormatBytes(iface.DailyUsedBytes), telemetry.FormatBytes(iface.DailyQuotaBytes))
			if iface.QuotaExceeded {
				quotaStr += " [EXCEEDED]"
			}
		} else if iface.Metered {
			quotaStr = "metered"
		}
		dnsStr := "-"
		if len(iface.DNSServers) > 0 {
			dnsStr = strings.Join(iface.DNSServers, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			name, iface.IP, gw, iface.TableID, health, quotaStr, dnsStr)
	}
	_ = w.Flush()
}
