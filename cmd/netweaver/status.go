// cmd/netweaver/status.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"netweaver/internal/api"
	"netweaver/internal/telemetry"
	"netweaver/internal/types"
)

// WaybarStatus matches the JSON schema expected by Waybar custom modules.
type WaybarStatus struct {
	Text    string `json:"text"`
	Tooltip string `json:"tooltip"`
	Class   string `json:"class"`
}

func handleStatus(client *api.Client, args []string) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	waybar := fs.Bool("waybar", false, "Emit single-line JSON for Waybar custom modules")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	ifaces, ifErr := client.ListInterfaces()
	procs, procErr := client.ListProcesses()
	pol, polErr := client.GetPolicy()

	var connErr error
	if ifErr != nil {
		connErr = ifErr
	} else if procErr != nil {
		connErr = procErr
	} else if polErr != nil {
		connErr = polErr
	}

	if *waybar {
		ws := buildWaybarStatus(ifaces, procs, pol, connErr)
		b, err := json.Marshal(ws)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding waybar JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}

	if connErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", connErr)
		os.Exit(1)
	}
	renderStatusText(os.Stdout, ifaces, procs, pol)
}

func buildWaybarStatus(ifaces []types.InterfaceInfo, procs []types.ProcessInfo, policy string, daemonErr error) WaybarStatus {
	if daemonErr != nil {
		return WaybarStatus{
			Text:    "NetWeaver: offline",
			Tooltip: fmt.Sprintf("netweaverd unreachable: %v", daemonErr),
			Class:   "offline",
		}
	}

	var totalRx, totalTx float64
	var primary string
	var healthyCount, unhealthyCount int
	var anyQuotaWarn, anyQuotaExceeded bool
	tooltipLines := make([]string, 0, len(ifaces)+3)
	if policy == "" {
		policy = types.PolicyFailover
	}
	tooltipLines = append(tooltipLines, fmt.Sprintf("NetWeaver (default policy: %s)", policy))

	for _, iface := range ifaces {
		totalRx += iface.RxRate
		totalTx += iface.TxRate
		if iface.Up && iface.Healthy {
			healthyCount++
			if primary == "" {
				primary = iface.Name
			}
		} else {
			unhealthyCount++
		}
		if iface.QuotaExceeded {
			anyQuotaExceeded = true
		} else if iface.DailyQuotaBytes > 0 && iface.DailyUsedBytes*100 >= iface.DailyQuotaBytes*80 {
			anyQuotaWarn = true
		}

		state := "UP"
		if !iface.Healthy {
			state = "DOWN"
		}
		vpnTag := ""
		if iface.IsTunnel {
			vpnTag = " [VPN]"
		}
		rtt := ""
		if iface.LatencyMs > 0 {
			rtt = fmt.Sprintf(" %.0fms", iface.LatencyMs)
		}
		quotaPart := ""
		if iface.DailyQuotaBytes > 0 {
			quotaPart = fmt.Sprintf(" quota %s/%s", telemetry.FormatBytes(iface.DailyUsedBytes), telemetry.FormatBytes(iface.DailyQuotaBytes))
			if iface.QuotaExceeded {
				quotaPart += " EXCEEDED"
			}
		} else if iface.Metered {
			quotaPart = " [metered]"
		}
		tooltipLines = append(tooltipLines, fmt.Sprintf("  %s%s (%s) %s%s ↓%s ↑%s%s",
			iface.Name, vpnTag, iface.IP, state, rtt,
			telemetry.FormatRate(iface.RxRate), telemetry.FormatRate(iface.TxRate), quotaPart))
	}

	var routedCount, blockedCount, limitedCount int
	for _, p := range procs {
		if p.AssignedInterface != "" || p.Profile != "" {
			routedCount++
		}
		if p.Blocked {
			blockedCount++
		}
		if p.RateLimitBps > 0 {
			limitedCount++
		}
	}
	tooltipLines = append(tooltipLines, fmt.Sprintf("Apps: %d total | %d routed | %d blocked | %d rate-limited",
		len(procs), routedCount, blockedCount, limitedCount))

	class := "ok"
	switch {
	case len(ifaces) == 0 || healthyCount == 0 || anyQuotaExceeded || blockedCount > 0:
		class = "critical"
	case unhealthyCount > 0 || anyQuotaWarn:
		class = "warning"
	}

	text := fmt.Sprintf("NetWeaver: %d routed", routedCount)
	if primary != "" {
		text = fmt.Sprintf("%s ↓%s ↑%s (%d routed)", primary, telemetry.FormatRate(totalRx), telemetry.FormatRate(totalTx), routedCount)
	} else if len(ifaces) == 0 {
		text = "NetWeaver: no uplinks"
	}
	if blockedCount > 0 {
		text += fmt.Sprintf(" [BLK:%d]", blockedCount)
	}

	return WaybarStatus{
		Text:    text,
		Tooltip: strings.Join(tooltipLines, "\n"),
		Class:   class,
	}
}

func renderStatusText(out io.Writer, ifaces []types.InterfaceInfo, procs []types.ProcessInfo, policy string) {
	ws := buildWaybarStatus(ifaces, procs, policy, nil)
	fmt.Fprintln(out, ws.Tooltip)
}
