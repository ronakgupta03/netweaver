// cmd/netweaver/main.go
package main

import (
	"fmt"
	"os"
	"strconv"

	"netweaver/internal/api"
	"netweaver/internal/tui"
)

const defaultSock = "/run/netweaver/netweaver.sock"

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
		fmt.Printf("%-8s %-25s %-15s\n", "PID", "NAME", "INTERFACE")
		fmt.Println("--------------------------------------------------")
		for _, p := range procs {
			iface := p.AssignedInterface
			if iface == "" {
				iface = "(default)"
			}
			fmt.Printf("%-8d %-25s %-15s\n", p.PID, p.Name, iface)
		}

	case "interfaces":
		ifaces, err := client.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%-10s %-5s %-18s %-18s %-8s\n", "NAME", "INDEX", "IP", "GATEWAY", "TABLE")
		fmt.Println("-----------------------------------------------------------------")
		for _, iface := range ifaces {
			fmt.Printf("%-10s %-5d %-18s %-18s %-8d\n", iface.Name, iface.Index, iface.IP, iface.Gateway, iface.TableID)
		}

	case "assign":
		if len(os.Args) < 4 {
			fmt.Println("Usage: netweaver assign <PID> <INTERFACE>")
			os.Exit(1)
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil || pid <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid PID: %s\n", os.Args[2])
			os.Exit(1)
		}
		if err := client.AssignRoute(pid, os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Assigned PID %d to interface %s\n", pid, os.Args[3])

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

	case "run":
		handleRun(os.Args[2:], defaultSock)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Commands: list, interfaces, assign, reset, run")
	}
}
