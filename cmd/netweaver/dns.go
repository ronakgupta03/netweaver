// cmd/netweaver/dns.go
package main

import (
	"fmt"
	"os"
	"strings"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

func handleDNS(client *api.Client, args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: netweaver dns <set|get> [args]")
		os.Exit(1)
	}

	switch args[0] {
	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: netweaver dns set <iface> <ip1,ip2|clear>")
			os.Exit(1)
		}
		iface := strings.TrimSpace(args[1])
		if !types.ValidInterfaceName(iface) {
			fmt.Fprintf(os.Stderr, "Invalid interface name: %s\n", iface)
			os.Exit(1)
		}
		servers, err := parseDNSServersArg(args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := client.SetInterfaceDNS(iface, servers); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(servers) == 0 {
			fmt.Printf("Cleared DNS override for %s\n", iface)
		} else {
			fmt.Printf("DNS for %s set to %s\n", iface, strings.Join(servers, ", "))
		}

	case "get":
		if len(args) < 2 {
			fmt.Println("Usage: netweaver dns get <iface>")
			os.Exit(1)
		}
		ifaceName := strings.TrimSpace(args[1])
		ifaces, err := client.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, info := range ifaces {
			if info.Name == ifaceName {
				if len(info.DNSServers) == 0 {
					fmt.Printf("%s: (none)\n", ifaceName)
				} else {
					fmt.Printf("%s: %s\n", ifaceName, strings.Join(info.DNSServers, ", "))
				}
				return
			}
		}
		fmt.Fprintf(os.Stderr, "Interface %q not found\n", ifaceName)
		os.Exit(1)

	default:
		fmt.Printf("Unknown dns command: %s\n", args[0])
		fmt.Println("Usage: netweaver dns <set|get> [args]")
		os.Exit(1)
	}
}
