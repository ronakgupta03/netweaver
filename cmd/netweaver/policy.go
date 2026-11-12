// cmd/netweaver/policy.go
package main

import (
	"fmt"
	"os"

	"netweaver/internal/api"
)

func handlePolicy(client *api.Client, args []string) {
	if len(args) == 0 {
		p, err := client.GetPolicy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Default policy: %s\n", p)
		fmt.Println("  failover - move traffic to the best remaining interface")
		fmt.Println("  strict   - block traffic (kill-switch) instead of leaking")
		return
	}

	if args[0] == "set" {
		if len(args) < 2 {
			fmt.Println("Usage: netweaver policy set <failover|strict>")
			os.Exit(1)
		}
		p, err := client.SetPolicy(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Default policy set to %s\n", p)
		return
	}

	fmt.Printf("Unknown policy command: %s\n", args[0])
	fmt.Println("Usage: netweaver policy [set <failover|strict>]")
	os.Exit(1)
}
