// cmd/netweaver/rules.go
package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

func handleRules(client *api.Client, args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: netweaver rules <list|add|remove|clear> [args]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		list, err := client.ListRules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(list) == 0 {
			fmt.Println("No auto-routing rules defined.")
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "MATCH\tINTERFACE\tPOLICY")
		for _, r := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Match, r.Interface, r.NormalizedPolicy())
		}
		_ = w.Flush()

	case "add":
		if len(args) < 3 {
			fmt.Println("Usage: netweaver rules add <match> <interface> [failover|strict]")
			os.Exit(1)
		}
		rule := types.Rule{Match: args[1], Interface: args[2]}
		if len(args) > 3 {
			rule.Policy = args[3]
		}
		if err := client.AddRule(rule); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Rule saved: %s -> %s [%s]\n", rule.Match, rule.Interface, rule.NormalizedPolicy())

	case "remove", "rm":
		if len(args) < 2 {
			fmt.Println("Usage: netweaver rules remove <match>")
			os.Exit(1)
		}
		if err := client.RemoveRule(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Rule removed: %s\n", args[1])

	case "clear":
		list, err := client.ListRules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, r := range list {
			if err := client.RemoveRule(r.Match); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Printf("Cleared %d rule(s)\n", len(list))

	default:
		fmt.Printf("Unknown rules command: %s\n", args[0])
		fmt.Println("Commands: list, add, remove, clear")
		os.Exit(1)
	}
}
