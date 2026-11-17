// cmd/netweaver/rules.go
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"netweaver/internal/api"
	"netweaver/internal/telemetry"
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
		renderRulesList(os.Stdout, list)

	case "add":
		rule, err := parseRuleAddArgs(args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
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

func renderRulesList(out io.Writer, list []types.Rule) {
	if len(list) == 0 {
		fmt.Fprintln(out, "No auto-routing rules defined.")
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "MATCH\tINTERFACE\tPOLICY\tRATE CAP\tBACKGROUND\tDOMAINS")
	for _, r := range list {
		rate := "unlimited"
		if r.RateLimitBps > 0 {
			rate = telemetry.FormatRate(float64(r.RateLimitBps))
		}
		bg := "no"
		if r.Background {
			bg = "yes"
		}
		domains := "-"
		if len(r.Domains) > 0 {
			domains = strings.Join(r.Domains, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Match, r.Interface, r.NormalizedPolicy(), rate, bg, domains)
	}
	_ = w.Flush()
}
