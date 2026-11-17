// cmd/netweaver/quota.go
package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"netweaver/internal/api"
	"netweaver/internal/telemetry"
	"netweaver/internal/types"
)

func handleQuota(client *api.Client, args []string) {
	if len(args) == 0 {
		list, err := client.ListQuotas()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		renderQuotaList(os.Stdout, list)
		return
	}

	switch args[0] {
	case "list":
		list, err := client.ListQuotas()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		renderQuotaList(os.Stdout, list)

	case "set":
		cfg, err := parseQuotaSetArgs(args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := client.SetQuota(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Quota set on %s: daily limit %s (warn %d%%, metered=%v)\n",
			cfg.Interface, telemetry.FormatBytes(cfg.DailyLimitBytes), cfg.WarnPercent, cfg.Metered)

	case "remove", "rm":
		if len(args) < 2 {
			fmt.Println("Usage: netweaver quota remove <iface>")
			os.Exit(1)
		}
		if err := client.RemoveQuota(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Quota removed for %s\n", args[1])

	default:
		fmt.Printf("Unknown quota command: %s\n", args[0])
		fmt.Println("Usage: netweaver quota <list|set|remove> [args]")
		os.Exit(1)
	}
}

func renderQuotaList(out io.Writer, list []types.QuotaConfig) {
	if len(list) == 0 {
		fmt.Fprintln(out, "No interface quotas configured.")
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "INTERFACE\tMETERED\tUSED\tLIMIT\tWARN %\tSTATUS")
	for _, q := range list {
		metered := "no"
		if q.Metered {
			metered = "yes"
		}
		warn := q.WarnPercent
		if warn <= 0 {
			warn = 80
		}
		status := "ok"
		if q.DailyLimitBytes > 0 {
			if q.UsedBytes >= q.DailyLimitBytes {
				status = "EXCEEDED"
			} else if q.UsedBytes*100 >= q.DailyLimitBytes*uint64(warn) {
				status = "WARNING"
			}
		}
		limitStr := "unlimited"
		if q.DailyLimitBytes > 0 {
			limitStr = telemetry.FormatBytes(q.DailyLimitBytes)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d%%\t%s\n",
			q.Interface, metered, telemetry.FormatBytes(q.UsedBytes), limitStr, warn, status)
	}
	_ = w.Flush()
}
