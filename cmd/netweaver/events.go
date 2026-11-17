// cmd/netweaver/events.go
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

func handleEvents(client *api.Client, args []string) {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	follow := fs.Bool("follow", false, "Stream new events continuously")
	notify := fs.Bool("notify", false, "Send desktop notifications for events via notify-send")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	evs, err := client.ListEvents(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var lastID uint64
	for _, ev := range evs {
		fmt.Fprintln(os.Stdout, formatEventLine(ev))
		if ev.ID > lastID {
			lastID = ev.ID
		}
		if *notify && !*follow {
			notifyEventDesktop(ev)
		}
	}

	if !*follow {
		if len(evs) == 0 {
			fmt.Println("No events recorded.")
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			batch, err := client.ListEvents(lastID)
			if err != nil {
				continue
			}
			for _, ev := range batch {
				fmt.Fprintln(os.Stdout, formatEventLine(ev))
				if ev.ID > lastID {
					lastID = ev.ID
				}
				if *notify {
					notifyEventDesktop(ev)
				}
			}
		}
	}
}

func formatEventLine(ev types.Event) string {
	ts := "-"
	if ev.Timestamp > 0 {
		ts = time.Unix(ev.Timestamp, 0).Format("15:04:05")
	}
	var meta []string
	if ev.App != "" {
		meta = append(meta, ev.App)
	}
	if ev.PID > 0 {
		meta = append(meta, fmt.Sprintf("pid=%d", ev.PID))
	}
	if ev.FromInterface != "" && ev.Interface != "" {
		meta = append(meta, fmt.Sprintf("%s->%s", ev.FromInterface, ev.Interface))
	} else if ev.Interface != "" {
		meta = append(meta, ev.Interface)
	}
	if ev.Policy != "" {
		meta = append(meta, ev.Policy)
	}
	metaStr := ""
	if len(meta) > 0 {
		metaStr = " [" + strings.Join(meta, " ") + "]"
	}
	return fmt.Sprintf("#%-4d %s %-14s%s %s", ev.ID, ts, strings.ToUpper(ev.Type), metaStr, ev.Message)
}

func renderEvents(out io.Writer, evs []types.Event) {
	for _, ev := range evs {
		fmt.Fprintln(out, formatEventLine(ev))
	}
}

var eventNotifyExec = func(title, body string) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return
	}
	bin, err := exec.LookPath("notify-send")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, bin, "-a", "NetWeaver", title, body).Run()
}

func notifyEventDesktop(ev types.Event) {
	title := fmt.Sprintf("NetWeaver: %s", ev.Type)
	eventNotifyExec(title, ev.Message)
}
