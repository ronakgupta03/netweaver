// cmd/netweaver/web.go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"netweaver/internal/web"
)

func handleWeb(args []string, sockPath string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8088", "HTTP listen address")
	open := fs.Bool("open", false, "open the dashboard in the default browser")
	_ = fs.Parse(args)

	srv := web.NewServer(*addr, sockPath)
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	url := "http://" + srv.Addr()
	if strings.HasPrefix(srv.Addr(), "0.0.0.0:") {
		url = "http://127.0.0.1:" + strings.TrimPrefix(srv.Addr(), "0.0.0.0:")
	}
	fmt.Printf("NetWeaver dashboard: %s\n", url)
	fmt.Println("Press Ctrl+C to stop.")

	if *open {
		_ = exec.Command("xdg-open", url).Start()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	_ = srv.Stop()
}
