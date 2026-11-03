// cmd/netweaver/run.go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"netweaver/internal/api"
)

func handleRun(args []string, sockPath string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	iface := fs.String("i", "", "Network interface to bind (e.g. wlan0, eno1)")
	_ = fs.Parse(args)

	cmdArgs := fs.Args()
	if *iface == "" || len(cmdArgs) == 0 {
		fmt.Println("Usage: netweaver run -i <interface> <command> [args...]")
		os.Exit(1)
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start process: %v\n", err)
		os.Exit(1)
	}

	client := api.NewClient(sockPath)
	if err := client.AssignRoute(cmd.Process.Pid, *iface); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to attach route: %v\n", err)
	}

	_ = cmd.Wait()
}
