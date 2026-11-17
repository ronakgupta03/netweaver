// cmd/netweaver/run.go
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

func handleRun(args []string, sockPath string) {
	client := api.NewClient(sockPath)
	code := runCommand(args, os.Stdin, os.Stdout, os.Stderr, client.AssignRouteWithOpts)
	if code != 0 {
		os.Exit(code)
	}
}

func runCommand(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	assignFn func(pid int, iface, policy string, rateLimitBps uint64) error,
) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	iface := fs.String("i", "", "Network interface or virtual profile to bind (e.g. wlan0, eno1, @low-latency)")
	strict := fs.Bool("strict", false, "Enforce strict kill-switch policy")
	failoverFlag := fs.Bool("failover", false, "Use failover policy")
	rateStr := fs.String("rate", "", "Egress rate limit (e.g. 500KB, 1MiB/s)")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *strict && *failoverFlag {
		fmt.Fprintln(stderr, "Error: cannot specify both --strict and --failover")
		return 1
	}

	cmdArgs := fs.Args()
	if *iface == "" || len(cmdArgs) == 0 {
		fmt.Fprintln(stderr, "Usage: netweaver run -i <interface|@profile> [--strict|--failover] [--rate <rate>] <command> [args...]")
		return 1
	}

	policyStr := ""
	if *strict {
		policyStr = types.PolicyStrict
	} else if *failoverFlag {
		policyStr = types.PolicyFailover
	}

	var rateBps uint64
	if *rateStr != "" {
		var err error
		rateBps, err = ParseRateLimit(*rateStr)
		if err != nil {
			fmt.Fprintf(stderr, "Error: invalid --rate %q: %v\n", *rateStr, err)
			return 1
		}
	}

	// Zero-leak first-packet launch: move this wrapper process into the target
	// cgroup BEFORE spawning the child so socket #1 inherits the binding.
	if err := assignFn(os.Getpid(), *iface, policyStr, rateBps); err != nil {
		fmt.Fprintf(stderr, "Error: failed to attach route before launch: %v\n", err)
		return 1
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "Failed to start process: %v\n", err)
		return 1
	}

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				return 128 + int(status.Signal())
			}
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "Process wait error: %v\n", err)
		return 1
	}
	return 0
}
