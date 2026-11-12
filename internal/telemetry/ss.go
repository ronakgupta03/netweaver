// internal/telemetry/ss.go
package telemetry

import (
	"bufio"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ProcBytes is cumulative socket byte accounting for a single process.
type ProcBytes struct {
	Rx uint64
	Tx uint64
}

var (
	pidPattern   = regexp.MustCompile(`pid=(\d+)`)
	ackedPattern = regexp.MustCompile(`bytes_acked:(\d+)`)
	recvPattern  = regexp.MustCompile(`bytes_received:(\d+)`)
)

func isLoopbackAddr(addr string) bool {
	return strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "[::1]")
}

// ParseSS extracts per-PID TCP byte counters from `ss -tinpH` output.
//
// A socket record starts with a state keyword line (ESTAB, LISTEN, ...) and is
// followed by indented `-i` info lines carrying bytes_acked / bytes_received.
// Loopback-to-loopback sockets are skipped so the UI reflects real uplink use.
func ParseSS(out string) map[int]ProcBytes {
	res := make(map[int]ProcBytes)
	var pids []int
	var rx, tx uint64
	skip := false

	flush := func() {
		if !skip {
			for _, pid := range pids {
				b := res[pid]
				b.Rx += rx
				b.Tx += tx
				res[pid] = b
			}
		}
		pids = pids[:0]
		rx, tx = 0, 0
		skip = false
	}

	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			// New socket record: state recv-q send-q local peer [process]
			flush()
			fields := strings.Fields(line)
			if len(fields) >= 5 && isLoopbackAddr(fields[3]) && isLoopbackAddr(fields[4]) {
				skip = true
				continue
			}
			for _, m := range pidPattern.FindAllStringSubmatch(line, -1) {
				if pid, err := strconv.Atoi(m[1]); err == nil {
					pids = append(pids, pid)
				}
			}
			continue
		}
		if m := ackedPattern.FindStringSubmatch(line); m != nil {
			if v, err := strconv.ParseUint(m[1], 10, 64); err == nil && v > tx {
				tx = v
			}
		}
		if m := recvPattern.FindStringSubmatch(line); m != nil {
			if v, err := strconv.ParseUint(m[1], 10, 64); err == nil && v > rx {
				rx = v
			}
		}
	}
	flush()
	return res
}

// collectProcessBytes samples all TCP sockets on the host.
func collectProcessBytes() (map[int]ProcBytes, error) {
	out, err := exec.Command("ss", "-tinpH").Output()
	if err != nil {
		return nil, err
	}
	return ParseSS(string(out)), nil
}
