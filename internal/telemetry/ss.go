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

// SocketInfo describes an active socket parsed from `ss` output.
type SocketInfo struct {
	Proto      string
	State      string
	LocalAddr  string
	RemoteAddr string
	PID        int
	RxBytes    uint64
	TxBytes    uint64
}

var (
	pidPattern   = regexp.MustCompile(`pid=(\d+)`)
	ackedPattern = regexp.MustCompile(`bytes_acked:(\d+)`)
	recvPattern  = regexp.MustCompile(`bytes_received:(\d+)`)
)

func isLoopbackAddr(addr string) bool {
	return strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "[::1]")
}

func socketAddrIndices(fields []string) (localIdx, peerIdx int, proto, state string) {
	if len(fields) > 0 {
		switch fields[0] {
		case "tcp", "udp", "mptcp", "sctp", "dccp", "raw", "icmp", "icmp6", "u_str", "u_dgr", "u_seq":
			st := ""
			if len(fields) > 1 {
				st = fields[1]
			}
			return 4, 5, fields[0], st
		}
	}
	st := ""
	if len(fields) > 0 {
		st = fields[0]
	}
	return 3, 4, "", st
}

func isQUICEndpoint(addr string) bool {
	return strings.HasSuffix(addr, ":443") || strings.HasSuffix(addr, ":8443")
}

// ParseSS extracts per-PID socket byte counters from `ss -tinpH` (or `ss -tuinpH` /
// `ss -tuainpH`) output.
//
// A socket record starts with a state (or netid + state) header line and is
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
			// New socket record: [netid] state recv-q send-q local peer [process]
			flush()
			fields := strings.Fields(line)
			localIdx, peerIdx, _, _ := socketAddrIndices(fields)
			if len(fields) > peerIdx && isLoopbackAddr(fields[localIdx]) && isLoopbackAddr(fields[peerIdx]) {
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

// ParseSSSockets extracts TCP, UDP, and QUIC socket records (per PID) from
// `ss` output (`ss -tinpH`, `ss -tuinpH`, `ss -tuainpH`, or `ss -uanpH`).
func ParseSSSockets(out string) []SocketInfo {
	var sockets []SocketInfo
	var pids []int
	var proto, state, localAddr, remoteAddr string
	var rx, tx uint64
	skip := false

	flush := func() {
		if !skip && len(pids) > 0 {
			p := proto
			if p == "udp" && (isQUICEndpoint(remoteAddr) || isQUICEndpoint(localAddr)) {
				p = "quic"
			}
			for _, pid := range pids {
				sockets = append(sockets, SocketInfo{
					Proto:      p,
					State:      state,
					LocalAddr:  localAddr,
					RemoteAddr: remoteAddr,
					PID:        pid,
					RxBytes:    rx,
					TxBytes:    tx,
				})
			}
		}
		pids = pids[:0]
		proto, state, localAddr, remoteAddr = "", "", "", ""
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
			flush()
			fields := strings.Fields(line)
			localIdx, peerIdx, netid, st := socketAddrIndices(fields)
			if len(fields) > peerIdx {
				localAddr = fields[localIdx]
				remoteAddr = fields[peerIdx]
				if isLoopbackAddr(localAddr) && isLoopbackAddr(remoteAddr) {
					skip = true
					continue
				}
			}
			state = st
			if netid != "" {
				proto = netid
			} else if st == "UNCONN" {
				proto = "udp"
			} else {
				proto = "tcp"
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
	return sockets
}

// collectProcessBytes samples TCP and connected/active UDP sockets on the host.
func collectProcessBytes() (map[int]ProcBytes, error) {
	out, err := exec.Command("ss", "-tuainpH").Output()
	if err != nil {
		out, err = exec.Command("ss", "-tinpH").Output()
		if err != nil {
			return nil, err
		}
	}
	return ParseSS(string(out)), nil
}

// CollectSockets samples active TCP and UDP/QUIC sockets on the host.
func CollectSockets() ([]SocketInfo, error) {
	out, err := exec.Command("ss", "-tuainpH").Output()
	if err != nil {
		out, err = exec.Command("ss", "-tinpH").Output()
		if err != nil {
			return nil, err
		}
	}
	return ParseSSSockets(string(out)), nil
}
