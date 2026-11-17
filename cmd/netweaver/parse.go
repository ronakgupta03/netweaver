// cmd/netweaver/parse.go
package main

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode"

	"netweaver/internal/types"
)

// ParseByteSize parses human-readable byte quantities such as "500KB", "1.5GB",
// "2GiB", "256K", or plain byte counts.
func ParseByteSize(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("byte size cannot be empty")
	}

	splitIdx := len(s)
	for i, r := range s {
		if !unicode.IsDigit(r) && r != '.' && r != '+' && r != '-' {
			splitIdx = i
			break
		}
	}

	numPart := strings.TrimSpace(s[:splitIdx])
	unitPart := strings.ToLower(strings.TrimSpace(s[splitIdx:]))
	if numPart == "" {
		return 0, fmt.Errorf("invalid byte size %q", raw)
	}

	val, err := strconv.ParseFloat(numPart, 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val < 0 {
		return 0, fmt.Errorf("invalid byte size %q", raw)
	}

	var mult float64
	switch unitPart {
	case "", "b":
		mult = 1
	case "k", "ki", "kib":
		mult = 1024
	case "kb":
		mult = 1000
	case "m", "mi", "mib":
		mult = 1024 * 1024
	case "mb":
		mult = 1000 * 1000
	case "g", "gi", "gib":
		mult = 1024 * 1024 * 1024
	case "gb":
		mult = 1000 * 1000 * 1000
	case "t", "ti", "tib":
		mult = 1024 * 1024 * 1024 * 1024
	case "tb":
		mult = 1000 * 1000 * 1000 * 1000
	case "p", "pi", "pib":
		mult = 1024 * 1024 * 1024 * 1024 * 1024
	case "pb":
		mult = 1000 * 1000 * 1000 * 1000 * 1000
	default:
		return 0, fmt.Errorf("unknown byte size unit %q in %q", unitPart, raw)
	}

	bytesFloat := val * mult
	if bytesFloat > float64(math.MaxUint64) {
		return 0, fmt.Errorf("byte size %q overflows uint64", raw)
	}
	return uint64(math.Round(bytesFloat)), nil
}

// ParseRateLimit parses human-readable rate limits such as "256KiB/s", "1MB",
// "1.5GiB/s", "0", or "unlimited".
func ParseRateLimit(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "unlimited") || strings.EqualFold(s, "none") {
		return 0, nil
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasSuffix(lower, "/sec"):
		s = strings.TrimSpace(s[:len(s)-4])
	case strings.HasSuffix(lower, "/s"):
		s = strings.TrimSpace(s[:len(s)-2])
	}
	return ParseByteSize(s)
}

type assignOpts struct {
	pid          int
	target       string
	policy       string
	rateLimitBps uint64
}

func parseAssignArgs(args []string) (assignOpts, error) {
	var pos []string
	var strictFlag, failoverFlag bool
	var rateStr string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--strict" || arg == "-strict":
			strictFlag = true
		case arg == "--failover" || arg == "-failover":
			failoverFlag = true
		case arg == "--rate" || arg == "-rate":
			if i+1 >= len(args) {
				return assignOpts{}, errors.New("--rate requires a value")
			}
			i++
			rateStr = args[i]
		case strings.HasPrefix(arg, "--rate="):
			rateStr = strings.TrimPrefix(arg, "--rate=")
		case strings.HasPrefix(arg, "-rate="):
			rateStr = strings.TrimPrefix(arg, "-rate=")
		case strings.HasPrefix(arg, "-"):
			return assignOpts{}, fmt.Errorf("unknown flag %q", arg)
		default:
			pos = append(pos, arg)
		}
	}

	if strictFlag && failoverFlag {
		return assignOpts{}, errors.New("cannot specify both --strict and --failover")
	}
	if len(pos) < 2 || len(pos) > 3 {
		return assignOpts{}, errors.New("Usage: netweaver assign <PID> <INTERFACE|@profile> [failover|strict] [--strict|--failover] [--rate <rate>]")
	}

	pid, err := strconv.Atoi(pos[0])
	if err != nil || pid <= 0 {
		return assignOpts{}, fmt.Errorf("invalid PID: %s", pos[0])
	}
	target := strings.TrimSpace(pos[1])
	if !types.IsVirtualProfile(target) && !types.ValidInterfaceName(target) {
		return assignOpts{}, fmt.Errorf("invalid interface or virtual profile %q", target)
	}

	var pol string
	if strictFlag {
		pol = types.PolicyStrict
	} else if failoverFlag {
		pol = types.PolicyFailover
	}
	if len(pos) == 3 {
		posPol := strings.ToLower(strings.TrimSpace(pos[2]))
		if posPol != types.PolicyFailover && posPol != types.PolicyStrict {
			return assignOpts{}, fmt.Errorf("unknown policy %q (use failover or strict)", pos[2])
		}
		if pol != "" && pol != posPol {
			return assignOpts{}, fmt.Errorf("conflicting policy %q and flag %q", posPol, pol)
		}
		pol = posPol
	}

	var rateBps uint64
	if rateStr != "" {
		rateBps, err = ParseRateLimit(rateStr)
		if err != nil {
			return assignOpts{}, fmt.Errorf("invalid rate %q: %w", rateStr, err)
		}
	}

	return assignOpts{
		pid:          pid,
		target:       target,
		policy:       pol,
		rateLimitBps: rateBps,
	}, nil
}

func parseRuleAddArgs(args []string) (types.Rule, error) {
	var pos []string
	var strictFlag, failoverFlag, background bool
	var domainsRaw, rateStr string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--background" || arg == "-background":
			background = true
		case arg == "--strict" || arg == "-strict":
			strictFlag = true
		case arg == "--failover" || arg == "-failover":
			failoverFlag = true
		case arg == "--domains" || arg == "-domains":
			if i+1 >= len(args) {
				return types.Rule{}, errors.New("--domains requires a comma-separated list")
			}
			i++
			domainsRaw = args[i]
		case strings.HasPrefix(arg, "--domains="):
			domainsRaw = strings.TrimPrefix(arg, "--domains=")
		case strings.HasPrefix(arg, "-domains="):
			domainsRaw = strings.TrimPrefix(arg, "-domains=")
		case arg == "--rate" || arg == "-rate":
			if i+1 >= len(args) {
				return types.Rule{}, errors.New("--rate requires a value")
			}
			i++
			rateStr = args[i]
		case strings.HasPrefix(arg, "--rate="):
			rateStr = strings.TrimPrefix(arg, "--rate=")
		case strings.HasPrefix(arg, "-rate="):
			rateStr = strings.TrimPrefix(arg, "-rate=")
		case strings.HasPrefix(arg, "-"):
			return types.Rule{}, fmt.Errorf("unknown flag %q", arg)
		default:
			pos = append(pos, arg)
		}
	}

	if strictFlag && failoverFlag {
		return types.Rule{}, errors.New("cannot specify both --strict and --failover")
	}
	if len(pos) < 2 || len(pos) > 3 {
		return types.Rule{}, errors.New("Usage: netweaver rules add <match> <interface|@profile> [failover|strict] [--domains d1,d2] [--rate <rate>] [--background]")
	}

	pol := ""
	if strictFlag {
		pol = types.PolicyStrict
	} else if failoverFlag {
		pol = types.PolicyFailover
	}
	if len(pos) == 3 {
		posPol := strings.ToLower(strings.TrimSpace(pos[2]))
		if posPol != types.PolicyFailover && posPol != types.PolicyStrict {
			return types.Rule{}, fmt.Errorf("unknown policy %q (use failover or strict)", pos[2])
		}
		if pol != "" && pol != posPol {
			return types.Rule{}, fmt.Errorf("conflicting policy %q and flag %q", posPol, pol)
		}
		pol = posPol
	}

	var rateBps uint64
	if rateStr != "" {
		var err error
		rateBps, err = ParseRateLimit(rateStr)
		if err != nil {
			return types.Rule{}, fmt.Errorf("invalid rate %q: %w", rateStr, err)
		}
	}

	var domains []string
	if domainsRaw != "" {
		for _, d := range strings.Split(domainsRaw, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domains = append(domains, d)
			}
		}
	}

	return types.Rule{
		Match:        pos[0],
		Interface:    pos[1],
		Policy:       pol,
		Domains:      domains,
		RateLimitBps: rateBps,
		Background:   background,
	}, nil
}

func parseQuotaSetArgs(args []string) (types.QuotaConfig, error) {
	var pos []string
	var metered bool
	warnPct := 80

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--metered" || arg == "-metered":
			metered = true
		case arg == "--warn" || arg == "-warn":
			if i+1 >= len(args) {
				return types.QuotaConfig{}, errors.New("--warn requires an integer percentage")
			}
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil || v <= 0 || v > 100 {
				return types.QuotaConfig{}, fmt.Errorf("invalid --warn percent %q (1-100)", args[i])
			}
			warnPct = v
		case strings.HasPrefix(arg, "--warn="):
			raw := strings.TrimPrefix(arg, "--warn=")
			v, err := strconv.Atoi(raw)
			if err != nil || v <= 0 || v > 100 {
				return types.QuotaConfig{}, fmt.Errorf("invalid --warn percent %q (1-100)", raw)
			}
			warnPct = v
		case strings.HasPrefix(arg, "-warn="):
			raw := strings.TrimPrefix(arg, "-warn=")
			v, err := strconv.Atoi(raw)
			if err != nil || v <= 0 || v > 100 {
				return types.QuotaConfig{}, fmt.Errorf("invalid --warn percent %q (1-100)", raw)
			}
			warnPct = v
		case strings.HasPrefix(arg, "-"):
			return types.QuotaConfig{}, fmt.Errorf("unknown flag %q", arg)
		default:
			pos = append(pos, arg)
		}
	}

	if len(pos) != 2 {
		return types.QuotaConfig{}, errors.New("Usage: netweaver quota set <iface> <limit> [--warn 80] [--metered]")
	}
	iface := strings.TrimSpace(pos[0])
	if !types.ValidInterfaceName(iface) {
		return types.QuotaConfig{}, fmt.Errorf("invalid interface name %q", iface)
	}
	limitBytes, err := ParseByteSize(pos[1])
	if err != nil {
		return types.QuotaConfig{}, fmt.Errorf("invalid quota limit %q: %w", pos[1], err)
	}

	return types.QuotaConfig{
		Interface:       iface,
		Metered:         metered,
		DailyLimitBytes: limitBytes,
		WarnPercent:     warnPct,
	}, nil
}

func parseDNSServersArg(raw string) ([]string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "none") || strings.EqualFold(s, "clear") {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if ip := net.ParseIP(p); ip == nil {
			host, _, err := net.SplitHostPort(p)
			if err != nil || net.ParseIP(host) == nil {
				return nil, fmt.Errorf("invalid DNS IP %q", p)
			}
		}
		out = append(out, p)
	}
	return out, nil
}
