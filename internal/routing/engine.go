// internal/routing/engine.go
package routing

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"netweaver/internal/cgroups"
	"netweaver/internal/types"
)

const nftTemplate = `
table inet netweaver {
{{- range .Sets }}
    set {{ .SetName }} {
        type {{ .AddrType }}
        flags interval
        auto-merge
        elements = { {{ .Elements }} }
    }
{{- end }}
    chain output {
        type route hook output priority mangle; policy accept;
{{- if .Marking }}
{{- if .Blocked }}
        socket cgroupv2 level 2 "netweaver/{{ .BlockedName }}" drop
{{- end }}
{{- range .Ifaces }}
        socket cgroupv2 level 2 "netweaver/{{ .Name }}" meta mark set 0x{{ printf "%x" .TableID }}
{{- end }}
{{- end }}
{{- range .DstRules }}
        {{ .Family }} daddr @{{ .SetName }} meta mark set 0x{{ printf "%x" .TableID }}
{{- end }}
    }
{{- if .DNSRules }}

    chain output_nat {
        type nat hook output priority dstnat; policy accept;
{{- range .DNSRules }}
        {{ .Family }} daddr != {{ .AddrExpr }} meta mark 0x{{ printf "%x" .TableID }} udp dport 53 dnat {{ .Family }} to {{ .TargetIP }}
        {{ .Family }} daddr != {{ .AddrExpr }} meta mark 0x{{ printf "%x" .TableID }} tcp dport 53 dnat {{ .Family }} to {{ .TargetIP }}
{{- end }}
    }
{{- end }}

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
{{- range .Ifaces }}
        oifname "{{ .Name }}" meta mark 0x{{ printf "%x" .TableID }} masquerade
{{- end }}
    }
}
`

type dstSetData struct {
	SetName  string
	AddrType string
	Elements string
}

type dstMarkRule struct {
	Family  string
	SetName string
	TableID int
}

type dnsNatRule struct {
	Family   string
	AddrExpr string
	TargetIP string
	TableID  int
}

type rulesetData struct {
	Ifaces      []types.InterfaceInfo
	Marking     bool
	Blocked     bool
	BlockedName string
	Sets        []dstSetData
	DstRules    []dstMarkRule
	DNSRules    []dnsNatRule
}

type resolvedDst struct {
	v4 []string
	v6 []string
}

func renderRuleset(data rulesetData) string {
	tmpl, err := template.New("nft").Parse(nftTemplate)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return ""
	}
	return buf.String()
}

// GenerateNftablesRuleset renders the full ruleset for the given interfaces.
func GenerateNftablesRuleset(ifaces []types.InterfaceInfo) string {
	dnsMap := make(map[string][]string, len(ifaces))
	for _, iface := range ifaces {
		if cleaned := cleanDNSServers(iface.DNSServers); len(cleaned) > 0 {
			dnsMap[iface.Name] = cleaned
		}
	}
	return renderRuleset(buildRulesetData(ifaces, true, true, dnsMap, nil))
}

// Engine owns policy routing state for every managed interface.
type Engine struct {
	mu            sync.RWMutex
	applyMu       sync.Mutex
	ifaces        map[string]types.InterfaceInfo
	cgroupRoot    string
	marking       bool
	dnsOverrides  map[string][]string
	discoveredDNS map[string][]string
	dstSplits     map[string]resolvedDst

	lookupFn         func(host string) ([]net.IP, error)
	hasGlobalIPv6Fn  func(iface string) bool
	runCmdFn         func(name string, args ...string) error
	runNftFn         func(ruleset string, skipped []string) error
}

func NewEngine() *Engine {
	e := &Engine{
		ifaces:          make(map[string]types.InterfaceInfo),
		cgroupRoot:      "/sys/fs/cgroup",
		marking:         true,
		dnsOverrides:    make(map[string][]string),
		discoveredDNS:   make(map[string][]string),
		dstSplits:       make(map[string]resolvedDst),
		lookupFn:        defaultLookupIP,
		hasGlobalIPv6Fn: defaultHasGlobalIPv6,
	}
	e.runCmdFn = func(name string, args ...string) error {
		return exec.Command(name, args...).Run()
	}
	e.runNftFn = e.defaultApplyNft
	return e
}

func NewEngineWithCgroupRoot(root string) *Engine {
	e := NewEngine()
	e.cgroupRoot = root
	return e
}

func defaultLookupIP(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func defaultHasGlobalIPv6(ifaceName string) bool {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil {
			continue
		}
		if ipNet.IP.To4() == nil && ipNet.IP.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

func (e *Engine) defaultApplyNft(ruleset string, skipped []string) error {
	// Idempotently purge existing table before reapplying to prevent duplicate rules
	_ = e.runCmd("nft", "delete", "table", "inet", "netweaver")

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply failed (skipped cgroups: %v): %s: %w", skipped, string(out), err)
	}
	return nil
}

func (e *Engine) runCmd(name string, args ...string) error {
	if e.runCmdFn != nil {
		return e.runCmdFn(name, args...)
	}
	return exec.Command(name, args...).Run()
}

// CgroupPathExists reports whether the cgroup directory for a name is present.
// nftables resolves cgroupv2 paths when the ruleset is loaded and rejects the
// whole transaction when one is missing, so rules must be filtered first.
func (e *Engine) CgroupPathExists(name string) bool {
	info, err := os.Stat(filepath.Join(e.cgroupRoot, "netweaver", name))
	return err == nil && info.IsDir()
}

// SetInterfaceDNS configures explicit per-interface DNS servers for port-53
// DNAT isolation. Passing nil or an empty slice clears the explicit override.
func (e *Engine) SetInterfaceDNS(iface string, servers []string) {
	if iface == "" {
		return
	}
	cleaned := cleanDNSServers(servers)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dnsOverrides == nil {
		e.dnsOverrides = make(map[string][]string)
	}
	if len(cleaned) == 0 {
		delete(e.dnsOverrides, iface)
		return
	}
	e.dnsOverrides[iface] = cleaned
}

// InterfaceDNS returns the active DNS servers configured for iface (explicit
// override first, otherwise discovered DNS servers from interface telemetry).
func (e *Engine) InterfaceDNS(iface string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return copyStringSlice(e.effectiveDNSLocked(iface))
}

func (e *Engine) effectiveDNSLocked(iface string) []string {
	if ov := e.dnsOverrides[iface]; len(ov) > 0 {
		return ov
	}
	if disc := e.discoveredDNS[iface]; len(disc) > 0 {
		return disc
	}
	if info, ok := e.ifaces[iface]; ok && len(info.DNSServers) > 0 {
		return cleanDNSServers(info.DNSServers)
	}
	return nil
}

// SetLookupFunc overrides the DNS lookup helper used when resolving split-tunnel
// domains into IPv4 and IPv6 addresses.
func (e *Engine) SetLookupFunc(fn func(host string) ([]net.IP, error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if fn == nil {
		e.lookupFn = defaultLookupIP
		return
	}
	e.lookupFn = fn
}

// SetDestinationRules updates per-interface destination IP/CIDR/domain split
// rules from the provided rule slice, replacing previous destination splits.
func (e *Engine) SetDestinationRules(rules []types.Rule) {
	grouped := make(map[string][]string)
	for _, r := range rules {
		iface := strings.TrimSpace(r.Interface)
		if iface == "" || len(r.Domains) == 0 {
			continue
		}
		grouped[iface] = append(grouped[iface], r.Domains...)
	}

	e.mu.RLock()
	lookup := e.lookupFn
	e.mu.RUnlock()
	if lookup == nil {
		lookup = defaultLookupIP
	}

	resolved := make(map[string]resolvedDst, len(grouped))
	for iface, entries := range grouped {
		v4, v6 := resolveDestinationEntries(entries, lookup)
		if len(v4) > 0 || len(v6) > 0 {
			resolved[iface] = resolvedDst{v4: v4, v6: v6}
		}
	}

	e.mu.Lock()
	e.dstSplits = resolved
	e.mu.Unlock()
}

// SetDestinationSplit configures domain/IP/CIDR destination split-tunneling
// targets for a single interface. Passing nil or empty clears the split entry.
func (e *Engine) SetDestinationSplit(iface string, domains []string) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return
	}

	if len(domains) == 0 {
		e.mu.Lock()
		if e.dstSplits != nil {
			delete(e.dstSplits, iface)
		}
		e.mu.Unlock()
		return
	}

	e.mu.RLock()
	lookup := e.lookupFn
	e.mu.RUnlock()
	if lookup == nil {
		lookup = defaultLookupIP
	}

	v4, v6 := resolveDestinationEntries(domains, lookup)

	e.mu.Lock()
	if e.dstSplits == nil {
		e.dstSplits = make(map[string]resolvedDst)
	}
	if len(v4) == 0 && len(v6) == 0 {
		delete(e.dstSplits, iface)
	} else {
		e.dstSplits[iface] = resolvedDst{v4: v4, v6: v6}
	}
	e.mu.Unlock()
}

// DestinationSplit returns copies of the resolved IPv4 and IPv6 destination
// split elements currently stored for iface.
func (e *Engine) DestinationSplit(iface string) (v4 []string, v6 []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	entry := e.dstSplits[iface]
	return copyStringSlice(entry.v4), copyStringSlice(entry.v6)
}

func (e *Engine) buildRuleset() (string, []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.buildRulesetLocked()
}

func (e *Engine) buildRulesetLocked() (string, []string) {
	var list []types.InterfaceInfo
	for _, iface := range e.ifaces {
		list = append(list, iface)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })

	kept := make([]types.InterfaceInfo, 0, len(list))
	var skipped []string
	for _, iface := range list {
		if !e.CgroupPathExists(iface.Name) {
			skipped = append(skipped, iface.Name)
			continue
		}
		kept = append(kept, iface)
	}

	dnsMap := make(map[string][]string, len(kept))
	for _, iface := range kept {
		if servers := e.effectiveDNSLocked(iface.Name); len(servers) > 0 {
			dnsMap[iface.Name] = servers
		}
	}

	data := buildRulesetData(kept, e.marking, e.CgroupPathExists(cgroups.BlockedCgroup), dnsMap, e.dstSplits)
	return renderRuleset(data), skipped
}

func buildRulesetData(
	kept []types.InterfaceInfo,
	marking bool,
	blocked bool,
	dnsMap map[string][]string,
	dstSplits map[string]resolvedDst,
) rulesetData {
	data := rulesetData{
		Ifaces:      kept,
		Marking:     marking,
		Blocked:     blocked,
		BlockedName: cgroups.BlockedCgroup,
	}

	usedSetNames := make(map[string]bool)
	for _, iface := range kept {
		if dst, ok := dstSplits[iface.Name]; ok && (len(dst.v4) > 0 || len(dst.v6) > 0) {
			safe := uniqueSafeName(iface.Name, iface.TableID, usedSetNames)
			if len(dst.v4) > 0 {
				setName := "dst4_" + safe
				data.Sets = append(data.Sets, dstSetData{
					SetName:  setName,
					AddrType: "ipv4_addr",
					Elements: strings.Join(dst.v4, ", "),
				})
				data.DstRules = append(data.DstRules, dstMarkRule{
					Family:  "ip",
					SetName: setName,
					TableID: iface.TableID,
				})
			}
			if len(dst.v6) > 0 {
				setName := "dst6_" + safe
				data.Sets = append(data.Sets, dstSetData{
					SetName:  setName,
					AddrType: "ipv6_addr",
					Elements: strings.Join(dst.v6, ", "),
				})
				data.DstRules = append(data.DstRules, dstMarkRule{
					Family:  "ip6",
					SetName: setName,
					TableID: iface.TableID,
				})
			}
		}

		if servers := dnsMap[iface.Name]; len(servers) > 0 {
			v4, v6 := splitDNSFamilies(servers)
			if len(v4) > 0 {
				data.DNSRules = append(data.DNSRules, dnsNatRule{
					Family:   "ip",
					AddrExpr: formatAddrExpr(v4),
					TargetIP: v4[0],
					TableID:  iface.TableID,
				})
			}
			if len(v6) > 0 {
				data.DNSRules = append(data.DNSRules, dnsNatRule{
					Family:   "ip6",
					AddrExpr: formatAddrExpr(v6),
					TargetIP: v6[0],
					TableID:  iface.TableID,
				})
			}
		}
	}
	return data
}

func uniqueSafeName(iface string, tableID int, used map[string]bool) string {
	var b strings.Builder
	b.Grow(len(iface))
	for _, r := range iface {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	base := b.String()
	if base == "" {
		base = fmt.Sprintf("if_%x", tableID)
	}
	candidate := base
	if used[candidate] {
		candidate = fmt.Sprintf("%s_%x", base, tableID)
	}
	for used[candidate] {
		candidate += "_"
	}
	used[candidate] = true
	return candidate
}

func formatAddrExpr(addrs []string) string {
	if len(addrs) == 1 {
		return addrs[0]
	}
	return "{ " + strings.Join(addrs, ", ") + " }"
}

func splitDNSFamilies(servers []string) (v4 []string, v6 []string) {
	for _, s := range servers {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6
}

func cleanDNSServers(servers []string) []string {
	if len(servers) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(servers))
	out := make([]string, 0, len(servers))
	for _, raw := range servers {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			if host, _, err := net.SplitHostPort(s); err == nil {
				ip = net.ParseIP(host)
			}
		}
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		canon := ip.String()
		if ip4 := ip.To4(); ip4 != nil {
			canon = ip4.String()
		}
		if _, dup := seen[canon]; dup {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func resolveDestinationEntries(entries []string, lookup func(host string) ([]net.IP, error)) (v4 []string, v6 []string) {
	seen4 := make(map[string]struct{})
	seen6 := make(map[string]struct{})
	addV4 := func(s string) {
		if _, ok := seen4[s]; !ok {
			seen4[s] = struct{}{}
			v4 = append(v4, s)
		}
	}
	addV6 := func(s string) {
		if _, ok := seen6[s]; !ok {
			seen6[s] = struct{}{}
			v6 = append(v6, s)
		}
	}

	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			if ipNet.IP.To4() != nil {
				addV4(ipNet.String())
			} else {
				addV6(ipNet.String())
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			if ip.IsUnspecified() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				addV4(ip4.String())
			} else {
				addV6(ip.String())
			}
			continue
		}

		host := strings.ToLower(entry)
		host = strings.TrimPrefix(host, "*.")
		host = strings.TrimSuffix(host, ".")
		if host == "" || strings.Contains(host, "*") || lookup == nil {
			continue
		}
		ips, err := lookup(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				addV4(ip4.String())
			} else {
				addV6(ip.String())
			}
		}
	}

	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

func copyStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// SetMarking selects whether nftables sets packet marks. When the eBPF
// classifier is active, marking lives in the kernel program and nftables only
// keeps NAT rules.
func (e *Engine) SetMarking(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.marking = enabled
}

func (e *Engine) MarkingEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.marking
}

func (e *Engine) infoHasGlobalIPv6(info types.InterfaceInfo) bool {
	if info.IP != "" {
		rawIP := strings.Split(info.IP, "/")[0]
		if ip := net.ParseIP(rawIP); ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() {
			return true
		}
	}
	if e.hasGlobalIPv6Fn != nil {
		return e.hasGlobalIPv6Fn(info.Name)
	}
	return false
}

// buildRouteCommands produces the ordered `ip` / `ip -6` commands for an
// interface routing table and fwmark FIB rules. Gateway-less L3 tunnel
// interfaces receive device-scoped default routes (`default dev <Name>`).
func buildRouteCommands(info types.InterfaceInfo, hasGlobalV6 bool) [][]string {
	table := fmt.Sprintf("%d", info.TableID)
	mark := fmt.Sprintf("0x%x", info.TableID)
	var cmds [][]string

	// 1. IPv4 Route in table
	if info.Gateway != "" {
		cmds = append(cmds, []string{"ip", "route", "replace", "default", "via", info.Gateway, "dev", info.Name, "table", table})
	} else if info.IsTunnel {
		cmds = append(cmds, []string{"ip", "route", "replace", "default", "dev", info.Name, "table", table})
	}

	// 2. IPv6 Route in table (or unreachable to prevent leaking onto other interfaces)
	if info.Gateway6 != "" {
		cmds = append(cmds, []string{"ip", "-6", "route", "replace", "default", "via", info.Gateway6, "dev", info.Name, "table", table})
	} else if info.IsTunnel && hasGlobalV6 {
		cmds = append(cmds, []string{"ip", "-6", "route", "replace", "default", "dev", info.Name, "table", table})
	} else {
		cmds = append(cmds, []string{"ip", "-6", "route", "replace", "unreachable", "default", "table", table})
	}

	// 3. IPv4 FIB rule
	cmds = append(cmds,
		[]string{"ip", "rule", "del", "fwmark", mark, "table", table},
		[]string{"ip", "rule", "add", "fwmark", mark, "table", table, "priority", "1000"},
	)

	// 4. IPv6 FIB rule
	cmds = append(cmds,
		[]string{"ip", "-6", "rule", "del", "fwmark", mark, "table", table},
		[]string{"ip", "-6", "rule", "add", "fwmark", mark, "table", table, "priority", "1000"},
	)

	return cmds
}

func (e *Engine) SetupInterfaceRoute(info types.InterfaceInfo) error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	e.mu.Lock()
	if e.ifaces == nil {
		e.ifaces = make(map[string]types.InterfaceInfo)
	}
	if e.discoveredDNS == nil {
		e.discoveredDNS = make(map[string][]string)
	}
	e.ifaces[info.Name] = info
	if cleaned := cleanDNSServers(info.DNSServers); len(cleaned) > 0 {
		e.discoveredDNS[info.Name] = cleaned
	} else {
		delete(e.discoveredDNS, info.Name)
	}
	hasGlobalV6 := e.infoHasGlobalIPv6(info)
	e.mu.Unlock()

	for _, cmd := range buildRouteCommands(info, hasGlobalV6) {
		_ = e.runCmd(cmd[0], cmd[1:]...)
	}

	return e.applyNftablesLocked()
}

// RemoveInterface drops every route and rule owned by an interface that is no
// longer usable, so its marks cannot blackhole traffic.
func (e *Engine) RemoveInterface(name string) error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	e.mu.Lock()
	info, ok := e.ifaces[name]
	if !ok {
		e.mu.Unlock()
		return nil
	}
	delete(e.ifaces, name)
	delete(e.discoveredDNS, name)
	e.mu.Unlock()

	table := fmt.Sprintf("%d", info.TableID)
	mark := fmt.Sprintf("0x%x", info.TableID)
	_ = e.runCmd("ip", "rule", "del", "fwmark", mark, "table", table)
	_ = e.runCmd("ip", "-6", "rule", "del", "fwmark", mark, "table", table)
	_ = e.runCmd("ip", "route", "flush", "table", table)
	_ = e.runCmd("ip", "-6", "route", "flush", "table", table)

	return e.applyNftablesLocked()
}

func (e *Engine) ApplyNftables() error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	return e.applyNftablesLocked()
}

func (e *Engine) applyNftablesLocked() error {
	ruleset, skipped := e.buildRuleset()
	if e.runNftFn != nil {
		return e.runNftFn(ruleset, skipped)
	}
	return e.defaultApplyNft(ruleset, skipped)
}

func (e *Engine) Teardown() error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	_ = e.runCmd("nft", "delete", "table", "inet", "netweaver")

	e.mu.RLock()
	snapshot := make([]types.InterfaceInfo, 0, len(e.ifaces))
	for _, iface := range e.ifaces {
		snapshot = append(snapshot, iface)
	}
	e.mu.RUnlock()

	for _, iface := range snapshot {
		table := fmt.Sprintf("%d", iface.TableID)
		mark := fmt.Sprintf("0x%x", iface.TableID)
		_ = e.runCmd("ip", "rule", "del", "fwmark", mark, "table", table)
		_ = e.runCmd("ip", "-6", "rule", "del", "fwmark", mark, "table", table)
		_ = e.runCmd("ip", "route", "flush", "table", table)
		_ = e.runCmd("ip", "-6", "route", "flush", "table", table)
	}
	return nil
}
