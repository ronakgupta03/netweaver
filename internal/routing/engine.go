// internal/routing/engine.go
package routing

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"netweaver/internal/cgroups"
	"netweaver/internal/types"

	"os/exec"
)

const nftTemplate = `
table inet netweaver {
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
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
{{- range .Ifaces }}
        oifname "{{ .Name }}" meta mark 0x{{ printf "%x" .TableID }} masquerade
{{- end }}
    }
}
`

type rulesetData struct {
	Ifaces      []types.InterfaceInfo
	Marking     bool
	Blocked     bool
	BlockedName string
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
	return renderRuleset(rulesetData{Ifaces: ifaces, Marking: true, Blocked: true, BlockedName: cgroups.BlockedCgroup})
}

// Engine owns policy routing state for every managed interface.
type Engine struct {
	ifaces     map[string]types.InterfaceInfo
	cgroupRoot string
	marking    bool
}

func NewEngine() *Engine {
	return &Engine{
		ifaces:     make(map[string]types.InterfaceInfo),
		cgroupRoot: "/sys/fs/cgroup",
		marking:    true,
	}
}

func NewEngineWithCgroupRoot(root string) *Engine {
	e := NewEngine()
	e.cgroupRoot = root
	return e
}

// CgroupPathExists reports whether the cgroup directory for a name is present.
// nftables resolves cgroupv2 paths when the ruleset is loaded and rejects the
// whole transaction when one is missing, so rules must be filtered first.
func (e *Engine) CgroupPathExists(name string) bool {
	info, err := os.Stat(filepath.Join(e.cgroupRoot, "netweaver", name))
	return err == nil && info.IsDir()
}

func (e *Engine) buildRuleset() (string, []string) {
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

	return renderRuleset(rulesetData{
		Ifaces:      kept,
		Marking:     e.marking,
		Blocked:     e.CgroupPathExists(cgroups.BlockedCgroup),
		BlockedName: cgroups.BlockedCgroup,
	}), skipped
}

// SetMarking selects whether nftables sets packet marks. When the eBPF
// classifier is active, marking lives in the kernel program and nftables only
// keeps NAT rules.
func (e *Engine) SetMarking(enabled bool) {
	e.marking = enabled
}

func (e *Engine) MarkingEnabled() bool {
	return e.marking
}

func (e *Engine) SetupInterfaceRoute(info types.InterfaceInfo) error {
	e.ifaces[info.Name] = info

	// 1. IPv4 Route in table
	if info.Gateway != "" {
		_ = exec.Command("ip", "route", "replace", "default", "via", info.Gateway, "dev", info.Name, "table", fmt.Sprintf("%d", info.TableID)).Run()
	}

	// 2. IPv6 Route in table (or unreachable to prevent leaking onto other interfaces)
	if info.Gateway6 != "" {
		_ = exec.Command("ip", "-6", "route", "replace", "default", "via", info.Gateway6, "dev", info.Name, "table", fmt.Sprintf("%d", info.TableID)).Run()
	} else {
		_ = exec.Command("ip", "-6", "route", "replace", "unreachable", "default", "table", fmt.Sprintf("%d", info.TableID)).Run()
	}

	// 3. IPv4 FIB rule
	_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID)).Run()
	_ = exec.Command("ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID), "priority", "1000").Run()

	// 4. IPv6 FIB rule
	_ = exec.Command("ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID)).Run()
	_ = exec.Command("ip", "-6", "rule", "add", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID), "priority", "1000").Run()

	return e.ApplyNftables()
}

// RemoveInterface drops every route and rule owned by an interface that is no
// longer usable, so its marks cannot blackhole traffic.
func (e *Engine) RemoveInterface(name string) error {
	info, ok := e.ifaces[name]
	if !ok {
		return nil
	}
	table := fmt.Sprintf("%d", info.TableID)
	_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", table).Run()
	_ = exec.Command("ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", table).Run()
	_ = exec.Command("ip", "route", "flush", "table", table).Run()
	_ = exec.Command("ip", "-6", "route", "flush", "table", table).Run()
	delete(e.ifaces, name)
	return e.ApplyNftables()
}

func (e *Engine) ApplyNftables() error {
	ruleset, skipped := e.buildRuleset()

	// Idempotently purge existing table before reapplying to prevent duplicate rules
	_ = exec.Command("nft", "delete", "table", "inet", "netweaver").Run()

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply failed (skipped cgroups: %v): %s: %w", skipped, string(out), err)
	}
	return nil
}

func (e *Engine) Teardown() error {
	_ = exec.Command("nft", "delete", "table", "inet", "netweaver").Run()

	for _, iface := range e.ifaces {
		_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", iface.TableID), "table", fmt.Sprintf("%d", iface.TableID)).Run()
		_ = exec.Command("ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("0x%x", iface.TableID), "table", fmt.Sprintf("%d", iface.TableID)).Run()
		_ = exec.Command("ip", "route", "flush", "table", fmt.Sprintf("%d", iface.TableID)).Run()
		_ = exec.Command("ip", "-6", "route", "flush", "table", fmt.Sprintf("%d", iface.TableID)).Run()
	}
	return nil
}
