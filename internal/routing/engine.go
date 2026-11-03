// internal/routing/engine.go
package routing

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"text/template"
	"netweaver/internal/types"
)

const nftTemplate = `
table inet netweaver {
    chain output {
        type route hook output priority mangle; policy accept;
{{- range . }}
        socket cgroupv2 level 2 "netweaver/{{ .Name }}" meta mark set 0x{{ printf "%x" .TableID }}
{{- end }}
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
{{- range . }}
        oifname "{{ .Name }}" meta mark 0x{{ printf "%x" .TableID }} masquerade
{{- end }}
    }
}
`

func GenerateNftablesRuleset(ifaces []types.InterfaceInfo) string {
	tmpl, err := template.New("nft").Parse(nftTemplate)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ifaces); err != nil {
		return ""
	}
	return buf.String()
}

type Engine struct {
	ifaces map[string]types.InterfaceInfo
}

func NewEngine() *Engine {
	return &Engine{
		ifaces: make(map[string]types.InterfaceInfo),
	}
}

func (e *Engine) SetupInterfaceRoute(info types.InterfaceInfo) error {
	e.ifaces[info.Name] = info

	// 1. ip route replace default via <GW> dev <IFACE> table <TableID>
	if info.Gateway != "" {
		cmd := exec.Command("ip", "route", "replace", "default", "via", info.Gateway, "dev", info.Name, "table", fmt.Sprintf("%d", info.TableID))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip route failed: %s: %w", string(out), err)
		}
	}

	// 2. ip rule add fwmark <TableID> lookup <TableID> priority 1000
	_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID)).Run()
	cmd := exec.Command("ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", info.TableID), "table", fmt.Sprintf("%d", info.TableID), "priority", "1000")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip rule failed: %s: %w", string(out), err)
	}

	return e.ApplyNftables()
}

func (e *Engine) ApplyNftables() error {
	var list []types.InterfaceInfo
	for _, iface := range e.ifaces {
		list = append(list, iface)
	}
	ruleset := GenerateNftablesRuleset(list)

	// Idempotently purge existing table before reapplying to prevent duplicate rules
	_ = exec.Command("nft", "delete", "table", "inet", "netweaver").Run()

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply failed: %s: %w", string(out), err)
	}
	return nil
}

func (e *Engine) Teardown() error {
	// Flush nftables table
	_ = exec.Command("nft", "delete", "table", "inet", "netweaver").Run()

	// Flush ip rules and tables
	for _, iface := range e.ifaces {
		_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", iface.TableID), "table", fmt.Sprintf("%d", iface.TableID)).Run()
		_ = exec.Command("ip", "route", "flush", "table", fmt.Sprintf("%d", iface.TableID)).Run()
	}
	return nil
}
