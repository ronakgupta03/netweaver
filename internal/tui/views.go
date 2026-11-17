// internal/tui/views.go
package tui

import (
	"fmt"
	"strings"

	"netweaver/internal/telemetry"
	"netweaver/internal/types"

	"github.com/charmbracelet/lipgloss"
)

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00E676"))

	healthyDotStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00E676"))

	unhealthyDotStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FF5252"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFB74D"))

	blockedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF5252"))

	tableStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#626262")).
			Padding(0, 1)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8A8A8A"))

	sparkRunes = []rune("▁▂▃▄▅▆▇█")
)

// sparkline renders a normalized activity trace padded to width characters.
func sparkline(samples []float64, width int) string {
	var b strings.Builder
	pad := width - len(samples)
	if pad < 0 {
		samples = samples[len(samples)-width:]
		pad = 0
	}
	b.WriteString(strings.Repeat(" ", pad))

	max := 0.0
	for _, v := range samples {
		if v > max {
			max = v
		}
	}
	for _, v := range samples {
		if max <= 0 {
			b.WriteRune(sparkRunes[0])
			continue
		}
		idx := int(v / max * float64(len(sparkRunes)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[idx])
	}
	return b.String()
}

func (m Model) interfaceSummary() string {
	if len(m.interfaces) == 0 {
		return "[None connected]"
	}
	quotaMap := make(map[string]types.QuotaConfig, len(m.quotas))
	for _, q := range m.quotas {
		quotaMap[q.Interface] = q
	}

	parts := make([]string, 0, len(m.interfaces))
	for _, iface := range m.interfaces {
		dot := healthyDotStyle.Render("●")
		if !iface.Healthy {
			dot = unhealthyDotStyle.Render("●")
		}
		name := iface.Name
		if iface.IsTunnel {
			name += " [VPN]"
		}
		rtt := ""
		if iface.LatencyMs > 0 {
			rtt = fmt.Sprintf(" %.0fms", iface.LatencyMs)
		} else if !iface.Healthy {
			rtt = " DOWN"
		}

		quotaTag := ""
		used := iface.DailyUsedBytes
		limit := iface.DailyQuotaBytes
		metered := iface.Metered
		exceeded := iface.QuotaExceeded
		if q, ok := quotaMap[iface.Name]; ok {
			if used == 0 {
				used = q.UsedBytes
			}
			if limit == 0 {
				limit = q.DailyLimitBytes
			}
			metered = metered || q.Metered
			if limit > 0 && used >= limit {
				exceeded = true
			}
		}
		if limit > 0 {
			quotaTag = fmt.Sprintf(" [%s/%s", telemetry.FormatBytes(used), telemetry.FormatBytes(limit))
			if exceeded {
				quotaTag += " EXCEEDED"
			}
			quotaTag += "]"
		} else if metered {
			quotaTag = " [metered]"
		}

		parts = append(parts, fmt.Sprintf("%s %s %s%s ↓%s ↑%s%s (table %d)",
			dot, name, iface.IP, rtt,
			telemetry.FormatRate(iface.RxRate),
			telemetry.FormatRate(iface.TxRate),
			quotaTag,
			iface.TableID))
	}
	return strings.Join(parts, "  |  ")
}

func formatProcessTarget(p types.ProcessInfo) string {
	switch {
	case p.Profile != "" && p.AssignedInterface != "" && p.AssignedInterface != "blocked":
		return fmt.Sprintf("%s (%s)", p.AssignedInterface, p.Profile)
	case p.Profile != "":
		return p.Profile
	case p.AssignedInterface == "":
		return "(default)"
	default:
		return p.AssignedInterface
	}
}

func formatProcessApp(p types.ProcessInfo) string {
	if p.Blocked {
		return "[BLOCKED] " + p.Name
	}
	return p.Name
}

func (m Model) View() string {
	var b strings.Builder

	polLabel := m.globalPolicy
	if polLabel == "" {
		polLabel = types.PolicyFailover
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("NetWeaver: Per-Application Network Interface Manager  [Default: %s]", polLabel)))
	b.WriteString("\n\n")

	if m.err != nil {
		b.WriteString(blockedStyle.Render(fmt.Sprintf("Daemon Error: %v", m.err)))
		b.WriteString("\n\n")
	} else if m.notice != "" {
		b.WriteString(warnStyle.Render(fmt.Sprintf("Notice: %s", m.notice)))
		b.WriteString("\n\n")
	}

	b.WriteString("Active Interfaces: ")
	b.WriteString(m.interfaceSummary())
	b.WriteString("\n\n")

	countStr := fmt.Sprintf("(%d applications)", len(m.processes))
	b.WriteString(fmt.Sprintf("%-2s %-7s %-24s %-22s %-8s %-11s %-11s %-11s %-10s %-12s %s\n",
		"", "PID", "APPLICATION", "INTERFACE", "POLICY", "RATE CAP", "DOWN", "UP", "USED", "ACTIVITY", countStr))
	b.WriteString("----------------------------------------------------------------------------------------------------------------------------\n")

	if len(m.processes) == 0 {
		b.WriteString("   No user applications detected.\n")
	} else {
		windowSize := 15
		startIdx := 0
		if m.cursor >= windowSize {
			startIdx = m.cursor - windowSize + 1
		}
		endIdx := startIdx + windowSize
		if endIdx > len(m.processes) {
			endIdx = len(m.processes)
		}

		for i := startIdx; i < endIdx; i++ {
			p := m.processes[i]
			cursor := "  "
			style := lipgloss.NewStyle()
			if m.cursor == i {
				cursor = ">"
				style = selectedStyle
			} else if p.Blocked {
				style = blockedStyle
			}

			iface := formatProcessTarget(p)
			policy := p.Policy
			if policy == "" {
				policy = "-"
			}
			rateCap := "-"
			if p.RateLimitBps > 0 {
				rateCap = telemetry.FormatRate(float64(p.RateLimitBps))
			}

			line := fmt.Sprintf("%s %-7d %-24s %-22s %-8s %-11s %-11s %-11s %-10s %-12s",
				cursor, p.PID,
				truncate(formatProcessApp(p), 24),
				truncate(iface, 22),
				truncate(policy, 8),
				truncate(rateCap, 11),
				telemetry.FormatRate(p.RxRate),
				telemetry.FormatRate(p.TxRate),
				telemetry.FormatBytes(p.RxBytes+p.TxBytes),
				sparkline(m.history[p.PID], 12))
			b.WriteString(style.Render(line) + "\n")
		}

		if len(m.processes) > windowSize {
			b.WriteString(fmt.Sprintf("\n   [Viewing %d-%d of %d - scroll with ↑/↓]\n", startIdx+1, endIdx, len(m.processes)))
		}
	}

	if len(m.events) > 0 {
		last := m.events[len(m.events)-1]
		b.WriteString("\n")
		b.WriteString(dimStyle.Render(fmt.Sprintf("Latest Event: [%s] %s", last.Type, last.Message)))
		b.WriteString("\n")
	} else {
		b.WriteString("\n")
	}

	b.WriteString(dimStyle.Render("[↑/↓] Nav | [Enter] Next iface/profile | [Space] Reset | [p] App policy | [b] Block | [l] Rate cap | [P] Global policy | [q] Quit"))
	return tableStyle.Render(b.String())
}

func truncate(s string, width int) string {
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width <= 1 {
		return string(r[:width])
	}
	return string(r[:width-1]) + "…"
}
