// internal/tui/views.go
package tui

import (
	"fmt"
	"strings"

	"netweaver/internal/telemetry"

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
	parts := make([]string, 0, len(m.interfaces))
	for _, iface := range m.interfaces {
		parts = append(parts, fmt.Sprintf("%s %s ↓%s ↑%s (table %d)",
			iface.Name, iface.IP,
			telemetry.FormatRate(iface.RxRate),
			telemetry.FormatRate(iface.TxRate),
			iface.TableID))
	}
	return strings.Join(parts, "  |  ")
}

func (m Model) View() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("NetWeaver: Per-Application Network Interface Manager"))
	b.WriteString("\n\n")

	b.WriteString("Active Interfaces: ")
	b.WriteString(m.interfaceSummary())
	b.WriteString("\n\n")

	countStr := fmt.Sprintf("(%d applications)", len(m.processes))
	b.WriteString(fmt.Sprintf("%-2s %-7s %-26s %-12s %-11s %-11s %-10s %-16s %s\n",
		"", "PID", "APPLICATION", "INTERFACE", "DOWN", "UP", "USED", "ACTIVITY", countStr))
	b.WriteString("--------------------------------------------------------------------------------------------\n")

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
			}

			iface := p.AssignedInterface
			if iface == "" {
				iface = "(default)"
			}

			line := fmt.Sprintf("%s %-7d %-26s %-12s %-11s %-11s %-10s %-16s",
				cursor, p.PID, truncate(p.Name, 26), truncate(iface, 12),
				telemetry.FormatRate(p.RxRate),
				telemetry.FormatRate(p.TxRate),
				telemetry.FormatBytes(p.RxBytes+p.TxBytes),
				sparkline(m.history[p.PID], historyLen))
			b.WriteString(style.Render(line) + "\n")
		}

		if len(m.processes) > windowSize {
			b.WriteString(fmt.Sprintf("\n   [Viewing %d-%d of %d - scroll with ↑/↓]\n", startIdx+1, endIdx, len(m.processes)))
		}
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("[↑/↓] Navigate | [Enter] Route to next iface | [Space] Reset default | [q] Quit"))
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
