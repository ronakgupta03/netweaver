// internal/tui/views.go
package tui

import (
	"fmt"
	"strings"

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
)

func (m Model) View() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("NetWeaver: Per-Application Network Interface Manager"))
	b.WriteString("\n\n")

	// Active interfaces summary
	b.WriteString("Active Interfaces: ")
	if len(m.interfaces) == 0 {
		b.WriteString("[None connected]")
	} else {
		for _, iface := range m.interfaces {
			b.WriteString(fmt.Sprintf("[%s: %s (table %d)] ", iface.Name, iface.IP, iface.TableID))
		}
	}
	b.WriteString("\n\n")

	// Process Table Header
	countStr := fmt.Sprintf("(%d applications)", len(m.processes))
	b.WriteString(fmt.Sprintf("%-3s %-8s %-32s %-15s %s\n", "   ", "PID", "APPLICATION", "INTERFACE", countStr))
	b.WriteString("-------------------------------------------------------------------\n")

	if len(m.processes) == 0 {
		b.WriteString("   No user applications detected.\n")
	} else {
		// Windowed scrolling: keep cursor visible within a 15-item viewport
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
				cursor = " >"
				style = selectedStyle
			}

			iface := p.AssignedInterface
			if iface == "" {
				iface = "(default)"
			}

			line := fmt.Sprintf("%s %-8d %-32s %-15s", cursor, p.PID, p.Name, iface)
			b.WriteString(style.Render(line) + "\n")
		}

		if len(m.processes) > windowSize {
			b.WriteString(fmt.Sprintf("\n   [Viewing %d-%d of %d - scroll with ↑/↓]\n", startIdx+1, endIdx, len(m.processes)))
		}
	}

	b.WriteString("\n[↑/↓] Navigate | [Enter] Route to next iface | [Space] Reset default | [q] Quit\n")
	return tableStyle.Render(b.String())
}
