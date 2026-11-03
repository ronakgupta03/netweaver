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
	for _, iface := range m.interfaces {
		b.WriteString(fmt.Sprintf("[%s: %s (table %d)] ", iface.Name, iface.IP, iface.TableID))
	}
	b.WriteString("\n\n")

	// Process Table
	b.WriteString(fmt.Sprintf("%-3s %-8s %-25s %-15s\n", "   ", "PID", "APPLICATION", "INTERFACE"))
	b.WriteString("------------------------------------------------------------\n")

	for i, p := range m.processes {
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

		line := fmt.Sprintf("%s %-8d %-25s %-15s", cursor, p.PID, p.Name, iface)
		b.WriteString(style.Render(line) + "\n")
		if i >= 15 { // display top 15 in view
			break
		}
	}

	b.WriteString("\n[↑/↓] Navigate | [Enter] Route to next iface | [Space] Reset default | [q] Quit\n")
	return tableStyle.Render(b.String())
}
