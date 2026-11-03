// internal/tui/app.go
package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

func Run(sockPath string) error {
	p := tea.NewProgram(InitialModel(sockPath), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.processes)-1 {
				m.cursor++
			}
		case "enter":
			if len(m.processes) > 0 && len(m.interfaces) > 0 {
				proc := m.processes[m.cursor]
				currIdx := -1
				for idx, iface := range m.interfaces {
					if iface.Name == proc.AssignedInterface {
						currIdx = idx
						break
					}
				}
				nextIdx := (currIdx + 1) % len(m.interfaces)
				targetIface := m.interfaces[nextIdx].Name
				_ = m.client.AssignRoute(proc.PID, targetIface)
				return m, m.fetchDataCmd()
			}
		case " ":
			if len(m.processes) > 0 {
				proc := m.processes[m.cursor]
				_ = m.client.ResetRoute(proc.PID)
				return m, m.fetchDataCmd()
			}
		}
	case dataLoadedMsg:
		m.processes = msg.processes
		m.interfaces = msg.interfaces
		if m.cursor >= len(m.processes) && len(m.processes) > 0 {
			m.cursor = len(m.processes) - 1
		}
	case TickMsg:
		return m, tea.Batch(m.fetchDataCmd(), tickCmd())
	}
	return m, nil
}
