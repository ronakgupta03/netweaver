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
				// Cycle to next available interface
				targetIface := m.interfaces[0].Name
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
	case TickMsg:
		return m, tea.Batch(m.fetchDataCmd(), tickCmd())
	}
	return m, nil
}
