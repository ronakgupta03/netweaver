// internal/tui/app.go
package tui

import (
	"netweaver/internal/types"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	smartProfiles = []string{
		types.ProfileLowLatency,
		types.ProfileHighBandwidth,
		types.ProfileUnmetered,
	}
	ratePresets = []uint64{
		0,
		256 * 1024,
		1024 * 1024,
		5 * 1024 * 1024,
	}
)

func Run(sockPath string) error {
	p := tea.NewProgram(InitialModel(sockPath), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

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
			if len(m.processes) > 0 {
				targets := make([]string, 0, len(m.interfaces)+len(smartProfiles))
				for _, iface := range m.interfaces {
					targets = append(targets, iface.Name)
				}
				targets = append(targets, smartProfiles...)
				if len(targets) > 0 {
					proc := m.processes[m.cursor]
					currentTarget := proc.AssignedInterface
					if proc.Profile != "" {
						currentTarget = proc.Profile
					}
					currIdx := -1
					for idx, t := range targets {
						if t == currentTarget {
							currIdx = idx
							break
						}
					}
					nextIdx := (currIdx + 1) % len(targets)
					target := targets[nextIdx]
					if err := m.client.AssignRoute(proc.PID, target); err != nil {
						m.notice = err.Error()
						return m, nil
					}
					m.notice = ""
					return m, m.fetchDataCmd()
				}
			}

		case " ":
			if len(m.processes) > 0 {
				proc := m.processes[m.cursor]
				if err := m.client.ResetRoute(proc.PID); err != nil {
					m.notice = err.Error()
					return m, nil
				}
				m.notice = ""
				return m, m.fetchDataCmd()
			}

		case "p":
			if len(m.processes) > 0 {
				proc := m.processes[m.cursor]
				cur := proc.Policy
				if cur == "" {
					cur = m.globalPolicy
				}
				next := types.PolicyStrict
				if cur == types.PolicyStrict {
					next = types.PolicyFailover
				}
				if err := m.client.SetProcessPolicy(proc.PID, next); err != nil {
					m.notice = err.Error()
					return m, nil
				}
				m.notice = ""
				return m, m.fetchDataCmd()
			}

		case "b":
			if len(m.processes) > 0 {
				proc := m.processes[m.cursor]
				if err := m.client.BlockProcess(proc.PID, !proc.Blocked); err != nil {
					m.notice = err.Error()
					return m, nil
				}
				m.notice = ""
				return m, m.fetchDataCmd()
			}

		case "l":
			if len(m.processes) > 0 {
				proc := m.processes[m.cursor]
				currIdx := -1
				for idx, bps := range ratePresets {
					if bps == proc.RateLimitBps {
						currIdx = idx
						break
					}
				}
				nextIdx := (currIdx + 1) % len(ratePresets)
				if err := m.client.SetProcessRateLimit(proc.PID, ratePresets[nextIdx]); err != nil {
					m.notice = err.Error()
					return m, nil
				}
				m.notice = ""
				return m, m.fetchDataCmd()
			}

		case "P":
			next := types.PolicyStrict
			if m.globalPolicy == types.PolicyStrict {
				next = types.PolicyFailover
			}
			updated, err := m.client.SetPolicy(next)
			if err != nil {
				m.notice = err.Error()
				return m, nil
			}
			if updated != "" {
				m.globalPolicy = updated
			} else {
				m.globalPolicy = next
			}
			m.notice = ""
			return m, m.fetchDataCmd()
		}

	case dataLoadedMsg:
		m.err = msg.err
		if msg.err == nil {
			m.processes = msg.processes
			m.interfaces = msg.interfaces
			m.quotas = msg.quotas
			m.events = msg.events
			if msg.globalPolicy != "" {
				m.globalPolicy = msg.globalPolicy
			}
		}
		live := make(map[int]bool, len(m.processes))
		for _, p := range m.processes {
			live[p.PID] = true
			hist := m.history[p.PID]
			hist = append(hist, p.RxRate+p.TxRate)
			if len(hist) > historyLen {
				hist = hist[len(hist)-historyLen:]
			}
			m.history[p.PID] = hist
		}
		for pid := range m.history {
			if !live[pid] {
				delete(m.history, pid)
			}
		}
		if m.cursor >= len(m.processes) && len(m.processes) > 0 {
			m.cursor = len(m.processes) - 1
		}

	case TickMsg:
		return m, tea.Batch(m.fetchDataCmd(), tickCmd())
	}
	return m, nil
}
