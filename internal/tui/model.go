// internal/tui/model.go
package tui

import (
	"time"
	"netweaver/internal/api"
	"netweaver/internal/types"

	tea "github.com/charmbracelet/bubbletea"
)

type TickMsg time.Time

type Model struct {
	client     *api.Client
	processes  []types.ProcessInfo
	interfaces []types.InterfaceInfo
	cursor     int
	modalOpen  bool
	selectedP  *types.ProcessInfo
	err        error
	width      int
	height     int
}

func InitialModel(sockPath string) Model {
	return Model{
		client: api.NewClient(sockPath),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.fetchDataCmd(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) fetchDataCmd() tea.Cmd {
	return func() tea.Msg {
		procs, _ := m.client.ListProcesses()
		ifaces, _ := m.client.ListInterfaces()
		return dataLoadedMsg{processes: procs, interfaces: ifaces}
	}
}

type dataLoadedMsg struct {
	processes  []types.ProcessInfo
	interfaces []types.InterfaceInfo
}
