// internal/tui/model.go
package tui

import (
	"netweaver/internal/api"
	"netweaver/internal/types"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type TickMsg time.Time

const historyLen = 16

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
	// history maps PID -> recent total throughput samples for sparklines.
	history map[int][]float64
}

func InitialModel(sockPath string) Model {
	return Model{
		client:  api.NewClient(sockPath),
		history: make(map[int][]float64),
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
