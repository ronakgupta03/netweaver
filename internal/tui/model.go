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

// BackendClient defines the daemon IPC operations consumed by the TUI.
type BackendClient interface {
	ListProcesses() ([]types.ProcessInfo, error)
	ListInterfaces() ([]types.InterfaceInfo, error)
	GetPolicy() (string, error)
	SetPolicy(policy string) (string, error)
	AssignRoute(pid int, iface string) error
	ResetRoute(pid int) error
	SetProcessPolicy(pid int, policy string) error
	BlockProcess(pid int, blocked bool) error
	SetProcessRateLimit(pid int, bps uint64) error
	ListQuotas() ([]types.QuotaConfig, error)
	ListEvents(since uint64) ([]types.Event, error)
}

var _ BackendClient = (*api.Client)(nil)

type Model struct {
	client       BackendClient
	processes    []types.ProcessInfo
	interfaces   []types.InterfaceInfo
	quotas       []types.QuotaConfig
	events       []types.Event
	globalPolicy string
	cursor       int
	modalOpen    bool
	selectedP    *types.ProcessInfo
	err          error
	notice       string
	width        int
	height       int
	// history maps PID -> recent total throughput samples for sparklines.
	history map[int][]float64
}

func InitialModel(sockPath string) Model {
	return InitialModelWithClient(api.NewClient(sockPath))
}

func InitialModelWithClient(client BackendClient) Model {
	return Model{
		client:       client,
		globalPolicy: types.PolicyFailover,
		history:      make(map[int][]float64),
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
	client := m.client
	return func() tea.Msg {
		procs, procErr := client.ListProcesses()
		ifaces, ifaceErr := client.ListInterfaces()
		pol, _ := client.GetPolicy()
		quotas, _ := client.ListQuotas()
		events, _ := client.ListEvents(0)

		var fetchErr error
		if procErr != nil {
			fetchErr = procErr
		} else if ifaceErr != nil {
			fetchErr = ifaceErr
		}
		return dataLoadedMsg{
			processes:    procs,
			interfaces:   ifaces,
			quotas:       quotas,
			events:       events,
			globalPolicy: pol,
			err:          fetchErr,
		}
	}
}

type dataLoadedMsg struct {
	processes    []types.ProcessInfo
	interfaces   []types.InterfaceInfo
	quotas       []types.QuotaConfig
	events       []types.Event
	globalPolicy string
	err          error
}
