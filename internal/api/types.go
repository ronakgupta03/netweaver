// internal/api/types.go
package api

import "netweaver/internal/types"

type Backend interface {
	ListInterfaces() ([]types.InterfaceInfo, error)
	ListProcesses() ([]types.ProcessInfo, error)
	AssignRoute(pid int, iface string) error
	ResetRoute(pid int) error
	ListRules() []types.Rule
	AddRule(rule types.Rule) error
	RemoveRule(match string) error
}

type Request struct {
	Method    string      `json:"method"`
	PID       int         `json:"pid,omitempty"`
	Interface string      `json:"interface,omitempty"`
	Match     string      `json:"match,omitempty"`
	Rule      *types.Rule `json:"rule,omitempty"`
}

type Response struct {
	Success    bool                  `json:"success"`
	Error      string                `json:"error,omitempty"`
	Interfaces []types.InterfaceInfo `json:"interfaces,omitempty"`
	Processes  []types.ProcessInfo   `json:"processes,omitempty"`
	Rules      []types.Rule          `json:"rules,omitempty"`
}
