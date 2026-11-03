// internal/types/models.go
package types

import (
	"errors"
	"fmt"
	"regexp"
)

var validIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,16}$`)

type InterfaceInfo struct {
	Name    string `json:"name"`
	Index   int    `json:"index"`
	IP      string `json:"ip"`
	Gateway string `json:"gateway"`
	TableID int    `json:"table_id"`
	Up      bool   `json:"up"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

func (i InterfaceInfo) Validate() error {
	if !validIfaceRegex.MatchString(i.Name) {
		return fmt.Errorf("invalid interface name: %q", i.Name)
	}
	if i.TableID <= 0 {
		return errors.New("table ID must be positive")
	}
	return nil
}

type ProcessInfo struct {
	PID               int     `json:"pid"`
	Name              string  `json:"name"`
	Cmdline           string  `json:"cmdline"`
	UID               uint32  `json:"uid"`
	AssignedInterface string  `json:"assigned_interface"`
	RxRate            float64 `json:"rx_rate"`
	TxRate            float64 `json:"tx_rate"`
}

type RouteRule struct {
	PID       int    `json:"pid"`
	AppName   string `json:"app_name"`
	Interface string `json:"interface"`
}

type DaemonStatus struct {
	UptimeSeconds uint64 `json:"uptime_seconds"`
	ActiveIfaces  int    `json:"active_ifaces"`
	ManagedProcs  int    `json:"managed_procs"`
}
