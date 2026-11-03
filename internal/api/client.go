// internal/api/client.go
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"netweaver/internal/types"
)

type Client struct {
	sockPath string
}

func NewClient(sockPath string) *Client {
	return &Client{sockPath: sockPath}
}

func (c *Client) call(req Request) (*Response, error) {
	conn, err := net.Dial("unix", c.sockPath)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to daemon at %s: %w", c.sockPath, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("server error: %s", resp.Error)
	}
	return &resp, nil
}

func (c *Client) ListInterfaces() ([]types.InterfaceInfo, error) {
	resp, err := c.call(Request{Method: "interfaces.list"})
	if err != nil {
		return nil, err
	}
	return resp.Interfaces, nil
}

func (c *Client) ListProcesses() ([]types.ProcessInfo, error) {
	resp, err := c.call(Request{Method: "processes.list"})
	if err != nil {
		return nil, err
	}
	return resp.Processes, nil
}

func (c *Client) AssignRoute(pid int, iface string) error {
	_, err := c.call(Request{Method: "route.assign", PID: pid, Interface: iface})
	return err
}

func (c *Client) ResetRoute(pid int) error {
	_, err := c.call(Request{Method: "route.reset", PID: pid})
	return err
}
