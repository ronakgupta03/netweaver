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

func (c *Client) ListRules() ([]types.Rule, error) {
	resp, err := c.call(Request{Method: "rules.list"})
	if err != nil {
		return nil, err
	}
	return resp.Rules, nil
}

func (c *Client) AddRule(rule types.Rule) error {
	_, err := c.call(Request{Method: "rules.add", Rule: &rule})
	return err
}

func (c *Client) RemoveRule(match string) error {
	_, err := c.call(Request{Method: "rules.remove", Match: match})
	return err
}

func (c *Client) GetPolicy() (string, error) {
	resp, err := c.call(Request{Method: "policy.get"})
	if err != nil {
		return "", err
	}
	return resp.Policy, nil
}

func (c *Client) SetPolicy(policy string) (string, error) {
	resp, err := c.call(Request{Method: "policy.set", Policy: policy})
	if err != nil {
		return "", err
	}
	return resp.Policy, nil
}

func (c *Client) AssignRouteWithOpts(pid int, iface string, policy string, rateLimitBps uint64) error {
	_, err := c.call(Request{
		Method:       "route.assign",
		PID:          pid,
		Interface:    iface,
		Policy:       policy,
		RateLimitBps: rateLimitBps,
	})
	return err
}

func (c *Client) SetProcessPolicy(pid int, policy string) error {
	_, err := c.call(Request{Method: "process.policy", PID: pid, Policy: policy})
	return err
}

func (c *Client) BlockProcess(pid int, blocked bool) error {
	_, err := c.call(Request{Method: "process.block", PID: pid, Blocked: blocked})
	return err
}

func (c *Client) SetProcessRateLimit(pid int, bps uint64) error {
	_, err := c.call(Request{Method: "process.ratelimit", PID: pid, RateLimitBps: bps})
	return err
}

func (c *Client) SwitchInterface(fromIface, toIface string) (int, error) {
	resp, err := c.call(Request{
		Method:        "interface.switch",
		FromInterface: fromIface,
		ToInterface:   toIface,
	})
	if err != nil {
		return 0, err
	}
	return resp.MovedCount, nil
}

func (c *Client) ListQuotas() ([]types.QuotaConfig, error) {
	resp, err := c.call(Request{Method: "quota.list"})
	if err != nil {
		return nil, err
	}
	return resp.Quotas, nil
}

func (c *Client) SetQuota(cfg types.QuotaConfig) error {
	_, err := c.call(Request{Method: "quota.set", Quota: &cfg})
	return err
}

func (c *Client) RemoveQuota(iface string) error {
	_, err := c.call(Request{Method: "quota.remove", Interface: iface})
	return err
}

func (c *Client) SetInterfaceDNS(iface string, servers []string) error {
	_, err := c.call(Request{Method: "dns.set", Interface: iface, DNSServers: servers})
	return err
}

func (c *Client) ListEvents(since uint64) ([]types.Event, error) {
	resp, err := c.call(Request{Method: "events.list", Since: since})
	if err != nil {
		return nil, err
	}
	return resp.Events, nil
}
