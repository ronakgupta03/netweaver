// internal/api/server.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type Server struct {
	sockPath string
	backend  Backend
	listener net.Listener
}

func NewServer(sockPath string, backend Backend) *Server {
	return &Server{sockPath: sockPath, backend: backend}
}

func (s *Server) Start() error {
	_ = os.Remove(s.sockPath)
	_ = os.MkdirAll(filepath.Dir(s.sockPath), 0755)

	l, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return err
	}
	s.listener = l
	// Set socket permissions so unprivileged local users can connect to daemon
	_ = os.Chmod(s.sockPath, 0666)

	go s.serve()
	return nil
}

func (s *Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	var resp Response
	switch req.Method {
	case "interfaces.list":
		ifaces, err := s.backend.ListInterfaces()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
			resp.Interfaces = ifaces
		}
	case "processes.list":
		procs, err := s.backend.ListProcesses()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
			resp.Processes = procs
		}
	case "route.assign":
		if ext, ok := s.backend.(ExtendedBackend); ok && (req.Policy != "" || req.RateLimitBps > 0) {
			if err := ext.AssignRouteWithOpts(req.PID, req.Interface, req.Policy, req.RateLimitBps); err != nil {
				resp.Error = err.Error()
			} else {
				resp.Success = true
			}
		} else {
			if err := s.backend.AssignRoute(req.PID, req.Interface); err != nil {
				resp.Error = err.Error()
			} else {
				resp.Success = true
			}
		}
	case "route.reset":
		if err := s.backend.ResetRoute(req.PID); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
		}
	case "rules.list":
		resp.Success = true
		resp.Rules = s.backend.ListRules()
	case "rules.add":
		if req.Rule == nil {
			resp.Error = "missing rule payload"
			break
		}
		if err := s.backend.AddRule(*req.Rule); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
		}
	case "policy.get":
		resp.Success = true
		resp.Policy = s.backend.GetPolicy()
	case "policy.set":
		if err := s.backend.SetPolicy(req.Policy); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
			resp.Policy = s.backend.GetPolicy()
		}
	case "rules.remove":
		if err := s.backend.RemoveRule(req.Match); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
		}
	case "process.policy":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			return ext.SetProcessPolicy(req.PID, req.Policy)
		})
	case "process.block":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			return ext.BlockProcess(req.PID, req.Blocked)
		})
	case "process.ratelimit":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			return ext.SetProcessRateLimit(req.PID, req.RateLimitBps)
		})
	case "interface.switch":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			moved, err := ext.SwitchInterface(req.FromInterface, req.ToInterface)
			if err == nil {
				resp.MovedCount = moved
			}
			return err
		})
	case "quota.list":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			resp.Quotas = ext.ListQuotas()
			return nil
		})
	case "quota.set":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			if req.Quota == nil {
				return errors.New("missing quota payload")
			}
			return ext.SetQuota(*req.Quota)
		})
	case "quota.remove":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			return ext.RemoveQuota(req.Interface)
		})
	case "dns.set":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			return ext.SetInterfaceDNS(req.Interface, req.DNSServers)
		})
	case "events.list":
		s.applyExtended(&resp, req.Method, func(ext ExtendedBackend) error {
			resp.Events = ext.ListEvents(req.Since)
			return nil
		})
	default:
		resp.Error = "unknown method"
	}

	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) applyExtended(resp *Response, method string, fn func(ExtendedBackend) error) {
	ext, ok := s.backend.(ExtendedBackend)
	if !ok {
		resp.Error = fmt.Sprintf("backend does not support extended operation %q", method)
		return
	}
	if err := fn(ext); err != nil {
		resp.Error = err.Error()
		return
	}
	resp.Success = true
}

func (s *Server) Stop() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.sockPath)
}
