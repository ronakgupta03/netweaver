// internal/api/server.go
package api

import (
	"encoding/json"
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
		if err := s.backend.AssignRoute(req.PID, req.Interface); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
		}
	case "route.reset":
		if err := s.backend.ResetRoute(req.PID); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Success = true
		}
	default:
		resp.Error = "unknown method"
	}

	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) Stop() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.sockPath)
}
