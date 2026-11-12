// internal/web/server.go
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

//go:embed index.html
var assets embed.FS

// Server exposes the daemon state over loopback HTTP for the dashboard.
type Server struct {
	client *api.Client
	addr   string
	http   *http.Server
}

func NewServer(addr, sockPath string) *Server {
	return &Server{client: api.NewClient(sockPath), addr: addr}
}

type stateResponse struct {
	Interfaces []types.InterfaceInfo `json:"interfaces"`
	Processes  []types.ProcessInfo   `json:"processes"`
	Rules      []types.Rule          `json:"rules"`
	Policy     string                `json:"policy"`
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	index, err := assets.ReadFile("index.html")
	if err != nil {
		return err
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/assign", s.handleAssign)
	mux.HandleFunc("/api/reset", s.handleReset)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/policy", s.handlePolicy)

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.addr, err)
	}
	s.addr = ln.Addr().String()
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.http.Serve(ln) }()
	return nil
}

// Addr returns the bound address (useful when :0 was requested).
func (s *Server) Addr() string { return s.addr }

func (s *Server) Stop() error {
	if s.http == nil {
		return nil
	}
	return s.http.Close()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	ifaces, err := s.client.ListInterfaces()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	procs, err := s.client.ListProcesses()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	rules, err := s.client.ListRules()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	policy, err := s.client.GetPolicy()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, stateResponse{Interfaces: ifaces, Processes: procs, Rules: rules, Policy: policy})
}

type assignRequest struct {
	PID       int    `json:"pid"`
	Interface string `json:"interface"`
}

func (s *Server) handleAssign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req assignRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.PID <= 0 || req.Interface == "" {
		writeErr(w, http.StatusBadRequest, errors.New("pid and interface are required"))
		return
	}
	if err := s.client.AssignRoute(req.PID, req.Interface); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		PID int `json:"pid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.PID <= 0 {
		writeErr(w, http.StatusBadRequest, errors.New("pid is required"))
		return
	}
	if err := s.client.ResetRoute(req.PID); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var rule types.Rule
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&rule); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.client.AddRule(rule); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case http.MethodDelete:
		match := r.URL.Query().Get("match")
		if match == "" {
			writeErr(w, http.StatusBadRequest, errors.New("match query parameter required"))
			return
		}
		if err := s.client.RemoveRule(match); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST or DELETE required"))
	}
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		Policy string `json:"policy"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	applied, err := s.client.SetPolicy(req.Policy)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"policy": applied})
}
