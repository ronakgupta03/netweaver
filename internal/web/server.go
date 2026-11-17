// internal/web/server.go
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

//go:embed index.html
var assets embed.FS

const maxRequestBodyBytes = 32 << 10

// Server exposes the daemon state over loopback HTTP for the dashboard.
type Server struct {
	client      *api.Client
	addr        string
	http        *http.Server
	sseInterval time.Duration
}

func NewServer(addr, sockPath string) *Server {
	return &Server{client: api.NewClient(sockPath), addr: addr}
}

func (s *Server) ssePollInterval() time.Duration {
	if s.sseInterval > 0 {
		return s.sseInterval
	}
	return time.Second
}

type stateResponse struct {
	Interfaces []types.InterfaceInfo `json:"interfaces"`
	Processes  []types.ProcessInfo   `json:"processes"`
	Rules      []types.Rule          `json:"rules"`
	Policy     string                `json:"policy"`
	Quotas     []types.QuotaConfig   `json:"quotas"`
	Events     []types.Event         `json:"events"`
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
	mux.HandleFunc("/api/block", s.handleBlock)
	mux.HandleFunc("/api/process-policy", s.handleProcessPolicy)
	mux.HandleFunc("/api/ratelimit", s.handleRateLimit)
	mux.HandleFunc("/api/switch", s.handleSwitch)
	mux.HandleFunc("/api/quota", s.handleQuota)
	mux.HandleFunc("/api/dns", s.handleDNS)
	mux.HandleFunc("/api/events", s.handleEvents)

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

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(dst)
}

func isUnsupportedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not support") ||
		strings.Contains(msg, "unknown method") ||
		strings.Contains(msg, "unsupported")
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

	quotas, err := s.client.ListQuotas()
	if err != nil {
		if !isUnsupportedErr(err) {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		quotas = []types.QuotaConfig{}
	}
	if quotas == nil {
		quotas = []types.QuotaConfig{}
	}

	events, err := s.client.ListEvents(0)
	if err != nil {
		if !isUnsupportedErr(err) {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		events = []types.Event{}
	}
	if events == nil {
		events = []types.Event{}
	}

	writeJSON(w, http.StatusOK, stateResponse{
		Interfaces: ifaces,
		Processes:  procs,
		Rules:      rules,
		Policy:     policy,
		Quotas:     quotas,
		Events:     events,
	})
}

type assignRequest struct {
	PID          int    `json:"pid"`
	Interface    string `json:"interface"`
	Policy       string `json:"policy,omitempty"`
	RateLimitBps uint64 `json:"rate_limit_bps,omitempty"`
}

func (s *Server) handleAssign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req assignRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.PID <= 0 || req.Interface == "" {
		writeErr(w, http.StatusBadRequest, errors.New("pid and interface are required"))
		return
	}
	req.Policy = strings.ToLower(strings.TrimSpace(req.Policy))
	if !types.ValidPolicy(req.Policy) {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown policy %q (use failover or strict)", req.Policy))
		return
	}
	var err error
	if req.Policy != "" || req.RateLimitBps > 0 {
		err = s.client.AssignRouteWithOpts(req.PID, req.Interface, req.Policy, req.RateLimitBps)
	} else {
		err = s.client.AssignRoute(req.PID, req.Interface)
	}
	if err != nil {
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
	if err := decodeJSON(w, r, &req); err != nil {
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
		if err := decodeJSON(w, r, &rule); err != nil {
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
	if err := decodeJSON(w, r, &req); err != nil {
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

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		PID     int  `json:"pid"`
		Blocked bool `json:"blocked"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.PID <= 0 {
		writeErr(w, http.StatusBadRequest, errors.New("pid is required"))
		return
	}
	if err := s.client.BlockProcess(req.PID, req.Blocked); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleProcessPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		PID    int    `json:"pid"`
		Policy string `json:"policy"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.PID <= 0 {
		writeErr(w, http.StatusBadRequest, errors.New("pid is required"))
		return
	}
	pol := strings.ToLower(strings.TrimSpace(req.Policy))
	if pol == "" {
		writeErr(w, http.StatusBadRequest, errors.New("policy required (failover or strict)"))
		return
	}
	if !types.ValidPolicy(pol) {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown policy %q (use failover or strict)", req.Policy))
		return
	}
	if err := s.client.SetProcessPolicy(req.PID, pol); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		PID          int    `json:"pid"`
		RateLimitBps uint64 `json:"rate_limit_bps"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.PID <= 0 {
		writeErr(w, http.StatusBadRequest, errors.New("pid is required"))
		return
	}
	if err := s.client.SetProcessRateLimit(req.PID, req.RateLimitBps); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		FromInterface string `json:"from_interface"`
		ToInterface   string `json:"to_interface"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.FromInterface = strings.TrimSpace(req.FromInterface)
	req.ToInterface = strings.TrimSpace(req.ToInterface)
	if req.FromInterface == "" || req.ToInterface == "" {
		writeErr(w, http.StatusBadRequest, errors.New("from_interface and to_interface are required"))
		return
	}
	moved, err := s.client.SwitchInterface(req.FromInterface, req.ToInterface)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "moved": moved})
}

func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var cfg types.QuotaConfig
		if err := decodeJSON(w, r, &cfg); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		cfg.Interface = strings.TrimSpace(cfg.Interface)
		if cfg.Interface == "" {
			writeErr(w, http.StatusBadRequest, errors.New("interface is required"))
			return
		}
		if err := s.client.SetQuota(cfg); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case http.MethodDelete:
		iface := strings.TrimSpace(r.URL.Query().Get("interface"))
		if iface == "" {
			writeErr(w, http.StatusBadRequest, errors.New("interface query parameter required"))
			return
		}
		if err := s.client.RemoveQuota(iface); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST or DELETE required"))
	}
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		Interface  string   `json:"interface"`
		DNSServers []string `json:"dns_servers"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Interface = strings.TrimSpace(req.Interface)
	if req.Interface == "" {
		writeErr(w, http.StatusBadRequest, errors.New("interface is required"))
		return
	}
	servers := make([]string, 0, len(req.DNSServers))
	for _, srv := range req.DNSServers {
		srv = strings.TrimSpace(srv)
		if srv != "" {
			servers = append(servers, srv)
		}
	}
	if err := s.client.SetInterfaceDNS(req.Interface, servers); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	var since uint64
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("invalid since parameter"))
			return
		}
		since = v
	} else if raw := strings.TrimSpace(r.Header.Get("Last-Event-ID")); raw != "" {
		if v, err := strconv.ParseUint(raw, 10, 64); err == nil {
			since = v
		}
	}

	isStream := strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") ||
		r.URL.Query().Get("stream") == "1"
	if !isStream {
		events, err := s.client.ListEvents(since)
		if err != nil {
			if !isUnsupportedErr(err) {
				writeErr(w, http.StatusBadGateway, err)
				return
			}
			events = []types.Event{}
		}
		if events == nil {
			events = []types.Event{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": events})
		return
	}

	s.streamEvents(w, r, since)
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request, lastID uint64) {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sendBatch := func() bool {
		events, err := s.client.ListEvents(lastID)
		if err != nil {
			// Keep stream open if backend is basic or temporarily restarting.
			return true
		}
		for _, ev := range events {
			data, mErr := json.Marshal(ev)
			if mErr != nil {
				continue
			}
			if _, wErr := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", ev.ID, data); wErr != nil {
				return false
			}
			if ev.ID > lastID {
				lastID = ev.ID
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil {
		return
	}
	if flusher != nil {
		flusher.Flush()
	}
	if !sendBatch() {
		return
	}

	ticker := time.NewTicker(s.ssePollInterval())
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !sendBatch() {
				return
			}
		}
	}
}
