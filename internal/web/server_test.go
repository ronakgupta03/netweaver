package web

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"netweaver/internal/api"
	"netweaver/internal/types"
)

type fakeBackend struct {
	rules  []types.Rule
	policy string
	assign []string
}

func (f *fakeBackend) ListInterfaces() ([]types.InterfaceInfo, error) {
	return []types.InterfaceInfo{{Name: "wlan0", Index: 4, IP: "10.0.0.2", TableID: 260, Up: true, RxRate: 2048}}, nil
}

func (f *fakeBackend) ListProcesses() ([]types.ProcessInfo, error) {
	return []types.ProcessInfo{{PID: 1725, Name: "firefox", AssignedInterface: "wlan0", Policy: types.PolicyStrict}}, nil
}

func (f *fakeBackend) AssignRoute(pid int, iface string) error {
	f.assign = append(f.assign, iface)
	return nil
}

func (f *fakeBackend) ResetRoute(pid int) error { return nil }

func (f *fakeBackend) ListRules() []types.Rule { return f.rules }

func (f *fakeBackend) AddRule(rule types.Rule) error {
	f.rules = append(f.rules, rule)
	return nil
}

func (f *fakeBackend) RemoveRule(match string) error {
	for i := range f.rules {
		if f.rules[i].Match == match {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeBackend) GetPolicy() string {
	if f.policy == "" {
		return types.PolicyFailover
	}
	return f.policy
}

func (f *fakeBackend) SetPolicy(p string) error {
	f.policy = p
	return nil
}

func startStack(t *testing.T) (*fakeBackend, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "daemon.sock")

	backend := &fakeBackend{}
	daemon := api.NewServer(sock, backend)
	if err := daemon.Start(); err != nil {
		t.Fatalf("daemon: %v", err)
	}
	t.Cleanup(daemon.Stop)

	srv := NewServer("127.0.0.1:0", sock)
	if err := srv.Start(); err != nil {
		t.Fatalf("web: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return backend, "http://" + srv.Addr()
}

func TestIndexServesDashboard(t *testing.T) {
	_, base := startStack(t)
	res, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "NetWeaver") || !strings.Contains(string(body), "/api/state") {
		t.Fatal("dashboard HTML missing expected content")
	}
}

func TestStateEndpointReflectsDaemon(t *testing.T) {
	_, base := startStack(t)
	res, err := http.Get(base + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var state stateResponse
	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if len(state.Interfaces) != 1 || state.Interfaces[0].Name != "wlan0" || state.Interfaces[0].RxRate != 2048 {
		t.Fatalf("interfaces = %+v", state.Interfaces)
	}
	if len(state.Processes) != 1 || state.Processes[0].Name != "firefox" {
		t.Fatalf("processes = %+v", state.Processes)
	}
	if state.Policy != types.PolicyFailover {
		t.Fatalf("policy = %q", state.Policy)
	}
}

func TestRuleAndPolicyMutations(t *testing.T) {
	backend, base := startStack(t)

	res, err := http.Post(base+"/api/rules", "application/json", strings.NewReader(`{"match":"firefox","interface":"wlan0","policy":"strict"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("add rule status = %d", res.StatusCode)
	}
	if len(backend.rules) != 1 || backend.rules[0].Policy != types.PolicyStrict {
		t.Fatalf("rules = %+v", backend.rules)
	}

	req, _ := http.NewRequest(http.MethodDelete, base+"/api/rules?match=firefox", nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(backend.rules) != 0 {
		t.Fatalf("rule not deleted: %+v", backend.rules)
	}

	res, err = http.Post(base+"/api/policy", "application/json", strings.NewReader(`{"policy":"strict"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if backend.policy != types.PolicyStrict {
		t.Fatalf("policy = %q, want strict", backend.policy)
	}

	res, err = http.Post(base+"/api/assign", "application/json", strings.NewReader(`{"pid":1725,"interface":"wlan0"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(backend.assign) != 1 || backend.assign[0] != "wlan0" {
		t.Fatalf("assign calls = %v", backend.assign)
	}
}

func TestInvalidRequestsRejected(t *testing.T) {
	_, base := startStack(t)

	res, err := http.Post(base+"/api/assign", "application/json", strings.NewReader(`{"pid":0}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("assign without pid status = %d, want 400", res.StatusCode)
	}

	res, err = http.Get(base + "/api/rules")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/rules status = %d, want 405", res.StatusCode)
	}

	res, err = http.Get(base + "/missing")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", res.StatusCode)
	}
}
