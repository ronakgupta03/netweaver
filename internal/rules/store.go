// internal/rules/store.go
package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"netweaver/internal/types"
)

// Store keeps auto-routing rules on disk as JSON and serves them to the daemon.
type Store struct {
	mu      sync.RWMutex
	path    string
	rules   []types.Rule
	version uint64
}

type fileFormat struct {
	Rules []types.Rule `json:"rules"`
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load reads rules from disk; a missing file is an empty rule set.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.rules = nil
			return nil
		}
		return fmt.Errorf("reading rules: %w", err)
	}

	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing rules: %w", err)
	}
	var loaded []types.Rule
	for _, r := range f.Rules {
		if r.Match == "" || r.Interface == "" {
			continue
		}
		loaded = append(loaded, types.Rule{
			Match:        r.Match,
			Interface:    r.Interface,
			Policy:       r.NormalizedPolicy(),
			Domains:      cleanStrings(r.Domains),
			RateLimitBps: r.RateLimitBps,
			Background:   r.Background,
		})
	}
	s.rules = loaded
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileFormat{Rules: s.rules}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Version increments on every mutation so watchers can detect reloads.
func (s *Store) Version() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *Store) List() []types.Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.Rule, len(s.rules))
	for i, r := range s.rules {
		r.Domains = cleanStrings(r.Domains)
		out[i] = r
	}
	return out
}

// Add inserts or updates a rule keyed by its match pattern (case-insensitive).
func (s *Store) Add(rule types.Rule) error {
	rule.Match = strings.TrimSpace(rule.Match)
	rule.Interface = strings.TrimSpace(rule.Interface)
	if rule.Match == "" {
		return errors.New("rule match pattern is required")
	}
	if rule.Interface == "" {
		return errors.New("rule interface is required")
	}
	if !types.IsVirtualProfile(rule.Interface) && !types.ValidInterfaceName(rule.Interface) {
		return fmt.Errorf("invalid interface or virtual profile %q", rule.Interface)
	}
	if !types.ValidPolicy(rule.Policy) {
		return fmt.Errorf("unknown policy %q (use failover or strict)", rule.Policy)
	}
	rule.Policy = rule.NormalizedPolicy()
	rule.Domains = cleanStrings(rule.Domains)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.version++
	for i := range s.rules {
		if strings.EqualFold(s.rules[i].Match, rule.Match) {
			s.rules[i] = rule
			return s.saveLocked()
		}
	}
	s.rules = append(s.rules, rule)
	return s.saveLocked()
}

func cleanStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Store) Remove(match string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if strings.EqualFold(s.rules[i].Match, match) {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			s.version++
			return s.saveLocked()
		}
	}
	return fmt.Errorf("no rule matching %q", match)
}

func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = nil
	s.version++
	return s.saveLocked()
}

// Match returns the first rule matching a process name or command line.
func (s *Store) Match(name, cmdline string) (types.Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := matchRules(s.rules, name, cmdline)
	if ok {
		r.Domains = cleanStrings(r.Domains)
	}
	return r, ok
}

// matchRules resolves a rule against a process.
//
// Plain patterns match the executable name (the kernel's comm) only, so a
// "firefox" rule binds the browser process group without also matching every
// "Web Content" helper. Two opt-in prefixes widen the match:
//
//	bin:firefox        argv[0] basename (catches helpers sharing a binary)
//	cmd:*-silent       full command line
func matchRules(list []types.Rule, name, cmdline string) (types.Rule, bool) {
	base := ""
	if fields := strings.Fields(cmdline); len(fields) > 0 {
		base = filepath.Base(fields[0])
	}
	for _, r := range list {
		pattern := r.Match
		switch {
		case strings.HasPrefix(pattern, "bin:"):
			if base != "" && matchOne(strings.TrimPrefix(pattern, "bin:"), base) {
				return r, true
			}
		case strings.HasPrefix(pattern, "cmd:"):
			if cmdline != "" && matchCommandLine(strings.TrimPrefix(pattern, "cmd:"), strings.TrimSpace(cmdline)) {
				return r, true
			}
		default:
			if matchOne(pattern, name) {
				return r, true
			}
		}
	}
	return types.Rule{}, false
}

// matchCommandLine glob-matches a whole command line, where "*" also spans
// spaces and path separators (path.Match stops at '/').
func matchCommandLine(pattern, candidate string) bool {
	quoted := regexp.QuoteMeta(strings.ToLower(pattern))
	quoted = strings.ReplaceAll(quoted, `\*`, ".*")
	quoted = strings.ReplaceAll(quoted, `\?`, ".")
	re, err := regexp.Compile("^" + quoted + "$")
	if err != nil {
		return false
	}
	return re.MatchString(strings.ToLower(candidate))
}

func matchOne(pattern, candidate string) bool {
	if candidate == "" {
		return false
	}
	if strings.EqualFold(pattern, candidate) {
		return true
	}
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(candidate))
	return err == nil && ok
}
