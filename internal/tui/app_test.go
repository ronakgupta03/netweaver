// internal/tui/app_test.go
package tui

import (
	"testing"
)

func TestInitialModel(t *testing.T) {
	m := InitialModel("/tmp/test.sock")
	if m.client == nil {
		t.Fatal("expected non-nil client")
	}
}
