// internal/types/models_test.go
package types

import (
	"testing"
)

func TestInterfaceInfoValidation(t *testing.T) {
	valid := InterfaceInfo{
		Name:    "wlan0",
		Index:   3,
		IP:      "192.168.1.100",
		Gateway: "192.168.1.1",
		TableID: 103,
		Up:      true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid interface, got: %v", err)
	}

	invalidName := valid
	invalidName.Name = "../evil/path"
	if err := invalidName.Validate(); err == nil {
		t.Fatal("expected error on malicious interface name, got nil")
	}

	invalidTable := valid
	invalidTable.TableID = 0
	if err := invalidTable.Validate(); err == nil {
		t.Fatal("expected error on zero TableID, got nil")
	}
}
