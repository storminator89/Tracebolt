//go:build !linux

package inventorystate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedPlatformNeverCreatesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if s, e := InitializeNew(path, fixtureBinding, fixtureAgent); s != nil || !errors.Is(e, ErrUnsupported) {
		t.Fatal("unsupported initialization", e)
	}
	if s, e := OpenExisting(path, fixtureBinding, fixtureAgent); s != nil || !errors.Is(e, ErrUnsupported) {
		t.Fatal("unsupported sender", e)
	}
	if e := ValidateExisting(path, fixtureBinding, fixtureAgent); !errors.Is(e, ErrUnsupported) {
		t.Fatal("unsupported validation", e)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("unsupported platform wrote state")
	}
}
