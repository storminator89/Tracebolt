//go:build !darwin

package macosinventorysender

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStorageUnsupportedDoesNotCreateFiles(t *testing.T) {
	enable, _ := storageFixtureEnable(t)
	path := filepath.Join(t.TempDir(), "not-created")
	if s, err := OpenFreshStorage(path, enable); s != nil || !errors.Is(err, ErrStorageUnsupported) {
		t.Fatal("non-Darwin adapter implied")
	}
	if s, raw, err := OpenExistingStorage(path, enable); s != nil || raw != nil || !errors.Is(err, ErrStorageUnsupported) {
		t.Fatal("non-Darwin reopen implied")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsupported path mutated")
	}
}
