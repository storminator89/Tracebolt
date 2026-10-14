//go:build !((darwin && !ios) || (linux && !android))

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedPlatformRejectsSelectedRegular(t *testing.T) {
	for _, selected := range []struct {
		name  string
		limit int64
	}{
		{"candidate.tar.gz", maxPackage},
		{"public-bootstrap.json", 64 << 10},
	} {
		name := filepath.Join(t.TempDir(), selected.name)
		bytes := []byte("selected public test input")
		if err := os.WriteFile(name, bytes, 0600); err != nil {
			t.Fatal(err)
		}
		f, err := openSelectedRegular(name, selected.limit)
		if f != nil {
			_ = f.Close()
			t.Fatalf("unsupported host opened %s", selected.name)
		}
		if !errors.Is(err, errRejected) {
			t.Fatalf("unsupported host must reject %s: %v", selected.name, err)
		}
		digest := sha256.Sum256(bytes)
		sha := hex.EncodeToString(digest[:])
		if selected.limit == maxPackage {
			if _, err := verifyPackage(name, sha, "amd64"); !errors.Is(err, errRejected) {
				t.Fatalf("unsupported host must reject package verification: %v", err)
			}
		} else if _, err := readBootstrap(name, sha, "basic-readonly-v1", false); !errors.Is(err, errRejected) {
			t.Fatalf("unsupported host must reject bootstrap selection: %v", err)
		}
	}
}
