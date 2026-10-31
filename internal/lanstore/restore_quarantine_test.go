//go:build linux

package lanstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func quarantineStoreTempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private-state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRestoreQuarantinePreservesHistoricalBytesAndCannotRearm(t *testing.T) {
	dir := quarantineStoreTempDir(t)
	// Invented strings only: no credential, database, native restore or host read.
	files := map[string][]byte{
		"agents.db":            []byte("old approval before revocation"),
		"enrollment-v2.db":     []byte("old consumed-action and replay floors"),
		"operator.db":          []byte("old consent before withdrawal"),
		"enrollment-v2.db-wal": []byte("retained invented sidecar"),
		"profile":              []byte("retained invented profile"),
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckRestoreQuarantine(dir); err != nil {
		t.Fatal(err)
	}
	if err := MarkRestoreQuarantine(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, RestoreQuarantineFile)
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		t.Fatal("marker was not written")
	}
	before, err := os.Stat(path)
	if err != nil || before.Mode().Perm() != 0600 {
		t.Fatal("marker is not private")
	}
	for i := 0; i < 2; i++ {
		if err := CheckRestoreQuarantine(dir); !errors.Is(err, ErrRestoreQuarantined) {
			t.Fatal("quarantine did not survive reinspection", err)
		}
		if err := MarkRestoreQuarantine(dir); !errors.Is(err, ErrRestoreQuarantined) {
			t.Fatal("existing marker was adopted or overwritten", err)
		}
	}
	after, err := os.Stat(path)
	got, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) || !bytes.Equal(raw, got) {
		t.Fatal("repeated marking changed original quarantine")
	}
	for name, expected := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(expected, got) {
			t.Fatal("historical authority bytes were changed", name)
		}
	}
}

func TestRestoreQuarantineEveryMarkerObjectDeniesWithoutReading(t *testing.T) {
	for _, kind := range []string{"empty", "partial", "unknown", "directory", "dangling-symlink", "symlink", "fifo", "hardlink", "public-mode"} {
		t.Run(kind, func(t *testing.T) {
			dir := quarantineStoreTempDir(t)
			path := filepath.Join(dir, RestoreQuarantineFile)
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "dangling-symlink":
				err = os.Symlink(filepath.Join(dir, "absent"), path)
			case "symlink":
				target := filepath.Join(dir, "untouched")
				if err = os.WriteFile(target, []byte("original"), 0600); err == nil {
					err = os.Symlink(target, path)
				}
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "hardlink":
				target := filepath.Join(dir, "untouched")
				if err = os.WriteFile(target, []byte("original"), 0600); err == nil {
					err = os.Link(target, path)
				}
			default:
				raw := []byte{}
				if kind == "partial" {
					raw = []byte("tracebolt.")
				}
				if kind == "unknown" {
					raw = []byte("not-a-release-authorization")
				}
				err = os.WriteFile(path, raw, 0600)
				if err == nil && kind == "public-mode" {
					err = os.Chmod(path, 0644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = CheckRestoreQuarantine(dir); !errors.Is(err, ErrRestoreQuarantined) {
				t.Fatal("marker object was ignored", err)
			}
			if err = MarkRestoreQuarantine(dir); !errors.Is(err, ErrRestoreQuarantined) {
				t.Fatal("marker object was overwritten", err)
			}
			if kind == "symlink" || kind == "hardlink" {
				if raw, err := os.ReadFile(filepath.Join(dir, "untouched")); err != nil || string(raw) != "original" {
					t.Fatal("link target changed or disappeared", err)
				}
			}
		})
	}
}

func TestRestoreQuarantineProtectedPathsAndMissingDirectory(t *testing.T) {
	dir := quarantineStoreTempDir(t)
	missing := filepath.Join(dir, "missing")
	if err := CheckRestoreQuarantine(missing); err != nil {
		t.Fatal("ordinary fresh startup was blocked", err)
	}
	if err := MarkRestoreQuarantine(missing); !errors.Is(err, ErrStorage) {
		t.Fatal("missing directory was created", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("missing directory changed")
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(dir, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", ".", "relative", dir + "/../invalid", link, filepath.Join(link, "child"), regular, public} {
		if err := CheckRestoreQuarantine(path); !errors.Is(err, ErrStorage) {
			t.Fatal("unsafe inspection accepted", path, err)
		}
		if err := MarkRestoreQuarantine(path); !errors.Is(err, ErrStorage) {
			t.Fatal("unsafe mark accepted", path, err)
		}
	}
}

func TestRestoreQuarantineConcurrentCreationHasOneWinner(t *testing.T) {
	dir := quarantineStoreTempDir(t)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := MarkRestoreQuarantine(dir)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrRestoreQuarantined) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("exclusive marker creation failed", winners.Load())
	}
	if err := CheckRestoreQuarantine(dir); !errors.Is(err, ErrRestoreQuarantined) {
		t.Fatal(err)
	}
}
