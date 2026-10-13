//go:build darwin

package macosinventorysender

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Native fixture tests are compiled on non-Darwin hosts, NEVER executed there.
// Separately authorized macOS runs are required to establish syscall, ACL,
// process-lock and filesystem behavior. These use newly created synthetic files.
func storageDarwinFixture(t *testing.T) (*Storage, string, []byte, []byte, time.Time) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fixture canonical path")
	}
	path := filepath.Join(base, "inventory")
	enable, at := storageFixtureEnable(t)
	s, err := OpenFreshStorage(path, enable)
	if err != nil {
		t.Fatal("protected fresh fixture rejected", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	raw := storageFixtureCheckpoint(t, enable, at)
	if s.CreateFresh(raw) != nil {
		t.Fatal("protected fixture initialization")
	}
	return s, path, enable, raw, at
}
func TestStorageDarwinRoundTripAndNoop(t *testing.T) {
	s, path, enable, raw, at := storageDarwinFixture(t)
	before, err := os.Stat(filepath.Join(path, storageCheckpointName))
	if err != nil {
		t.Fatal("fixture stat")
	}
	if s.Commit(raw, raw) != nil {
		t.Fatal("verified no-op")
	}
	after, err := os.Stat(filepath.Join(path, storageCheckpointName))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("no-op replaced checkpoint")
	}
	if other, _, err := OpenExistingStorage(path, enable); !errors.Is(err, ErrStorageLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second owner admitted")
	}
	next := storageFixtureCheckpoint(t, enable, at.Add(time.Second))
	if s.Commit(raw, next) != nil {
		t.Fatal("atomic replacement")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restored, actual, err := OpenExistingStorage(path, enable)
	if err != nil {
		t.Fatal("existing fixture rejected", err)
	}
	defer restored.Close()
	if !bytes.Equal(actual, next) || restored.Commit(actual, actual) != nil {
		t.Fatal("exact reopen")
	}
	if other, err := OpenFreshStorage(path, enable); err == nil {
		other.Close()
		t.Fatal("used storage reset")
	}
}
func TestStorageDarwinCrossProcessLock(t *testing.T) {
	_, path, _, _, _ := storageDarwinFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestStorageDarwinLockChild$")
	cmd.Env = append(os.Environ(), "TRACEBOLT_SYNTHETIC_INVENTORY_LOCK_PATH="+path)
	if err := cmd.Run(); err != nil {
		t.Fatal("cross-process exclusion fixture")
	}
}
func TestStorageDarwinLockChild(t *testing.T) {
	path := os.Getenv("TRACEBOLT_SYNTHETIC_INVENTORY_LOCK_PATH")
	if path == "" {
		t.Skip("subprocess-only synthetic fixture")
	}
	enable, _ := storageFixtureEnable(t)
	other, _, err := OpenExistingStorage(path, enable)
	if other != nil {
		other.Close()
	}
	if !errors.Is(err, ErrStorageLocked) {
		t.Fatal("exclusive owner not enforced")
	}
}
func TestStorageDarwinMissingAndUnexpectedEntries(t *testing.T) {
	for _, name := range []string{storageUsedName, storageReadyName, storageCheckpointName, storageLockName} {
		t.Run(name, func(t *testing.T) {
			s, path, enable, raw, _ := storageDarwinFixture(t)
			if os.Remove(filepath.Join(path, name)) != nil {
				t.Fatal("fixture remove")
			}
			if s.Commit(raw, raw) == nil {
				t.Fatal("missing entry no-op accepted")
			}
			s.Close()
			if other, _, err := OpenExistingStorage(path, enable); err == nil {
				other.Close()
				t.Fatal("missing state recreated")
			}
			if other, err := OpenFreshStorage(path, enable); err == nil {
				other.Close()
				t.Fatal("used marker reset")
			}
		})
	}
	for _, name := range []string{storageTempName, "unrecognized"} {
		s, path, enable, raw, _ := storageDarwinFixture(t)
		if os.WriteFile(filepath.Join(path, name), []byte("synthetic interrupted write"), 0600) != nil {
			t.Fatal("fixture unknown")
		}
		if s.Commit(raw, raw) == nil {
			t.Fatal("unknown entry ignored")
		}
		s.Close()
		if other, _, err := OpenExistingStorage(path, enable); err == nil {
			other.Close()
			t.Fatal("unknown entry repaired")
		}
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Fatal("interrupted bytes removed")
		}
	}
}
func TestStorageDarwinExpectedInodeBytesAndProtection(t *testing.T) {
	for _, mutation := range []string{"inode", "bytes", "symlink", "hardlink", "mode"} {
		t.Run(mutation, func(t *testing.T) {
			s, path, _, raw, _ := storageDarwinFixture(t)
			checkpoint := filepath.Join(path, storageCheckpointName)
			switch mutation {
			case "inode":
				replacement := filepath.Join(filepath.Dir(path), "replacement")
				if os.WriteFile(replacement, raw, 0600) != nil || os.Rename(replacement, checkpoint) != nil {
					t.Fatal("replacement fixture")
				}
			case "bytes":
				changed := append(bytes.Clone(raw), '\n')
				if os.WriteFile(checkpoint, changed, 0600) != nil {
					t.Fatal("changed fixture")
				}
			case "symlink":
				target := filepath.Join(filepath.Dir(path), "target")
				if os.WriteFile(target, raw, 0600) != nil || os.Remove(checkpoint) != nil || os.Symlink(target, checkpoint) != nil {
					t.Fatal("symlink fixture")
				}
			case "hardlink":
				if os.Link(checkpoint, filepath.Join(filepath.Dir(path), "extra-link")) != nil {
					t.Fatal("hardlink fixture")
				}
			case "mode":
				if os.Chmod(checkpoint, 0644) != nil {
					t.Fatal("mode fixture")
				}
			}
			if s.Commit(raw, raw) == nil {
				t.Fatal("altered checkpoint accepted by no-op")
			}
		})
	}
}
func TestStorageDarwinCanonicalPathAndNoAdoption(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fixture")
	}
	enable, _ := storageFixtureEnable(t)
	for _, path := range []string{"relative", "/", base + "/../inventory", base + "//inventory", base + "/inventory/"} {
		if s, err := OpenFreshStorage(path, enable); err == nil {
			s.Close()
			t.Fatal("noncanonical path accepted")
		}
	}
	missing := filepath.Join(base, "missing")
	if s, _, err := OpenExistingStorage(missing, enable); err == nil {
		s.Close()
		t.Fatal("missing path initialized")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("existing open mutated missing path")
	}
	original := filepath.Join(base, "fresh")
	s, err := OpenFreshStorage(original, enable)
	if err != nil {
		t.Fatal("fresh lock")
	}
	s.Close()
	if s, err := OpenFreshStorage(original, enable); err == nil {
		s.Close()
		t.Fatal("interrupted lock-only domain adopted")
	}
	alias := filepath.Join(base, "alias")
	if os.Symlink(original, alias) != nil {
		t.Fatal("alias fixture")
	}
	if s, err := OpenFreshStorage(alias, enable); err == nil {
		s.Close()
		t.Fatal("symlink alias followed")
	}
}
func TestStorageDarwinPublicationFlagsAndIrreversibleMarkers(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fixture")
	}
	path := filepath.Join(base, "inventory")
	enable, at := storageFixtureEnable(t)
	s, err := OpenFreshStorage(path, enable)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := s.backend.(*darwinInventoryStorage)
	originalRename := b.ops.rename
	calls := 0
	b.ops.rename = func(from int, old string, to int, next string, flags uint32) error {
		calls++
		if flags != unix.RENAME_EXCL {
			t.Error("fresh publication was replace-capable")
		}
		if next == storageCheckpointName {
			// The used fence must be fully published before any checkpoint rename.
			if _, err := os.Stat(filepath.Join(path, storageUsedName)); err != nil {
				t.Error("checkpoint precedes used fence")
			}
			if err := originalRename(from, old, to, next, flags); err != nil {
				return err
			}
			return unix.EIO // Publication happened but acknowledgement is uncertain.
		}
		return originalRename(from, old, to, next, flags)
	}
	raw := storageFixtureCheckpoint(t, enable, at)
	if s.CreateFresh(raw) == nil {
		t.Fatal("uncertain fresh publication succeeded")
	}
	count := calls
	if s.CreateFresh(raw) == nil || s.Commit(raw, raw) == nil || calls != count {
		t.Fatal("uncertain callbacks retried")
	}
	s.Close()
	if _, err := os.Stat(filepath.Join(path, storageUsedName)); err != nil {
		t.Fatal("used fence removed")
	}
	if other, _, err := OpenExistingStorage(path, enable); err == nil {
		other.Close()
		t.Fatal("partial fresh completed automatically")
	}
	if other, err := OpenFreshStorage(path, enable); err == nil {
		other.Close()
		t.Fatal("partial fresh reset")
	}
}
func TestStorageDarwinReplacementErrorAndPanicPoison(t *testing.T) {
	for _, panics := range []bool{false, true} {
		s, path, enable, raw, at := storageDarwinFixture(t)
		b := s.backend.(*darwinInventoryStorage)
		originalRename := b.ops.rename
		next := storageFixtureCheckpoint(t, enable, at.Add(time.Second))
		b.ops.rename = func(from int, old string, to int, name string, flags uint32) error {
			if name != storageCheckpointName || flags != 0 {
				t.Error("marker rewrite or exclusive replacement")
			}
			if err := originalRename(from, old, to, name, flags); err != nil {
				return err
			}
			if panics {
				panic("synthetic callback panic")
			}
			return unix.EIO
		}
		var err error
		panicSeen := storageRecover(func() { err = s.Commit(raw, next) })
		if !panicSeen && err == nil {
			t.Fatal("uncertain replacement accepted")
		}
		if s.Commit(raw, next) == nil {
			t.Fatal("poisoned adapter reused")
		}
		s.Close()
		restored, actual, err := OpenExistingStorage(path, enable)
		if err != nil {
			t.Fatal("reopen inspection", err)
		}
		if !bytes.Equal(actual, next) {
			t.Fatal("reopen rolled back uncertain publication")
		}
		restored.Close()
	}
}
