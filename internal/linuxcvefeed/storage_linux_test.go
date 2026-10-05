//go:build linux

package linuxcvefeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/linuxcve"
	"localrmm/internal/linuxpackages"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newCache(t *testing.T) (*Cache, *linuxcve.Store, string) {
	t.Helper()
	dir := filepath.Join(privateStateDir(t), "security-data")
	c, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s := &linuxcve.Store{}
	if err = c.Load(context.Background(), s, testNow); err != nil {
		t.Fatal(err)
	}
	return c, s, dir
}

func privateStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func imported(t *testing.T, c *Cache, at time.Time, fixed string) *Candidate {
	t.Helper()
	candidate, err := c.PrepareImport(context.Background(), bytes.NewReader(importFixture(t, linuxcve.DebianProvider, at, debianFixture(fixed))), at)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestProtectedCacheSurvivesRestartWithoutRefreshingAge(t *testing.T) {
	for _, official := range []bool{false, true} {
		t.Run(map[bool]string{false: "import", true: "official"}[official], func(t *testing.T) {
			c, s, dir := newCache(t)
			candidate := imported(t, c, testNow, "1.2-3")
			if official {
				c.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(debianFixture("1.2-3")), nil })
				var err error
				candidate, err = c.FetchDebian(context.Background(), testNow)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Commit(candidate, s, testNow); err != nil {
				t.Fatal(err)
			}
			before := s.Snapshot(linuxpackages.Debian13).Metadata(testNow)
			for _, path := range []string{dir, filepath.Join(dir, "debian-security-tracker.json"), filepath.Join(dir, lockName)} {
				st, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				want := os.FileMode(0600)
				if path == dir {
					want = 0700
				}
				if st.Mode().Perm() != want {
					t.Fatalf("permission %o, want %o", st.Mode().Perm(), want)
				}
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := New(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			now := testNow.Add(72 * time.Hour)
			restored := &linuxcve.Store{}
			if err = restarted.Load(context.Background(), restored, now); err != nil {
				t.Fatal(err)
			}
			after := restored.Snapshot(linuxpackages.Debian13).Metadata(now)
			if after.Freshness != "stale" || !before.FetchedAt.Equal(after.FetchedAt) || !before.ExpiresAt.Equal(after.ExpiresAt) || before.SHA256 != after.SHA256 || before.Trust != after.Trust || !after.ValidatedAt.Equal(now) {
				t.Fatalf("restart changed original provenance/age: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestCommitRequiresInitialLoadAndRejectsPersistentRollback(t *testing.T) {
	dir := filepath.Join(privateStateDir(t), "security-data")
	c, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := &linuxcve.Store{}
	candidate := imported(t, c, testNow, "1.2-3")
	if err = c.Commit(candidate, s, testNow); !errors.Is(err, ErrNotLoaded) {
		t.Fatal(err)
	}
	if err = c.Load(context.Background(), s, testNow); err != nil {
		t.Fatal(err)
	}
	if err = c.Commit(candidate, s, testNow); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "debian-security-tracker.json"))
	for _, next := range []*Candidate{imported(t, c, testNow.Add(-time.Hour), "1.2-2"), imported(t, c, testNow, "1.2-4")} {
		// Deliberately use a separate empty memory store. The loaded cache must
		// retain its own timestamp guard, not rely on only the supplied store.
		if err = c.Commit(next, &linuxcve.Store{}, testNow); !errors.Is(err, linuxcve.ErrRollback) {
			t.Fatalf("got %v", err)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "debian-security-tracker.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("rollback modified persistent snapshot")
	}
}

func TestFailedPromotionPreservesMemoryAndDisk(t *testing.T) {
	for _, failure := range []string{"file sync", "rename", "directory sync"} {
		t.Run(failure, func(t *testing.T) {
			c, s, dir := newCache(t)
			old := imported(t, c, testNow, "1.2-3")
			if err := c.Commit(old, s, testNow); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "debian-security-tracker.json")
			before, _ := os.ReadFile(path)
			disk := c.disk.(*linuxStorage)
			syncOriginal, renameOriginal := disk.sync, disk.rename
			defer func() { disk.sync = syncOriginal; disk.rename = renameOriginal }()
			syncCalls := 0
			switch failure {
			case "file sync":
				disk.sync = func(fd int) error {
					if fd != disk.dirFD() {
						return unix.EIO
					}
					return unix.Fsync(fd)
				}
			case "rename":
				disk.rename = func(int, string, int, string, uint) error { return unix.EIO }
			case "directory sync":
				disk.sync = func(fd int) error {
					if fd == disk.dirFD() {
						syncCalls++
						if syncCalls == 1 {
							return unix.EIO
						}
					}
					return unix.Fsync(fd)
				}
			}
			next := imported(t, c, testNow.Add(time.Hour), "1.2-4")
			if err := c.Commit(next, s, testNow.Add(time.Hour)); !errors.Is(err, ErrIO) {
				t.Fatalf("got %v", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("failed persistence replaced last-good disk bytes")
			}
			if s.Snapshot(linuxpackages.Debian13).Metadata(testNow).SHA256 != old.Metadata(testNow).SHA256 {
				t.Fatal("failed persistence replaced memory")
			}
		})
	}
}

func TestFailedFirstPromotionDoesNotLeavePublishedCache(t *testing.T) {
	c, s, dir := newCache(t)
	disk := c.disk.(*linuxStorage)
	calls := 0
	disk.sync = func(fd int) error {
		if fd == disk.dirFD() {
			calls++
			if calls == 1 {
				return unix.EIO
			}
		}
		return unix.Fsync(fd)
	}
	if err := c.Commit(imported(t, c, testNow, "1.2-3"), s, testNow); !errors.Is(err, ErrIO) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "debian-security-tracker.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed initial promotion left cache")
	}
	if s.Snapshot(linuxpackages.Debian13) != nil {
		t.Fatal("failed initial promotion published memory")
	}
}

func TestUncertainRollbackRetainsPreviousStage(t *testing.T) {
	c, s, dir := newCache(t)
	old := imported(t, c, testNow, "1.2-3")
	if err := c.Commit(old, s, testNow); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "debian-security-tracker.json"))
	disk := c.disk.(*linuxStorage)
	disk.sync = func(fd int) error {
		if fd == disk.dirFD() {
			return unix.EIO
		}
		return unix.Fsync(fd)
	}
	calls := 0
	disk.rename = func(a int, b string, c int, d string, flags uint) error {
		calls++
		if calls == 2 {
			return unix.EIO
		}
		return unix.Renameat2(a, b, c, d, flags)
	}
	if err := c.Commit(imported(t, c, testNow.Add(time.Hour), "1.2-4"), s, testNow.Add(time.Hour)); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	stage, err := os.ReadFile(filepath.Join(dir, ".debian-security-tracker.json.tmp"))
	if err != nil || !bytes.Equal(stage, before) {
		t.Fatal("uncertain rollback deleted prior file")
	}
	if s.Snapshot(linuxpackages.Debian13).Metadata(testNow).SHA256 != old.Metadata(testNow).SHA256 {
		t.Fatal("uncertain commit published memory")
	}
	if err := c.Commit(old, s, testNow.Add(time.Hour)); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("uncertain cache allowed another write: %v", err)
	}
	// Restore I/O, then explicitly revalidate the actual disk publication. The
	// original downloaded timestamp remains intact across this recovery.
	disk.sync, disk.rename = unix.Fsync, unix.Renameat2
	if err := c.Load(context.Background(), s, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(old, s, testNow.Add(time.Hour)); !errors.Is(err, linuxcve.ErrRollback) {
		t.Fatalf("reloaded cache lost on-disk rollback floor: %v", err)
	}
}

func TestCorruptProviderDoesNotEraseOtherProviderOrLastGood(t *testing.T) {
	c, s, dir := newCache(t)
	old := imported(t, c, testNow, "1.2-3")
	if err := c.Commit(old, s, testNow); err != nil {
		t.Fatal(err)
	}
	ubuntu := `[{"id":"UBUNTU-CVE-2025-99998","modified":"2026-10-04T00:00:00Z","affected":[{"package":{"name":"fixture-source","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2-3"}]}]}]}]`
	candidate, err := c.PrepareImport(context.Background(), bytes.NewReader(importFixture(t, linuxcve.UbuntuProvider, testNow, ubuntu)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Commit(candidate, s, testNow); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "debian-security-tracker.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = c.Load(context.Background(), s, testNow); !errors.Is(err, ErrCache) {
		t.Fatal(err)
	}
	if s.Snapshot(linuxpackages.Debian13) == nil || s.Snapshot(linuxpackages.Ubuntu2404) == nil {
		t.Fatal("corruption erased valid memory")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	newStore := &linuxcve.Store{}
	if err = c.Load(context.Background(), newStore, testNow); !errors.Is(err, ErrCache) {
		t.Fatal(err)
	}
	if newStore.Snapshot(linuxpackages.Debian13) != nil || newStore.Snapshot(linuxpackages.Ubuntu2404) == nil {
		t.Fatal("corrupt provider affected independent cache")
	}
}

func TestDirectoryLockAndUnsafePaths(t *testing.T) {
	c, _, dir := newCache(t)
	if second, err := New(dir); !errors.Is(err, ErrLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second writer got %v", err)
	}
	parent := t.TempDir()
	if err := os.Symlink(dir, filepath.Join(parent, "link")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(parent, "link"), parent + "/link/child", "relative/path", parent + "/../security-data", "/"} {
		if other, err := New(path); err == nil {
			other.Close()
			t.Fatalf("unsafe path accepted: %s", path)
		}
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := c.disk.read("debian-security-tracker.json"); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../elsewhere", "/tmp/file", "debian-security-tracker.json/extra"} {
		if _, err := c.disk.read(name); !errors.Is(err, ErrUnsafe) {
			t.Fatal(err)
		}
	}
}

func TestRejectSymlinkHardlinkPermissiveAndSpecialCacheFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			c, s, dir := newCache(t)
			outside := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "debian-security-tracker.json")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(outside, path)
			case "hardlink":
				err = os.Link(outside, path)
			case "mode":
				err = os.WriteFile(path, []byte("invalid"), 0644)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = c.Load(context.Background(), s, testNow); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("read got %v", err)
			}
			if err = c.Commit(imported(t, c, testNow, "1.2-3"), s, testNow); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("write got %v", err)
			}
			unchanged, _ := os.ReadFile(outside)
			if string(unchanged) != "keep" {
				t.Fatal("modified external file")
			}
		})
	}
}

func TestInterruptedStageIsNeverPromotedOrRead(t *testing.T) {
	c, s, dir := newCache(t)
	stage := filepath.Join(dir, ".debian-security-tracker.json.tmp")
	if err := os.WriteFile(stage, []byte("partial stage"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Load(context.Background(), s, testNow); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot(linuxpackages.Debian13) != nil {
		t.Fatal("promoted uncommitted stage")
	}
	if err := c.Commit(imported(t, c, testNow, "1.2-3"), s, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stage not cleaned")
	}
}

func TestCacheRestorationCannotRelabelImportedBytes(t *testing.T) {
	candidate := imported(t, &Cache{}, testNow, "1.2-3")
	var e cacheEnvelope
	if json.Unmarshal(candidate.encoded, &e) != nil {
		t.Fatal("fixture")
	}
	e.Kind = officialKind
	raw, _ := json.Marshal(e)
	if _, err := restore(context.Background(), raw, linuxcve.DebianProvider, testNow); err == nil {
		t.Fatal("import envelope misparsed as official feed")
	}
	if _, err := restore(context.Background(), []byte(strings.Repeat(" ", 10)), linuxcve.DebianProvider, testNow); err == nil {
		t.Fatal("empty JSON accepted")
	}
}
