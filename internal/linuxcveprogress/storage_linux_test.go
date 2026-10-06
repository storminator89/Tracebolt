//go:build linux

package linuxcveprogress

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func privateParent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newDiskCache(t *testing.T) (*Cache, string) {
	t.Helper()
	dir := filepath.Join(privateParent(t), "cve-progress")
	c, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, dir
}

func TestProtectedRestartPreservesAgeAndExpiry(t *testing.T) {
	c, dir := newDiskCache(t)
	expires := testNow.Add(24 * time.Hour)
	mustSave(t, c, testKey('a'), expires, testNow, " \n {\"cursor\":17}\t")
	before, err := os.ReadFile(filepath.Join(dir, slotNames[0]))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", lockName, slotNames[0]} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if name == "" {
			want = 0700
		}
		if st.Mode().Perm() != want {
			t.Fatalf("mode got %o, want %o", st.Mode().Perm(), want)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	mustLoad(t, restarted, testKey('a'), testNow.Add(3*time.Hour), " \n {\"cursor\":17}\t")
	after, err := os.ReadFile(filepath.Join(dir, slotNames[0]))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restart refreshed durable timestamps", err)
	}
	mustLoad(t, restarted, testKey('a'), expires, "")
	mustLoad(t, restarted, testKey('b'), expires, "")
}

func TestLockExclusionAndRelease(t *testing.T) {
	c, dir := newDiskCache(t)
	if other, err := Open(dir); !errors.Is(err, ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("second process lock: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal("lock not released", err)
	}
	other.Close()
}

func TestUnsafeDirectoryPathsAndNoPermissionRepair(t *testing.T) {
	parent := privateParent(t)
	private := filepath.Join(parent, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "/", "relative/path", parent + "/../unsafe", parent + "/./unsafe", parent + "/null\x00", link, link + "/child"} {
		if c, err := Open(path); !errors.Is(err, ErrUnsafe) {
			if c != nil {
				c.Close()
			}
			t.Fatalf("unsafe path %q accepted: %v", path, err)
		}
	}
	for _, mode := range []os.FileMode{0755, 0770, 0710} {
		if err := os.Chmod(private, mode); err != nil {
			t.Fatal(err)
		}
		if c, err := Open(private); !errors.Is(err, ErrUnsafe) {
			if c != nil {
				c.Close()
			}
			t.Fatal("unsafe directory accepted", err)
		}
		st, _ := os.Stat(private)
		if st.Mode().Perm() != mode {
			t.Fatal("directory permissions repaired")
		}
		// Creating the final component also requires an already-private parent.
		if c, err := Open(filepath.Join(private, "child")); !errors.Is(err, ErrUnsafe) {
			if c != nil {
				c.Close()
			}
			t.Fatal("unsafe parent used to create directory", err)
		}
	}
}

func TestUnsafeFilesAndStagesAreNeverRepaired(t *testing.T) {
	for _, name := range []string{slotNames[0], "." + slotNames[0] + ".tmp"} {
		for _, kind := range []string{"symlink", "hardlink", "permissions", "fifo", "directory", "setuid", "owner"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				c, dir := newDiskCache(t)
				path := filepath.Join(dir, name)
				outside := filepath.Join(privateParent(t), "untouched")
				if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "symlink":
					err = os.Symlink(outside, path)
				case "hardlink":
					err = os.Link(outside, path)
				case "permissions":
					err = os.WriteFile(path, []byte(`{}`), 0644)
				case "fifo":
					err = unix.Mkfifo(path, 0600)
				case "directory":
					err = os.Mkdir(path, 0700)
				case "setuid":
					err = os.WriteFile(path, []byte(`{}`), 0600)
					if err == nil {
						err = os.Chmod(path, 0600|os.ModeSetuid)
					}
				case "owner":
					if os.Geteuid() != 0 {
						t.Skip("fixture ownership change requires effective root")
					}
					err = os.WriteFile(path, []byte(`{}`), 0600)
					if err == nil {
						err = os.Chown(path, 1, 1)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := c.Load(testKey('a'), testNow); !errors.Is(err, ErrUnsafe) || got != nil {
					t.Fatalf("unsafe load got %q, %v", got, err)
				}
				if err := c.Save(testKey('a'), testNow.Add(time.Hour), testNow, []byte(`{}`)); !errors.Is(err, ErrUnsafe) {
					t.Fatal("unsafe save", err)
				}
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
					t.Fatal("unsafe file repaired", err)
				}
				raw, err := os.ReadFile(outside)
				if err != nil || string(raw) != "untouched" {
					t.Fatal("outside file modified", err)
				}
			})
		}
	}
}

func TestUnsafeLocksRejected(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "contents", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateParent(t)
			path := filepath.Join(dir, lockName)
			outside := filepath.Join(privateParent(t), "untouched")
			if err := os.WriteFile(outside, nil, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(outside, path)
			case "hardlink":
				err = os.Link(outside, path)
			case "mode":
				err = os.WriteFile(path, nil, 0644)
			case "contents":
				err = os.WriteFile(path, []byte("x"), 0600)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if c, err := Open(dir); !errors.Is(err, ErrUnsafe) {
				if c != nil {
					c.Close()
				}
				t.Fatal("unsafe lock accepted", err)
			}
		})
	}
}

func TestFileAndDirectoryOwnershipPredicates(t *testing.T) {
	uid := uint32(os.Geteuid())
	file := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: uid, Nlink: 1}
	if !privateFile(file) {
		t.Fatal("private owner file rejected")
	}
	file.Uid = uid + 1
	if privateFile(file) {
		t.Fatal("different owner file accepted")
	}
	dir := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: uid, Nlink: 2}
	if !trustedDirectory(dir, true) {
		t.Fatal("private owner directory rejected")
	}
	dir.Uid = uid + 1
	if trustedDirectory(dir, true) || trustedDirectory(dir, false) {
		t.Fatal("different non-root owner directory accepted")
	}
	dir.Uid = 0
	dir.Mode = unix.S_IFDIR | 0755
	if !trustedDirectory(dir, false) || trustedDirectory(dir, true) {
		t.Fatal("root ancestor trust changed private-directory requirement")
	}
	dir.Mode = unix.S_IFDIR | 0777
	if trustedDirectory(dir, false) {
		t.Fatal("non-sticky writable ancestor accepted")
	}
	dir.Mode |= unix.S_ISVTX
	if !trustedDirectory(dir, false) {
		t.Fatal("root-owned sticky ancestor rejected")
	}
}

func TestPathAndLockSubstitutionAfterOpen(t *testing.T) {
	for _, kind := range []string{"directory permissions", "directory replacement", "ancestor replacement", "lock replacement"} {
		t.Run(kind, func(t *testing.T) {
			c, dir := newDiskCache(t)
			var err error
			switch kind {
			case "directory permissions":
				err = os.Chmod(dir, 0755)
			case "directory replacement":
				err = os.Rename(dir, dir+"-old")
				if err == nil {
					err = os.Mkdir(dir, 0700)
				}
			case "ancestor replacement":
				parent := filepath.Dir(dir)
				err = os.Rename(parent, parent+"-old")
				if err == nil {
					t.Cleanup(func() { _ = os.Rename(parent+"-old", parent) })
					err = os.Symlink(parent+"-old", parent)
					t.Cleanup(func() { _ = os.Remove(parent) })
				}
			case "lock replacement":
				err = os.Rename(filepath.Join(dir, lockName), filepath.Join(dir, "old-lock"))
				if err == nil {
					err = os.WriteFile(filepath.Join(dir, lockName), nil, 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Load(testKey('a'), testNow); !errors.Is(err, ErrUnsafe) {
				t.Fatal("path substitution permitted read", err)
			}
			if err := c.Save(testKey('a'), testNow.Add(time.Hour), testNow, []byte(`{}`)); !errors.Is(err, ErrUnsafe) {
				t.Fatal("path substitution permitted write", err)
			}
		})
	}
}

func TestCorruptAndOversizedDiskCheckpointsNotEvicted(t *testing.T) {
	for _, raw := range []string{"", "broken", strings.Repeat(" ", MaxEnvelopeBytes+1)} {
		t.Run("bytes-"+string(rune(len(raw)%100+65)), func(t *testing.T) {
			c, dir := newDiskCache(t)
			path := filepath.Join(dir, slotNames[3])
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if data, err := c.Load(testKey('a'), testNow); !errors.Is(err, ErrCorrupt) || data != nil {
				t.Fatalf("corrupt file accepted: %q, %v", data, err)
			}
			if err := c.Save(testKey('a'), testNow.Add(time.Hour), testNow, []byte(`{}`)); !errors.Is(err, ErrCorrupt) {
				t.Fatal("corrupt slot ignored during save", err)
			}
			unchanged, err := os.ReadFile(path)
			if err != nil || string(unchanged) != raw {
				t.Fatal("corrupt checkpoint changed", err)
			}
		})
	}
}

func TestFailedPromotionsKeepPriorDurableBytes(t *testing.T) {
	for _, exists := range []bool{false, true} {
		for _, failure := range []string{"file sync", "rename", "directory sync"} {
			t.Run(map[bool]string{false: "new/", true: "replace/"}[exists]+failure, func(t *testing.T) {
				c, dir := newDiskCache(t)
				expires := testNow.Add(24 * time.Hour)
				prior := ""
				if exists {
					prior = `{"cursor":10}`
					mustSave(t, c, testKey('a'), expires, testNow, prior)
				}
				before, _ := os.ReadFile(filepath.Join(dir, slotNames[0]))
				disk := c.disk.(*linuxStorage)
				calls := 0
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
							calls++
							if calls == 1 {
								return unix.EIO
							}
						}
						return unix.Fsync(fd)
					}
				}
				if err := c.Save(testKey('a'), expires, testNow.Add(time.Hour), []byte(`{"cursor":20}`)); !errors.Is(err, ErrIO) {
					t.Fatalf("failed save got %v", err)
				}
				after, err := os.ReadFile(filepath.Join(dir, slotNames[0]))
				if exists && (err != nil || !bytes.Equal(before, after)) || !exists && !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed promotion changed publication", err)
				}
				disk.sync, disk.rename = unix.Fsync, unix.Renameat2
				mustLoad(t, c, testKey('a'), testNow.Add(time.Hour), prior)
				mustSave(t, c, testKey('a'), expires, testNow.Add(time.Hour), `{"cursor":30}`)
			})
		}
	}
}

func TestUncertainPromotionPoisonsInstance(t *testing.T) {
	for _, failure := range []string{"rollback rename", "rollback sync", "rename reports error after mutation", "first promotion rollback sync"} {
		t.Run(failure, func(t *testing.T) {
			c, dir := newDiskCache(t)
			expires := testNow.Add(24 * time.Hour)
			if failure != "first promotion rollback sync" {
				mustSave(t, c, testKey('a'), expires, testNow, `{"cursor":10}`)
			}
			disk := c.disk.(*linuxStorage)
			if failure != "rename reports error after mutation" {
				disk.sync = func(fd int) error {
					if fd == disk.dirFD() {
						return unix.EIO
					}
					return unix.Fsync(fd)
				}
			}
			calls := 0
			if failure == "rollback rename" {
				disk.rename = func(a int, b string, c int, d string, flags uint) error {
					calls++
					if calls == 2 {
						return unix.EIO
					}
					return unix.Renameat2(a, b, c, d, flags)
				}
			} else if failure == "rename reports error after mutation" {
				disk.rename = func(a int, b string, c int, d string, flags uint) error {
					if err := unix.Renameat2(a, b, c, d, flags); err != nil {
						return err
					}
					return unix.EIO
				}
			}
			if err := c.Save(testKey('a'), expires, testNow.Add(time.Hour), []byte(`{"cursor":20}`)); !errors.Is(err, ErrUncertain) {
				t.Fatalf("uncertain save got %v", err)
			}
			disk.sync, disk.rename = unix.Fsync, unix.Renameat2
			if _, err := c.Load(testKey('a'), testNow.Add(time.Hour)); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain instance allowed read", err)
			}
			if err := c.Save(testKey('b'), expires, testNow.Add(time.Hour), []byte(`{}`)); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain instance allowed write", err)
			}
			if failure == "rollback rename" || failure == "rename reports error after mutation" {
				stage, err := os.ReadFile(filepath.Join(dir, "."+slotNames[0]+".tmp"))
				if err != nil || !bytes.Contains(stage, []byte(`"cursor":10`)) {
					t.Fatal("previous stage lost after uncertain publication", err)
				}
			}
		})
	}
}

func TestInterruptedPrivateStageNeverLoadsAndSafeSaveDiscardsIt(t *testing.T) {
	c, dir := newDiskCache(t)
	stage := filepath.Join(dir, "."+slotNames[0]+".tmp")
	if err := os.WriteFile(stage, []byte(`{"partial"`), 0600); err != nil {
		t.Fatal(err)
	}
	mustLoad(t, c, testKey('a'), testNow, "")
	mustSave(t, c, testKey('a'), testNow.Add(time.Hour), testNow, `{"cursor":1}`)
	mustLoad(t, c, testKey('a'), testNow, `{"cursor":1}`)
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stage not removed after successful save", err)
	}
}

func TestConcurrentLoadsAndSavesStayBound(t *testing.T) {
	c, _ := newDiskCache(t)
	var wg sync.WaitGroup
	for _, key := range []byte{'a', 'b', 'c', 'd'} {
		wg.Add(1)
		go func(key byte) {
			defer wg.Done()
			want := `{"binding":"` + string(key) + `"}`
			for range 8 {
				if err := c.Save(testKey(key), testNow.Add(time.Hour), testNow, []byte(want)); err != nil {
					t.Error(err)
					return
				}
				if raw, err := c.Load(testKey(key), testNow); err != nil || string(raw) != want {
					t.Errorf("binding mixed: %q, %v", raw, err)
					return
				}
			}
		}(key)
	}
	wg.Wait()
}
