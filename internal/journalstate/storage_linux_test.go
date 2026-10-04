//go:build linux

package journalstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"localrmm/internal/journalrequest"
)

func write(t *testing.T, p string, b []byte, mode os.FileMode) {
	t.Helper()
	if e := os.WriteFile(p, b, mode); e != nil {
		t.Fatal(e)
	}
}
func chmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if e := os.Chmod(p, mode); e != nil {
		t.Fatal(e)
	}
}
func remove(t *testing.T, p string) {
	t.Helper()
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
}
func TestPrivateModesAndNumericOwnerRules(t *testing.T) {
	s, dir := fixture(t)
	for _, name := range []string{"", stateName, lockName} {
		info, e := os.Stat(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		want := os.FileMode(0600)
		if name == "" {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatal("wrong mode")
		}
	}
	uid := uint32(os.Geteuid())
	file := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: uid, Nlink: 1}
	if !privateFile(file) {
		t.Fatal("valid file refused")
	}
	file.Uid = uid + 1
	if privateFile(file) {
		t.Fatal("foreign owner accepted")
	}
	file.Uid = uid
	file.Nlink = 2
	if privateFile(file) {
		t.Fatal("hardlink accepted")
	}
	d := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: uid, Nlink: 2}
	if !trustedDirectory(d, true) {
		t.Fatal("owned dir refused")
	}
	d.Uid = uid + 1
	if trustedDirectory(d, true) {
		t.Fatal("foreign dir accepted")
	}
	_ = s.Close()
}
func TestUnsafePathsRefusedWithoutRepair(t *testing.T) {
	for _, kind := range []string{"directory-mode", "directory-symlink", "ancestor-symlink", "ancestor-writable", "state-mode", "lock-mode", "state-symlink", "lock-symlink", "state-hardlink", "lock-hardlink", "state-directory", "lock-directory", "unknown-entry", "state-absent", "lock-absent", "corrupt", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := fixture(t)
			_ = s.Close()
			statePath := filepath.Join(dir, stateName)
			lockPath := filepath.Join(dir, lockName)
			target := statePath
			switch kind {
			case "directory-mode":
				chmod(t, dir, 0755)
			case "directory-symlink":
				renamed := dir + "-real"
				if e := os.Rename(dir, renamed); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(renamed, dir); e != nil {
					t.Fatal(e)
				}
			case "ancestor-symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if e := os.Symlink(filepath.Dir(dir), alias); e != nil {
					t.Fatal(e)
				}
				dir = filepath.Join(alias, "journal")
			case "ancestor-writable":
				chmod(t, filepath.Dir(dir), 0777)
			case "state-mode":
				chmod(t, statePath, 0644)
			case "lock-mode":
				chmod(t, lockPath, 0644)
			case "lock-symlink", "lock-hardlink", "lock-directory":
				target = lockPath
				fallthrough
			case "state-symlink", "state-hardlink", "state-directory":
				external := filepath.Join(t.TempDir(), "inert")
				write(t, external, read(t, target), 0600)
				remove(t, target)
				var e error
				if strings.HasSuffix(kind, "symlink") {
					e = os.Symlink(external, target)
				} else if strings.HasSuffix(kind, "hardlink") {
					e = os.Link(external, target)
				} else {
					e = os.Mkdir(target, 0700)
				}
				if e != nil {
					t.Fatal(e)
				}
			case "unknown-entry":
				write(t, filepath.Join(dir, "unexpected"), []byte("synthetic"), 0600)
			case "state-absent":
				remove(t, statePath)
			case "lock-absent":
				remove(t, lockPath)
			case "corrupt":
				write(t, statePath, []byte(`{"version":null}`), 0600)
			case "oversized":
				write(t, statePath, bytes.Repeat([]byte("x"), MaxStateBytes+1), 0600)
			}
			got, e := Open(context.Background(), dir, testCurrent.SenderBinding)
			if got != nil {
				_ = got.Close()
				t.Fatal("unsafe path accepted")
			}
			if e == nil {
				t.Fatal("missing error")
			}
			if kind == "directory-mode" {
				info, _ := os.Stat(dir)
				if info.Mode().Perm() != 0755 {
					t.Fatal("directory repaired")
				}
			}
			if kind == "state-mode" {
				info, _ := os.Stat(statePath)
				if info.Mode().Perm() != 0644 {
					t.Fatal("file repaired")
				}
			}
			if kind == "state-absent" {
				if _, e = os.Stat(statePath); !os.IsNotExist(e) {
					t.Fatal("state recreated")
				}
			}
			if kind == "lock-absent" {
				if _, e = os.Stat(lockPath); !os.IsNotExist(e) {
					t.Fatal("lock recreated")
				}
			}
		})
	}
}
func TestCrashTemporariesNeverCleaned(t *testing.T) {
	for _, kind := range []string{"empty", "valid", "malformed", "symlink", "hardlink", "mode", "directory"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := fixture(t)
			_ = s.Close()
			path := filepath.Join(dir, tempName)
			switch kind {
			case "directory":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Symlink(filepath.Join(dir, stateName), path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				target := filepath.Join(t.TempDir(), "inert")
				write(t, target, []byte("synthetic"), 0600)
				if e := os.Link(target, path); e != nil {
					t.Fatal(e)
				}
			case "empty":
				write(t, path, nil, 0600)
			case "valid":
				write(t, path, read(t, filepath.Join(dir, stateName)), 0600)
			case "malformed":
				write(t, path, []byte("synthetic incomplete"), 0600)
			case "mode":
				write(t, path, []byte("synthetic"), 0644)
			}
			before, e := os.Lstat(path)
			if e != nil {
				t.Fatal(e)
			}
			_, e = Open(context.Background(), dir, testCurrent.SenderBinding)
			wantErr(t, e, ErrUncertain)
			after, e := os.Lstat(path)
			if e != nil || !os.SameFile(before, after) {
				t.Fatal("temporary changed or removed")
			}
			_, e = Initialize(context.Background(), dir, testCurrent.SenderBinding)
			if e == nil {
				t.Fatal("ambiguous domain reset")
			}
		})
	}
}
func TestLiveMutationPoisonsCopiedHandles(t *testing.T) {
	for _, kind := range []string{"replace-state", "edit-state", "replace-lock", "remove-state", "temp", "directory-mode", "directory-replace"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := fixture(t)
			copyState := *s
			statePath := filepath.Join(dir, stateName)
			switch kind {
			case "replace-state":
				b := read(t, statePath)
				replacement := filepath.Join(t.TempDir(), "replacement")
				write(t, replacement, b, 0600)
				if e := os.Rename(replacement, statePath); e != nil {
					t.Fatal(e)
				}
			case "edit-state":
				b := read(t, statePath)
				b = bytes.Replace(b, []byte(testCurrent.SenderBinding), []byte(strings.Repeat("e", 64)), 1)
				write(t, statePath, b, 0600)
			case "replace-lock":
				remove(t, filepath.Join(dir, lockName))
				write(t, filepath.Join(dir, lockName), nil, 0600)
			case "remove-state":
				remove(t, statePath)
			case "temp":
				write(t, filepath.Join(dir, tempName), []byte("synthetic"), 0600)
			case "directory-mode":
				chmod(t, dir, 0755)
			case "directory-replace":
				if e := os.Rename(dir, dir+"-old"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(dir, 0700); e != nil {
					t.Fatal(e)
				}
			}
			_, e := s.Consume(context.Background(), testCurrent, grant(t, 1), testNow)
			if e == nil {
				t.Fatal("mutation admitted")
			}
			_, other := copyState.SequenceFloor()
			if other != e {
				t.Fatal("copied state did not share failure")
			}
		})
	}
}
func TestDurabilityBarriersBeforePermission(t *testing.T) {
	s, dir := fixture(t)
	store := s.inner.store.(*linuxStorage)
	syncOriginal := store.ops.sync
	renameOriginal := store.ops.rename
	stage := 0
	store.ops.sync = func(fd int) error {
		if fd == store.dirFD() {
			if stage != 2 {
				t.Fatal("directory sync before rename")
			}
			stage = 3
		} else {
			if stage != 0 {
				t.Fatal("file sync out of order")
			}
			r, e := decodeRecord(read(t, filepath.Join(dir, stateName)))
			if e != nil || r.Sequence != 0 {
				t.Fatal("state changed before fsync")
			}
			stage = 1
		}
		return syncOriginal(fd)
	}
	store.ops.rename = func(a int, b string, c int, d string) error {
		if stage != 1 {
			t.Fatal("rename before file sync")
		}
		stage = 2
		return renameOriginal(a, b, c, d)
	}
	p := consume(t, s, grant(t, 777))
	if stage != 3 {
		t.Fatal("permission before durable commit")
	}
	if e := s.Use(context.Background(), p, testCurrent, testNow, func(context.Context, journalrequest.Grant) error {
		if stage != 3 {
			t.Fatal("helper before fsync")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestCrashWriteFaultsFailClosed(t *testing.T) {
	for _, phase := range []string{"file-sync", "rename", "directory-sync", "cancel-before-rename", "cancel-after-commit"} {
		t.Run(phase, func(t *testing.T) {
			s, dir := fixture(t)
			copyState := *s
			store := s.inner.store.(*linuxStorage)
			originalSync := store.ops.sync
			originalRename := store.ops.rename
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store.ops.sync = func(fd int) error {
				if phase == "file-sync" && fd != store.dirFD() {
					return errors.New("injected")
				}
				if phase == "directory-sync" && fd == store.dirFD() {
					return errors.New("injected")
				}
				e := originalSync(fd)
				if phase == "cancel-before-rename" && fd != store.dirFD() {
					cancel()
				}
				if phase == "cancel-after-commit" && fd == store.dirFD() {
					cancel()
				}
				return e
			}
			store.ops.rename = func(a int, b string, c int, d string) error {
				if phase == "rename" {
					return errors.New("injected")
				}
				return originalRename(a, b, c, d)
			}
			g := grant(t, 19)
			p, e := s.Consume(ctx, testCurrent, g, testNow)
			want := ErrUncertain
			if phase == "cancel-after-commit" {
				want = ErrCanceled
			}
			wantErr(t, e, want)
			if p.inner != nil {
				t.Fatal("failed commit yielded permission")
			}
			if phase != "cancel-after-commit" {
				_, e = copyState.SequenceFloor()
				wantErr(t, e, ErrUncertain)
			} else {
				floor(t, &copyState, 19)
			}
			_ = s.Close()
			if phase == "directory-sync" || phase == "cancel-after-commit" {
				s = reopen(t, dir)
				floor(t, s, 19)
				_, e = s.Consume(context.Background(), testCurrent, g, testNow)
				wantErr(t, e, ErrConsumed)
			} else {
				_, e = Open(context.Background(), dir, testCurrent.SenderBinding)
				wantErr(t, e, ErrUncertain)
				if _, e = os.Lstat(filepath.Join(dir, tempName)); e != nil {
					t.Fatal("ambiguous temporary lost")
				}
			}
		})
	}
}
