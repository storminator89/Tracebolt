//go:build linux

package actionstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

func TestProtectedModesNumericOwnerAndLinks(t *testing.T) {
	s, dir := fixture(t)
	defer s.Close()
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
	file.Uid++
	if privateFile(file) {
		t.Fatal("foreign owner")
	}
	file.Uid = uid
	file.Nlink = 2
	if privateFile(file) {
		t.Fatal("hardlink")
	}
	d := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: uid, Nlink: 2}
	if !trustedDirectory(d, true) {
		t.Fatal("owned dir refused")
	}
	d.Uid++
	if trustedDirectory(d, true) {
		t.Fatal("foreign dir")
	}
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
				if e := os.Rename(dir, dir+"-real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(dir+"-real", dir); e != nil {
					t.Fatal(e)
				}
			case "ancestor-symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if e := os.Symlink(filepath.Dir(dir), alias); e != nil {
					t.Fatal(e)
				}
				dir = filepath.Join(alias, "actions")
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
				write(t, filepath.Join(dir, "unexpected"), []byte("inert"), 0600)
			case "state-absent":
				remove(t, statePath)
			case "lock-absent":
				remove(t, lockPath)
			case "corrupt":
				write(t, statePath, []byte(`{"version":null}`), 0600)
			case "oversized":
				write(t, statePath, bytes.Repeat([]byte("x"), MaxStateBytes+1), 0600)
			}
			got, e := Open(context.Background(), dir, verifier(t))
			if got != nil {
				_ = got.Close()
				t.Fatal("unsafe path accepted")
			}
			if e == nil {
				t.Fatal("no error")
			}
			if kind == "state-mode" {
				info, _ := os.Stat(statePath)
				if info.Mode().Perm() != 0644 {
					t.Fatal("repaired file")
				}
			}
			if kind == "state-absent" {
				if _, e = os.Stat(statePath); !os.IsNotExist(e) {
					t.Fatal("recreated state")
				}
			}
		})
	}
}

func TestCrashTemporaryPreserved(t *testing.T) {
	for _, kind := range []string{"empty", "valid", "malformed", "symlink", "hardlink", "mode", "directory"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := fixture(t)
			_ = s.Close()
			p := filepath.Join(dir, tempName)
			switch kind {
			case "directory":
				if e := os.Mkdir(p, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Symlink(filepath.Join(dir, stateName), p); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(filepath.Join(dir, stateName), p); e != nil {
					t.Fatal(e)
				}
			case "valid":
				write(t, p, read(t, filepath.Join(dir, stateName)), 0600)
			case "mode":
				write(t, p, []byte("inert"), 0644)
			case "malformed":
				write(t, p, []byte("incomplete"), 0600)
			default:
				write(t, p, nil, 0600)
			}
			before, e := os.Lstat(p)
			if e != nil {
				t.Fatal(e)
			}
			_, e = Open(context.Background(), dir, verifier(t))
			if e == nil {
				t.Fatal("temporary accepted")
			}
			after, e := os.Lstat(p)
			if e != nil || !os.SameFile(before, after) {
				t.Fatal("temporary changed")
			}
			_, e = Initialize(context.Background(), dir, verifier(t))
			if e == nil {
				t.Fatal("domain reset")
			}
		})
	}
}

func TestLiveMutationsPoisonCopies(t *testing.T) {
	for _, kind := range []string{"replace-state", "edit-state", "replace-lock", "remove-state", "temp", "directory-mode", "directory-replace"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := fixture(t)
			copyState := *s
			p := filepath.Join(dir, stateName)
			switch kind {
			case "replace-state":
				replacement := filepath.Join(t.TempDir(), "replacement")
				write(t, replacement, read(t, p), 0600)
				if e := os.Rename(replacement, p); e != nil {
					t.Fatal(e)
				}
			case "edit-state":
				write(t, p, append(read(t, p), ' '), 0600)
			case "replace-lock":
				remove(t, filepath.Join(dir, lockName))
				write(t, filepath.Join(dir, lockName), nil, 0600)
			case "remove-state":
				remove(t, p)
			case "temp":
				write(t, filepath.Join(dir, tempName), nil, 0600)
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
			_, e := s.Admit(context.Background(), signed(t, permit(t, 1)), testNow)
			if e == nil {
				t.Fatal("mutated state admitted")
			}
			_, other := copyState.Status(context.Background(), permit(t, 1).JobID)
			if other != e {
				t.Fatal("copy not poisoned", e, other)
			}
		})
	}
}

func TestDurabilityBarriersBeforeAdmission(t *testing.T) {
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
			r, e := decodeRecord(read(t, filepath.Join(dir, stateName)), verifier(t))
			if e != nil || r.Floor != 0 {
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
	got, e := s.Admit(context.Background(), signed(t, permit(t, 77)), testNow)
	if e != nil || stage != 3 || got.Phase != Admitted {
		t.Fatal("admission before durable commit", e)
	}
}

func TestWriteFaultsAndCancellationNeverReturnAdmission(t *testing.T) {
	for _, phase := range []string{"disk-full", "short-write", "file-sync", "rename", "directory-sync", "cancel-before-rename", "cancel-after-commit"} {
		t.Run(phase, func(t *testing.T) {
			s, dir := fixture(t)
			copyState := *s
			store := s.inner.store.(*linuxStorage)
			syncOriginal := store.ops.sync
			renameOriginal := store.ops.rename
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "disk-full" {
				store.ops.write = func(*os.File, []byte) (int, error) { return 0, unix.ENOSPC }
			} else if phase == "short-write" {
				store.ops.write = func(f *os.File, raw []byte) (int, error) { return f.Write(raw[:len(raw)/2]) }
			}
			store.ops.sync = func(fd int) error {
				if phase == "file-sync" && fd != store.dirFD() || phase == "directory-sync" && fd == store.dirFD() {
					return errors.New("injected")
				}
				e := syncOriginal(fd)
				if phase == "cancel-before-rename" && fd != store.dirFD() || phase == "cancel-after-commit" && fd == store.dirFD() {
					cancel()
				}
				return e
			}
			store.ops.rename = func(a int, b string, c int, d string) error {
				if phase == "rename" {
					return errors.New("injected")
				}
				return renameOriginal(a, b, c, d)
			}
			p := permit(t, 19)
			raw := signed(t, p)
			got, e := s.Admit(ctx, raw, testNow)
			want := ErrUncertain
			if phase == "cancel-after-commit" {
				want = ErrCanceled
			}
			requireErr(t, e, want)
			if got.Phase != "" {
				t.Fatal("failure returned admission")
			}
			if phase != "cancel-after-commit" {
				_, e = copyState.Status(context.Background(), p.JobID)
				requireErr(t, e, ErrUncertain)
			} else {
				got, e = copyState.Status(context.Background(), p.JobID)
				if e != nil || got.Phase != Admitted {
					t.Fatal("lost committed state")
				}
			}
			_ = s.Close()
			if phase == "directory-sync" || phase == "cancel-after-commit" {
				s, e = Open(context.Background(), dir, verifier(t))
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
				got, e = s.Admit(context.Background(), raw, testNow)
				if e != nil || got.Phase != NeedsIntervention {
					t.Fatal("uncertain admission was replayable")
				}
			} else {
				_, e = Open(context.Background(), dir, verifier(t))
				requireErr(t, e, ErrUncertain)
				if _, e = os.Lstat(filepath.Join(dir, tempName)); e != nil {
					t.Fatal("lost ambiguous temp")
				}
			}
		})
	}
}
