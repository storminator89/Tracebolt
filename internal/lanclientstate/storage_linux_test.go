//go:build linux

package lanclientstate

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func mustWrite(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if os.WriteFile(path, raw, mode) != nil {
		t.Fatal("fixture write failed")
	}
}
func mustRemove(t *testing.T, path string) {
	t.Helper()
	if os.Remove(path) != nil {
		t.Fatal("fixture removal failed")
	}
}
func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if os.Chmod(path, mode) != nil {
		t.Fatal("fixture mode change failed")
	}
}
func mustLink(t *testing.T, old, new string, symbolic bool) {
	t.Helper()
	var err error
	if symbolic {
		err = os.Symlink(old, new)
	} else {
		err = os.Link(old, new)
	}
	if err != nil {
		t.Fatal("fixture link failed")
	}
}

func TestPrivateCreationAndNonblockingLock(t *testing.T) {
	s, dir := openTestState(t)
	for _, name := range []string{"", stateName, lockName} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal("state artifact missing")
		}
		want := os.FileMode(0600)
		if name == "" {
			want = 0700
		}
		if st.Mode().Perm() != want {
			t.Fatal("incorrect state permissions")
		}
	}
	_, err := Open(dir, testBinding)
	requireError(t, err, ErrLocked)
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessLockHelper$")
	cmd.Env = append(os.Environ(), "LANCLIENTSTATE_TEST_LOCK_DIR="+dir)
	if err := cmd.Run(); err != nil {
		t.Fatal("cross-process writer exclusion failed")
	}
	_ = s.Close()
	_ = reopenTestState(t, dir)
}
func TestProcessLockHelper(t *testing.T) {
	dir := os.Getenv("LANCLIENTSTATE_TEST_LOCK_DIR")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	s, err := Open(dir, testBinding)
	if s != nil {
		_ = s.Close()
		t.Fatal("second process acquired lock")
	}
	requireError(t, err, ErrLocked)
}

func TestUnsafeDirectoriesAreRejectedWithoutRepair(t *testing.T) {
	for _, kind := range []string{"direct-mode", "ancestor-mode", "direct-symlink", "ancestor-symlink", "file", "special-mode", "missing-under-file"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "sender")
			switch kind {
			case "direct-mode":
				if os.Mkdir(dir, 0755) != nil {
					t.Fatal("fixture mkdir failed")
				}
			case "special-mode":
				if os.Mkdir(dir, 0700) != nil {
					t.Fatal("fixture mkdir failed")
				}
				mustChmod(t, dir, 0700|os.ModeSticky)
			case "ancestor-mode":
				mustChmod(t, root, 0777)
			case "direct-symlink", "ancestor-symlink":
				target := filepath.Join(root, "target")
				if os.Mkdir(target, 0700) != nil {
					t.Fatal("fixture mkdir failed")
				}
				mustLink(t, target, dir, true)
				if kind == "ancestor-symlink" {
					dir = filepath.Join(dir, "child")
				}
			case "file", "missing-under-file":
				mustWrite(t, dir, []byte("fixture"), 0600)
				if kind == "missing-under-file" {
					dir = filepath.Join(dir, "child")
				}
			}
			s, err := Open(dir, testBinding)
			if s != nil {
				_ = s.Close()
				t.Fatal("unsafe directory opened")
			}
			if err == nil {
				t.Fatal("unsafe directory accepted")
			}
			if strings.Contains(err.Error(), root) {
				t.Fatal("error leaked path")
			}
			if kind == "direct-mode" {
				st, _ := os.Stat(dir)
				if st.Mode().Perm() != 0755 {
					t.Fatal("unsafe mode silently repaired")
				}
			}
		})
	}
}

func TestInsecureStateLockAndTempAreRejected(t *testing.T) {
	for _, name := range []string{stateName, lockName, tempName} {
		for _, kind := range []string{"mode", "symlink", "hardlink", "fifo", "directory"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				s, dir := openTestState(t)
				_ = s.Close()
				path := filepath.Join(dir, name)
				if name != tempName {
					mustRemove(t, path)
				}
				target := filepath.Join(dir, "untouched-target")
				mustWrite(t, target, []byte("private-target"), 0600)
				switch kind {
				case "mode":
					mustWrite(t, path, []byte("insecure"), 0644)
				case "symlink":
					mustLink(t, target, path, true)
				case "hardlink":
					mustLink(t, target, path, false)
				case "fifo":
					if unix.Mkfifo(path, 0600) != nil {
						t.Fatal("fixture fifo failed")
					}
				case "directory":
					if os.Mkdir(path, 0700) != nil {
						t.Fatal("fixture mkdir failed")
					}
				}
				got, err := Open(dir, testBinding)
				if got != nil {
					_ = got.Close()
					t.Fatal("unsafe file opened")
				}
				if err == nil {
					t.Fatal("unsafe file accepted")
				}
				raw, _ := os.ReadFile(target)
				if string(raw) != "private-target" {
					t.Fatal("link target changed")
				}
				if kind == "mode" {
					st, _ := os.Stat(path)
					if st.Mode().Perm() != 0644 {
						t.Fatal("unsafe file silently repaired")
					}
				}
			})
		}
	}
}

func TestExistingLockContentsAndMissingLedgerFailClosed(t *testing.T) {
	for _, kind := range []string{"lock-data", "missing-state", "missing-lock"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := openTestState(t)
			if _, err := s.Stage(1, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			switch kind {
			case "lock-data":
				mustWrite(t, filepath.Join(dir, lockName), []byte("unexpected"), 0600)
			case "missing-state":
				mustRemove(t, filepath.Join(dir, stateName))
			case "missing-lock":
				mustRemove(t, filepath.Join(dir, lockName))
			}
			got, err := Open(dir, testBinding)
			if got != nil {
				_ = got.Close()
				t.Fatal("incomplete ledger reset silently")
			}
			if err == nil {
				t.Fatal("incomplete ledger accepted")
			}
		})
	}
}

func TestActiveHandleDetectsSubstitutionAndCorruption(t *testing.T) {
	for _, kind := range []string{"state-mode", "state-hardlink", "state-symlink", "state-inplace", "state-replace", "state-missing", "lock-mode", "lock-hardlink", "lock-replace", "directory-replace", "ancestor-mode"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := openTestState(t)
			statePath := filepath.Join(dir, stateName)
			lockPath := filepath.Join(dir, lockName)
			switch kind {
			case "state-mode":
				mustChmod(t, statePath, 0644)
			case "lock-mode":
				mustChmod(t, lockPath, 0644)
			case "state-hardlink":
				mustLink(t, statePath, filepath.Join(dir, "extra-link"), false)
			case "lock-hardlink":
				mustLink(t, lockPath, filepath.Join(dir, "extra-link"), false)
			case "state-symlink":
				target := filepath.Join(dir, "target")
				mustWrite(t, target, []byte("private"), 0600)
				mustRemove(t, statePath)
				mustLink(t, target, statePath, true)
			case "state-inplace":
				raw, _ := os.ReadFile(statePath)
				raw = bytes.Replace(raw, []byte(`"lastSequence":0`), []byte(`"lastSequence":9`), 1)
				mustWrite(t, statePath, raw, 0600)
			case "state-replace", "lock-replace":
				path := statePath
				if kind == "lock-replace" {
					path = lockPath
				}
				raw, _ := os.ReadFile(path)
				other := filepath.Join(dir, "replacement")
				mustWrite(t, other, raw, 0600)
				if os.Rename(other, path) != nil {
					t.Fatal("fixture rename failed")
				}
			case "state-missing":
				mustRemove(t, statePath)
			case "directory-replace":
				if os.Rename(dir, dir+"-old") != nil || os.Mkdir(dir, 0700) != nil {
					t.Fatal("fixture directory replacement failed")
				}
			case "ancestor-mode":
				mustChmod(t, filepath.Dir(dir), 0777)
			}
			_, err := s.NextSequence()
			if err == nil {
				t.Fatal("tampered active state remained usable")
			}
			_, nextErr := s.Stage(1, []byte(`{}`))
			if !errors.Is(nextErr, err) {
				t.Fatal("unsafe handle was not poisoned")
			}
		})
	}
}

func TestOldStateWinsOverInterruptedTemporaryWrite(t *testing.T) {
	s, dir := openTestState(t)
	p, err := s.Stage(1, []byte(`{"collectedAt":"2000-01-01T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	mustWrite(t, filepath.Join(dir, tempName), []byte(`{"partiallyWritten":`), 0600)
	s = reopenTestState(t, dir)
	got, err := s.Pending()
	if err != nil || got == nil || got.Digest != p.Digest || !bytes.Equal(got.Body(), p.Body()) {
		t.Fatal("temporary file changed authoritative state")
	}
	if _, err := os.Lstat(filepath.Join(dir, tempName)); !os.IsNotExist(err) {
		t.Fatal("abandoned private temporary not removed")
	}
}

func TestAtomicWriteOrderingAndDurabilityFailures(t *testing.T) {
	for _, failure := range []string{"none", "file-sync", "rename", "directory-sync"} {
		t.Run(failure, func(t *testing.T) {
			s, dir := openTestState(t)
			backend := s.inner.store.(*linuxStorage)
			var events []string
			backend.ops.sync = func(fd int) error {
				kind := "file-sync"
				if fd == backend.dirFD() {
					kind = "directory-sync"
				}
				events = append(events, kind)
				if failure == kind {
					return unix.EIO
				}
				return unix.Fsync(fd)
			}
			backend.ops.rename = func(from int, old string, to int, next string) error {
				events = append(events, "rename")
				if failure == "rename" {
					return unix.EIO
				}
				return unix.Renameat(from, old, to, next)
			}
			p, err := s.Stage(1, []byte(`{"observation":"exact"}`))
			if failure == "none" {
				if err != nil || p.Sequence != 1 {
					t.Fatal("durable stage failed")
				}
				if strings.Join(events, ",") != "file-sync,rename,directory-sync" {
					t.Fatal("durability operation ordering changed")
				}
			} else {
				requireError(t, err, ErrIO)
				if p.Sequence != 0 || p.Body() != nil {
					t.Fatal("failed stage returned sendable request")
				}
				_, err = s.NextSequence()
				requireError(t, err, ErrIO)
			}
			_ = s.Close()
			raw, err := os.ReadFile(filepath.Join(dir, stateName))
			if err != nil {
				t.Fatal("state lost after failed write")
			}
			record, err := decodeRecord(raw)
			if err != nil {
				t.Fatal("failed write left partial authoritative state")
			}
			committed := failure == "none" || failure == "directory-sync"
			if (record.Pending != nil) != committed {
				t.Fatal("atomic rename outcome incorrect")
			}
			s = reopenTestState(t, dir)
			want := uint64(1)
			if committed {
				want = 2
			}
			requireSequence(t, s, want)
		})
	}
}

func TestInterruptedInitializationCannotResetSequenceLedger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sender")
	store, _, fresh, err := newStorage(dir)
	if err != nil || !fresh {
		t.Fatal("new storage fixture failed")
	}
	backend := store.(*linuxStorage)
	backend.ops.sync = func(int) error { return unix.EIO }
	raw, _ := encodeRecord(diskRecord{Version: stateVersion, Binding: testBinding})
	requireError(t, store.replace(raw), ErrIO)
	_ = store.close()
	_, err = Open(dir, testBinding)
	requireError(t, err, ErrCorrupt)
}

func TestFreshStateRequiresEmptyDedicatedDirectory(t *testing.T) {
	for _, name := range []string{tempName, "unrelated-file", stateName} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			original := []byte("unrelated-private-data")
			mustWrite(t, path, original, 0600)
			_, err := Open(dir, testBinding)
			requireError(t, err, ErrUnsafe)
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("fresh initialization touched unrelated data")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatal("fresh initialization added files to unrelated directory")
			}
		})
	}
}

func TestRejectedLedgerNeverCleansTemporaryFile(t *testing.T) {
	for _, kind := range []string{"binding", "corrupt", "digest"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := openTestState(t)
			if _, err := s.Stage(1, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			temp := []byte("unrelated-private-data")
			mustWrite(t, filepath.Join(dir, tempName), temp, 0600)
			binding := testBinding
			want := ErrCorrupt
			switch kind {
			case "binding":
				binding = strings.Repeat("b", 64)
				want = ErrBinding
			case "corrupt":
				putState(t, dir, []byte(`{"version":1`))
			case "digest":
				raw, _ := os.ReadFile(filepath.Join(dir, stateName))
				raw = bytes.Replace(raw, []byte(`"body":"e30="`), []byte(`"body":"bnVsbA=="`), 1)
				putState(t, dir, raw)
			}
			before, _ := os.ReadFile(filepath.Join(dir, stateName))
			_, err := Open(dir, binding)
			requireError(t, err, want)
			after, err := os.ReadFile(filepath.Join(dir, tempName))
			if err != nil || !bytes.Equal(after, temp) {
				t.Fatal("rejected ledger removed or changed temporary")
			}
			after, _ = os.ReadFile(filepath.Join(dir, stateName))
			if !bytes.Equal(before, after) {
				t.Fatal("rejected ledger changed state")
			}
		})
	}
}

func TestLowLevelOwnershipAndPermissionPolicy(t *testing.T) {
	uid := uint32(os.Geteuid())
	file := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: uid, Nlink: 1}
	if !privateFile(file) {
		t.Fatal("private file policy rejected runtime file")
	}
	for _, change := range []func(*unix.Stat_t){
		func(v *unix.Stat_t) { v.Uid = uid + 1 },
		func(v *unix.Stat_t) { v.Nlink = 2 },
		func(v *unix.Stat_t) { v.Mode |= 0040 },
		func(v *unix.Stat_t) { v.Mode |= unix.S_ISUID },
	} {
		bad := file
		change(&bad)
		if privateFile(bad) {
			t.Fatal("unsafe file policy accepted")
		}
	}
	dir := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: uid, Nlink: 1}
	if !trustedDirectory(dir, true) {
		t.Fatal("private directory rejected")
	}
	dir.Uid = uid + 1
	if trustedDirectory(dir, false) {
		t.Fatal("foreign-owned ancestor accepted")
	}
	dir.Uid = 0
	dir.Mode = unix.S_IFDIR | 01777
	if !trustedDirectory(dir, false) || trustedDirectory(dir, true) {
		t.Fatal("sticky ancestor policy incorrect")
	}
	dir.Mode = unix.S_IFDIR | 0777
	if trustedDirectory(dir, false) {
		t.Fatal("replaceable ancestor accepted")
	}
}
