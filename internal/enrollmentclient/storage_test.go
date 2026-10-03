//go:build linux

package enrollmentclient

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func storageFixture(t *testing.T) (*localStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "enrollment")
	s, err := openStore(dir)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func storageWriteFixture(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal("fixture write failed")
	}
}

func storageMkdirFixture(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal("fixture mkdir failed")
	}
}

func storageChmodFixture(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("fixture chmod failed")
	}
}

func storageRemoveFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal("fixture remove failed")
	}
}

func storageLinkFixture(t *testing.T, old, new string, symbolic bool) {
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

func storagePersistLedger(t *testing.T, s *localStore) {
	t.Helper()
	if err := s.Write("ledger.json", []byte(`{"fixture":"original"}`)); err != nil {
		t.Fatalf("write fixture ledger: %v", err)
	}
}

func storageExpectError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func storageExpectRejected(t *testing.T, dir string) {
	t.Helper()
	s, err := openStore(dir)
	if s != nil {
		_ = s.Close()
		t.Fatal("unsafe fixture opened")
	}
	storageExpectError(t, err, ErrState)
	if filepath.IsAbs(dir) && strings.Contains(err.Error(), dir) {
		t.Fatal("storage error exposed private path")
	}
}

func TestStoragePrivateCreationResumeAndLock(t *testing.T) {
	s, dir := storageFixture(t)
	if raw, err := s.Read("ledger.json"); raw != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fresh ledger was not missing")
	}
	storagePersistLedger(t, s)
	for _, name := range []string{"agent-key.pem", "agent-cert.pem", "server-ca.pem", "agent.json", "ready.json"} {
		if err := s.Write(name, []byte("fixture:"+name)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	for _, name := range []string{"", storeLockName, "ledger.json", "agent-key.pem", "agent-cert.pem", "server-ca.pem", "agent.json", "ready.json"} {
		st, err := os.Stat(filepath.Join(dir, name))
		want := os.FileMode(0600)
		if name == "" {
			want = 0700
		}
		if err != nil || st.Mode().Perm() != want {
			t.Fatal("private artifact missing or incorrectly protected")
		}
	}
	other, err := openStore(dir)
	if other != nil {
		_ = other.Close()
		t.Fatal("second store acquired writer lock")
	}
	storageExpectError(t, err, ErrLocked)
	cmd := exec.Command(os.Args[0], "-test.run=^TestStorageProcessLockHelper$")
	cmd.Env = append(os.Environ(), "ENROLLMENT_STORAGE_TEST_LOCK="+dir)
	if err = cmd.Run(); err != nil {
		t.Fatal("cross-process writer lock failed")
	}
	if err = s.Close(); err != nil || s.Close() != nil {
		t.Fatal("close was not successful and idempotent")
	}
	s, err = openStore(dir)
	if err != nil {
		t.Fatalf("resume fixture: %v", err)
	}
	defer s.Close()
	raw, err := s.Read("agent-key.pem")
	if err != nil || string(raw) != "fixture:agent-key.pem" {
		t.Fatal("resume changed private bytes")
	}
	raw[0] = 'X'
	raw, err = s.Read("agent-key.pem")
	if err != nil || string(raw) != "fixture:agent-key.pem" {
		t.Fatal("returned bytes changed private state")
	}
	if err = s.Write("ledger.json", []byte(`{"fixture":"updated"}`)); err != nil {
		t.Fatalf("replace fixture: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 7 {
		t.Fatal("successful writes retained temporary entries")
	}
}

func TestStorageProcessLockHelper(t *testing.T) {
	dir := os.Getenv("ENROLLMENT_STORAGE_TEST_LOCK")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	s, err := openStore(dir)
	if s != nil {
		_ = s.Close()
		t.Fatal("second process acquired writer lock")
	}
	storageExpectError(t, err, ErrLocked)
}

func TestStorageRejectsNonemptyFreshDirectoryWithoutMutation(t *testing.T) {
	for _, name := range []string{"unrelated.txt", storeTempName, "ledger.json", "agent-key.pem", "agent-cert.pem", "server-ca.pem", "agent.json", "ready.json", storeLockName, "telemetry"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if name == "telemetry" {
				storageMkdirFixture(t, path, 0700)
				storageWriteFixture(t, filepath.Join(path, "state.json"), "sender-sequence-must-survive", 0600)
			} else {
				text := "unrelated-private-fixture"
				if name == storeLockName {
					text = ""
				}
				storageWriteFixture(t, path, text, 0600)
			}
			before := storageTreeSnapshot(t, dir)
			storageExpectRejected(t, dir)
			if !reflect.DeepEqual(before, storageTreeSnapshot(t, dir)) {
				t.Fatal("rejection changed existing directory")
			}
		})
	}
}

func TestStorageRejectedResumeNeverCleansUnknownOrTemporary(t *testing.T) {
	for _, name := range []string{"unrelated.txt", storeTempName, ".ledger.tmp", "nested"} {
		t.Run(name, func(t *testing.T) {
			s, dir := storageFixture(t)
			storagePersistLedger(t, s)
			_ = s.Close()
			path := filepath.Join(dir, name)
			if name == "nested" {
				storageMkdirFixture(t, path, 0700)
				path = filepath.Join(path, "untouched")
			}
			storageWriteFixture(t, path, "preexisting-data", 0600)
			before := storageTreeSnapshot(t, dir)
			storageExpectRejected(t, dir)
			if !reflect.DeepEqual(before, storageTreeSnapshot(t, dir)) {
				t.Fatal("rejected resume removed or changed existing data")
			}
		})
	}
}

func TestStorageRequiresBothLockAndLedger(t *testing.T) {
	for _, missing := range []string{storeLockName, "ledger.json"} {
		t.Run(missing, func(t *testing.T) {
			s, dir := storageFixture(t)
			storagePersistLedger(t, s)
			_ = s.Close()
			storageRemoveFixture(t, filepath.Join(dir, missing))
			before := storageTreeSnapshot(t, dir)
			storageExpectRejected(t, dir)
			if !reflect.DeepEqual(before, storageTreeSnapshot(t, dir)) {
				t.Fatal("missing identity/lock was silently reset")
			}
		})
	}
}

func TestStorageRejectsUnsafeDirectories(t *testing.T) {
	for _, kind := range []string{"relative", "dotdot", "double-slash", "missing-parent", "mode", "sticky", "ancestor-mode", "symlink", "ancestor-symlink", "regular-file"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "enrollment")
			switch kind {
			case "relative":
				dir = "enrollment"
			case "dotdot":
				dir = root + "/unused/../enrollment"
			case "double-slash":
				dir = root + "//enrollment"
			case "missing-parent":
				dir = filepath.Join(root, "missing", "enrollment")
			case "mode":
				storageMkdirFixture(t, dir, 0755)
			case "sticky":
				storageMkdirFixture(t, dir, 0700)
				storageChmodFixture(t, dir, 0700|os.ModeSticky)
			case "ancestor-mode":
				storageChmodFixture(t, root, 0777)
			case "symlink", "ancestor-symlink":
				target := filepath.Join(root, "target")
				storageMkdirFixture(t, target, 0700)
				storageLinkFixture(t, target, dir, true)
				if kind == "ancestor-symlink" {
					dir = filepath.Join(dir, "child")
				}
			case "regular-file":
				storageWriteFixture(t, dir, "untouched", 0600)
			}
			before := storageTreeSnapshot(t, root)
			storageExpectRejected(t, dir)
			if !reflect.DeepEqual(before, storageTreeSnapshot(t, root)) {
				t.Fatal("directory rejection changed or repaired existing path")
			}
		})
	}
}

func TestStorageRejectsUnsafeKnownFiles(t *testing.T) {
	for _, name := range []string{"ledger.json", "agent-key.pem", "agent-cert.pem", "server-ca.pem", "agent.json", "ready.json", storeLockName} {
		for _, kind := range []string{"mode", "symlink", "hardlink", "fifo", "directory", "contents"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				s, dir := storageFixture(t)
				storagePersistLedger(t, s)
				if storeDataName(name) && name != "ledger.json" {
					if err := s.Write(name, []byte("fixture")); err != nil {
						t.Fatal(err)
					}
				}
				_ = s.Close()
				path := filepath.Join(dir, name)
				storageRemoveFixture(t, path)
				target := filepath.Join(filepath.Dir(dir), "untouched-target")
				storageWriteFixture(t, target, "untouched-private-target", 0600)
				switch kind {
				case "mode":
					storageWriteFixture(t, path, "insecure", 0644)
				case "symlink":
					storageLinkFixture(t, target, path, true)
				case "hardlink":
					storageLinkFixture(t, target, path, false)
				case "fifo":
					if unix.Mkfifo(path, 0600) != nil {
						t.Fatal("fixture fifo failed")
					}
				case "directory":
					storageMkdirFixture(t, path, 0700)
				case "contents":
					text := ""
					if name == storeLockName {
						text = "not-empty"
					}
					storageWriteFixture(t, path, text, 0600)
				}
				before := storageTreeSnapshot(t, filepath.Dir(dir))
				storageExpectRejected(t, dir)
				if !reflect.DeepEqual(before, storageTreeSnapshot(t, filepath.Dir(dir))) {
					t.Fatal("rejection modified unsafe file or linked target")
				}
			})
		}
	}
}

func TestStorageActiveTamperingPoisonsHandle(t *testing.T) {
	for _, kind := range []string{"inplace", "replace", "missing", "file-mode", "file-link", "lock-replace", "lock-mode", "unknown", "directory-replace", "ancestor-mode"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := storageFixture(t)
			storagePersistLedger(t, s)
			path := filepath.Join(dir, "ledger.json")
			switch kind {
			case "inplace":
				storageWriteFixture(t, path, `{"fixture":"modified"}`, 0600)
			case "replace", "lock-replace":
				text := `{"fixture":"original"}`
				if kind == "lock-replace" {
					path = filepath.Join(dir, storeLockName)
					text = ""
				}
				replacement := filepath.Join(filepath.Dir(dir), "replacement")
				storageWriteFixture(t, replacement, text, 0600)
				if os.Rename(replacement, path) != nil {
					t.Fatal("fixture replacement failed")
				}
			case "missing":
				storageRemoveFixture(t, path)
			case "file-mode":
				storageChmodFixture(t, path, 0644)
			case "file-link":
				storageLinkFixture(t, path, filepath.Join(filepath.Dir(dir), "hardlink"), false)
			case "lock-mode":
				storageChmodFixture(t, filepath.Join(dir, storeLockName), 0644)
			case "unknown":
				storageWriteFixture(t, filepath.Join(dir, "unrelated"), "must-survive", 0600)
			case "directory-replace":
				if os.Rename(dir, dir+"-old") != nil {
					t.Fatal("fixture directory rename failed")
				}
				storageMkdirFixture(t, dir, 0700)
			case "ancestor-mode":
				storageChmodFixture(t, filepath.Dir(dir), 0777)
			}
			before := storageTreeSnapshot(t, filepath.Dir(dir))
			_, err := s.Read("ledger.json")
			storageExpectError(t, err, ErrState)
			storageExpectError(t, s.Write("agent-key.pem", []byte("must-not-write")), ErrState)
			storageExpectError(t, s.EnsureTelemetry(), ErrState)
			if !reflect.DeepEqual(before, storageTreeSnapshot(t, filepath.Dir(dir))) {
				t.Fatal("active tamper rejection changed existing data")
			}
		})
	}
}

func TestStorageAtomicWriteOrderingAndFailuresPreserveState(t *testing.T) {
	for _, failure := range []string{"none", "file-sync", "rename", "directory-sync"} {
		t.Run(failure, func(t *testing.T) {
			s, dir := storageFixture(t)
			storagePersistLedger(t, s)
			var events []string
			s.ops.sync = func(fd int) error {
				kind := "file-sync"
				if fd == s.dirFD() {
					kind = "directory-sync"
				}
				events = append(events, kind)
				if failure == kind {
					return unix.EIO
				}
				return unix.Fsync(fd)
			}
			s.ops.rename = func(from int, old string, to int, next string, flags uint) error {
				events = append(events, "rename")
				if flags != 0 {
					t.Fatal("existing owned-file replacement unexpectedly used no-replace")
				}
				if failure == "rename" {
					return unix.EIO
				}
				return unix.Renameat2(from, old, to, next, flags)
			}
			next := []byte(`{"fixture":"updated"}`)
			err := s.Write("ledger.json", next)
			if failure == "none" {
				if err != nil || strings.Join(events, ",") != "file-sync,rename,directory-sync" {
					t.Fatal("durability ordering changed")
				}
			} else {
				storageExpectError(t, err, ErrState)
				_, err = s.Read("ledger.json")
				storageExpectError(t, err, ErrState)
			}
			_ = s.Close()
			raw, err := os.ReadFile(filepath.Join(dir, "ledger.json"))
			if err != nil {
				t.Fatal("authoritative ledger disappeared")
			}
			if failure == "file-sync" || failure == "rename" {
				if string(raw) != `{"fixture":"original"}` {
					t.Fatal("failed precommit changed authoritative ledger")
				}
				temp, err := os.ReadFile(filepath.Join(dir, storeTempName))
				if err != nil || !bytes.Equal(temp, next) {
					t.Fatal("failed temporary was deleted or altered")
				}
				before := storageTreeSnapshot(t, dir)
				storageExpectRejected(t, dir)
				if !reflect.DeepEqual(before, storageTreeSnapshot(t, dir)) {
					t.Fatal("reopen cleaned interrupted temporary")
				}
			} else {
				if !bytes.Equal(raw, next) {
					t.Fatal("atomic publication produced partial bytes")
				}
				resumed, err := openStore(dir)
				if err != nil {
					t.Fatal("complete published ledger could not resume")
				}
				_ = resumed.Close()
			}
		})
	}
}

func TestStorageFirstWriteNeverOverwritesRacingFile(t *testing.T) {
	s, dir := storageFixture(t)
	storagePersistLedger(t, s)
	s.ops.rename = func(from int, old string, to int, next string, flags uint) error {
		if flags != unix.RENAME_NOREPLACE {
			t.Fatal("first publication did not use no-replace")
		}
		storageWriteFixture(t, filepath.Join(dir, next), "foreign-racing-file", 0600)
		return unix.Renameat2(from, old, to, next, flags)
	}
	storageExpectError(t, s.Write("agent-key.pem", []byte("new-fixture")), ErrState)
	raw, err := os.ReadFile(filepath.Join(dir, "agent-key.pem"))
	if err != nil || string(raw) != "foreign-racing-file" {
		t.Fatal("first write overwrote racing file")
	}
	_ = s.Close()
	before := storageTreeSnapshot(t, dir)
	storageExpectRejected(t, dir)
	if !reflect.DeepEqual(before, storageTreeSnapshot(t, dir)) {
		t.Fatal("rejected racing write state was cleaned")
	}
}

func TestStorageReplacementRechecksValidatedFileAfterTempSync(t *testing.T) {
	s, dir := storageFixture(t)
	storagePersistLedger(t, s)
	s.ops.sync = func(fd int) error {
		if fd != s.dirFD() {
			storageWriteFixture(t, filepath.Join(dir, "ledger.json"), "changed-during-write", 0600)
		}
		return unix.Fsync(fd)
	}
	storageExpectError(t, s.Write("ledger.json", []byte("must-not-replace")), ErrState)
	raw, err := os.ReadFile(filepath.Join(dir, "ledger.json"))
	if err != nil || string(raw) != "changed-during-write" {
		t.Fatal("write replaced file modified after initial validation")
	}
}

func TestStorageTelemetryPreservesIndependentSenderState(t *testing.T) {
	s, dir := storageFixture(t)
	storagePersistLedger(t, s)
	if err := s.EnsureTelemetry(); err != nil {
		t.Fatal(err)
	}
	telemetry := filepath.Join(dir, "telemetry")
	storageWriteFixture(t, filepath.Join(telemetry, "state.json"), `{"sequence":41,"pending":"must-survive"}`, 0600)
	storageWriteFixture(t, filepath.Join(telemetry, "state.lock"), "", 0600)
	storageWriteFixture(t, filepath.Join(telemetry, ".state.tmp"), "sender-owned-temporary", 0600)
	storageMkdirFixture(t, filepath.Join(telemetry, "sender-owned-directory"), 0700)
	before := storageTreeSnapshot(t, telemetry)
	if err := s.EnsureTelemetry(); err != nil {
		t.Fatal("idempotent telemetry validation failed")
	}
	_ = s.Close()
	s, err := openStore(dir)
	if err != nil {
		t.Fatalf("resume with independent sender state: %v", err)
	}
	defer s.Close()
	if err = s.EnsureTelemetry(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, storageTreeSnapshot(t, telemetry)) {
		t.Fatal("enrollment altered sender sequence, lock, or temporary state")
	}
}

func TestStorageTelemetryExistsNeverCreatesOrReadsSenderState(t *testing.T) {
	s, dir := storageFixture(t)
	storagePersistLedger(t, s)
	before := storageTreeSnapshot(t, dir)
	if exists, err := s.TelemetryExists(); err != nil || exists {
		t.Fatal("missing telemetry was not reported")
	}
	if !reflect.DeepEqual(before, storageTreeSnapshot(t, dir)) {
		t.Fatal("existence check created or modified state")
	}
	if err := s.EnsureTelemetry(); err != nil {
		t.Fatal(err)
	}
	// An unreadable sender-owned entry must not matter: enrollment must never
	// inspect sender files to answer whether the private directory exists.
	storageWriteFixture(t, filepath.Join(dir, "telemetry", "state.json"), "sender-owned-sequence", 0000)
	if exists, err := s.TelemetryExists(); err != nil || !exists {
		t.Fatal("existence check inspected independent sender state")
	}
	_ = s.Close()
	resumed, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	if exists, err := resumed.TelemetryExists(); err != nil || !exists {
		t.Fatal("resumed telemetry was not reported")
	}
}

func TestStorageTelemetryExistsDetectsRemovalAndMissingResume(t *testing.T) {
	s, dir := storageFixture(t)
	storagePersistLedger(t, s)
	if err := s.EnsureTelemetry(); err != nil {
		t.Fatal(err)
	}
	storageRemoveFixture(t, filepath.Join(dir, "telemetry"))
	if exists, err := s.TelemetryExists(); exists || !errors.Is(err, ErrState) {
		t.Fatal("active telemetry removal was not rejected")
	}
	storageExpectError(t, s.EnsureTelemetry(), ErrState)
	_ = s.Close()
	resumed, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	before := storageTreeSnapshot(t, dir)
	if exists, err := resumed.TelemetryExists(); err != nil || exists {
		t.Fatal("missing resumed telemetry was not reported")
	}
	if !reflect.DeepEqual(before, storageTreeSnapshot(t, dir)) {
		t.Fatal("missing resumed telemetry was recreated")
	}
	_ = resumed.Close()
	if exists, err := resumed.TelemetryExists(); exists || !errors.Is(err, ErrState) {
		t.Fatal("closed existence check was accepted")
	}
}

func TestStorageTelemetryRejectsUnsafeOrUnexpectedDirectory(t *testing.T) {
	for _, kind := range []string{"mode", "symlink", "file", "active-create", "active-replace"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := storageFixture(t)
			storagePersistLedger(t, s)
			path := filepath.Join(dir, "telemetry")
			if kind == "active-replace" {
				if err := s.EnsureTelemetry(); err != nil {
					t.Fatal(err)
				}
				if os.Rename(path, filepath.Join(filepath.Dir(dir), "old-telemetry")) != nil {
					t.Fatal("fixture directory rename failed")
				}
			}
			if !strings.HasPrefix(kind, "active-") {
				_ = s.Close()
			}
			switch kind {
			case "mode":
				storageMkdirFixture(t, path, 0755)
			case "symlink":
				target := filepath.Join(filepath.Dir(dir), "target")
				storageMkdirFixture(t, target, 0700)
				storageWriteFixture(t, filepath.Join(target, "state.json"), "must-survive", 0600)
				storageLinkFixture(t, target, path, true)
			case "file":
				storageWriteFixture(t, path, "must-survive", 0600)
			default:
				storageMkdirFixture(t, path, 0700)
				storageWriteFixture(t, filepath.Join(path, "state.json"), "must-survive", 0600)
			}
			before := storageTreeSnapshot(t, filepath.Dir(dir))
			if strings.HasPrefix(kind, "active-") {
				storageExpectError(t, s.EnsureTelemetry(), ErrState)
			} else {
				storageExpectRejected(t, dir)
			}
			if !reflect.DeepEqual(before, storageTreeSnapshot(t, filepath.Dir(dir))) {
				t.Fatal("unsafe telemetry was repaired or changed")
			}
		})
	}
}

func TestStorageRejectsInvalidNamesAndClosedOperations(t *testing.T) {
	s, _ := storageFixture(t)
	for _, name := range []string{"", "../ledger.json", "telemetry/state.json", storeLockName, "telemetry", storeTempName, "/ledger.json"} {
		_, err := s.Read(name)
		storageExpectError(t, err, ErrState)
		storageExpectError(t, s.Write(name, []byte("fixture")), ErrState)
	}
	storageExpectError(t, s.Write("ledger.json", nil), ErrState)
	storageExpectError(t, s.Write("ledger.json", bytes.Repeat([]byte("x"), storeMaxBytes+1)), ErrState)
	storagePersistLedger(t, s)
	_ = s.Close()
	_, err := s.Read("ledger.json")
	storageExpectError(t, err, ErrState)
	storageExpectError(t, s.Write("ledger.json", []byte("fixture")), ErrState)
	storageExpectError(t, s.EnsureTelemetry(), ErrState)
}

func TestStorageOwnershipAndModePolicy(t *testing.T) {
	uid := uint32(os.Geteuid())
	file := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: uid, Nlink: 1}
	if !storePrivateFile(file) {
		t.Fatal("private file rejected")
	}
	for _, change := range []func(*unix.Stat_t){
		func(v *unix.Stat_t) { v.Uid = uid + 1 },
		func(v *unix.Stat_t) { v.Nlink = 2 },
		func(v *unix.Stat_t) { v.Mode |= 0040 },
		func(v *unix.Stat_t) { v.Mode |= unix.S_ISUID },
		func(v *unix.Stat_t) { v.Mode = unix.S_IFIFO | 0600 },
	} {
		bad := file
		change(&bad)
		if storePrivateFile(bad) {
			t.Fatal("unsafe private file policy accepted")
		}
	}
	dir := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: uid, Nlink: 1}
	if !storeTrustedDirectory(dir, true) {
		t.Fatal("private directory rejected")
	}
	dir.Uid = uid + 1
	if storeTrustedDirectory(dir, true) || storeTrustedDirectory(dir, false) {
		t.Fatal("foreign-owned directory accepted")
	}
	dir.Uid = 0
	dir.Mode = unix.S_IFDIR | 01777
	if !storeTrustedDirectory(dir, false) || storeTrustedDirectory(dir, true) {
		t.Fatal("sticky trusted ancestor policy incorrect")
	}
	dir.Mode = unix.S_IFDIR | 0777
	if storeTrustedDirectory(dir, false) {
		t.Fatal("writable non-sticky ancestor accepted")
	}
}

type storageSnapshotEntry struct {
	Mode   os.FileMode
	Target string
	Data   string
	Inode  uint64
	Links  uint64
}

// Snapshot fixtures without following links or opening special files. Inode
// identity and link counts ensure rejection does not delete/recreate entries.
func storageTreeSnapshot(t *testing.T, root string) map[string]storageSnapshotEntry {
	t.Helper()
	out := map[string]storageSnapshotEntry{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		snap := storageSnapshotEntry{Mode: st.Mode()}
		var id unix.Stat_t
		if err = unix.Lstat(path, &id); err != nil {
			return err
		}
		snap.Inode, snap.Links = id.Ino, uint64(id.Nlink)
		if st.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			snap.Data = string(raw)
		} else if st.Mode()&os.ModeSymlink != 0 {
			snap.Target, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[rel] = snap
		return nil
	})
	if err != nil {
		t.Fatal("fixture snapshot failed")
	}
	return out
}
