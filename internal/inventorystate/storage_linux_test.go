//go:build linux

package inventorystate

import (
	"context"
	"errors"
	"localrmm/internal/inventorywire"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStrictEnrollmentAndSenderRefusalsPreserveFiles(t *testing.T) {
	s, dir := newFixture(t)
	s.Close()
	before := directoryBytes(t, dir)
	if other, e := InitializeNew(dir, fixtureBinding, fixtureAgent); e == nil {
		other.Close()
		t.Fatal("initializer adopted existing state")
	}
	unchanged(t, dir, before)
	if other, e := OpenExisting(dir, strings.Repeat("4", 64), fixtureAgent); !errors.Is(e, ErrBinding) {
		if other != nil {
			other.Close()
		}
		t.Fatal("wrong binding accepted", e)
	}
	unchanged(t, dir, before)
	root := t.TempDir()
	missing := filepath.Join(root, "new", "missing")
	if other, e := OpenExisting(missing, fixtureBinding, fixtureAgent); e == nil {
		other.Close()
		t.Fatal("sender initialized missing domain")
	}
	if _, e := os.Stat(filepath.Join(root, "new")); !os.IsNotExist(e) {
		t.Fatal("sender created path")
	}
	empty := filepath.Join(root, "empty")
	os.Mkdir(empty, 0700)
	if other, e := OpenExisting(empty, fixtureBinding, fixtureAgent); e == nil {
		other.Close()
		t.Fatal("sender initialized empty replacement")
	}
	entries, _ := os.ReadDir(empty)
	if len(entries) != 0 {
		t.Fatal("sender wrote empty directory")
	}
	for _, name := range []string{stateName, lockName} {
		t.Run(name, func(t *testing.T) {
			s, dir := newFixture(t)
			s.Close()
			os.Remove(filepath.Join(dir, name))
			before := directoryBytes(t, dir)
			if other, e := OpenExisting(dir, fixtureBinding, fixtureAgent); e == nil {
				other.Close()
				t.Fatal("missing ledger/lock accepted")
			}
			unchanged(t, dir, before)
		})
	}
	occupied := filepath.Join(root, "occupied")
	os.Mkdir(occupied, 0700)
	os.WriteFile(filepath.Join(occupied, "unrelated"), []byte("keep"), 0600)
	before = directoryBytes(t, occupied)
	if other, e := InitializeNew(occupied, fixtureBinding, fixtureAgent); e == nil {
		other.Close()
		t.Fatal("initializer adopted unrelated directory")
	}
	unchanged(t, occupied, before)
}
func TestValidationAndWrongBindingNeverCleanTemporaries(t *testing.T) {
	for _, name := range []string{tempName, packTempName, "unrelated"} {
		t.Run(name, func(t *testing.T) {
			s, dir := newFixture(t)
			s.Close()
			os.WriteFile(filepath.Join(dir, name), []byte("invented uncommitted fixture"), 0600)
			before := directoryBytes(t, dir)
			if e := ValidateExisting(dir, fixtureBinding, fixtureAgent); e == nil {
				t.Fatal("unexpected file accepted")
			}
			unchanged(t, dir, before)
			if e := ValidateExisting(dir, strings.Repeat("4", 64), fixtureAgent); !errors.Is(e, ErrBinding) {
				t.Fatal("schema binding must be checked before temp decisions", e)
			}
			unchanged(t, dir, before)
		})
	}
}
func TestLifetimeLockAndReplacementFailClosed(t *testing.T) {
	s, dir := newFixture(t)
	if other, e := OpenExisting(dir, fixtureBinding, fixtureAgent); !errors.Is(e, ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second writer accepted", e)
	}
	if e := ValidateExisting(dir, fixtureBinding, fixtureAgent); !errors.Is(e, ErrLocked) {
		t.Fatal("validator ignored writer lock")
	}
	for _, name := range []string{stateName, lockName} {
		t.Run(name, func(t *testing.T) {
			s, dir := newFixture(t)
			raw, _ := os.ReadFile(filepath.Join(dir, name))
			os.Rename(filepath.Join(dir, name), filepath.Join(dir, "old"))
			os.WriteFile(filepath.Join(dir, name), raw, 0600)
			if _, e := s.SequenceFloor(); e == nil {
				t.Fatal("replaced inode accepted")
			}
		})
	}
	t.Run("directory", func(t *testing.T) {
		s, dir := newFixture(t)
		os.Rename(dir, dir+"-old")
		os.Mkdir(dir, 0700)
		if _, e := s.SequenceFloor(); e == nil {
			t.Fatal("replaced directory accepted")
		}
	})
	s.Close()
}
func TestPrivateModesSymlinkHardlinkAndFIFORefused(t *testing.T) {
	for _, kind := range []string{"mode", "symlink", "hardlink", "fifo"} {
		for _, name := range []string{stateName, lockName, packName} {
			t.Run(kind+name, func(t *testing.T) {
				s, dir := newFixture(t)
				stageFixture(t, s, 10)
				s.Close()
				target := filepath.Join(dir, name)
				switch kind {
				case "mode":
					os.Chmod(target, 0640)
				case "symlink":
					raw, _ := os.ReadFile(target)
					outside := filepath.Join(t.TempDir(), "fixture")
					os.WriteFile(outside, raw, 0600)
					os.Remove(target)
					os.Symlink(outside, target)
				case "hardlink":
					os.Link(target, filepath.Join(t.TempDir(), "linked"))
				case "fifo":
					os.Remove(target)
					unix.Mkfifo(target, 0600)
				}
				if other, e := OpenExisting(dir, fixtureBinding, fixtureAgent); e == nil {
					other.Close()
					t.Fatal("unsafe file accepted")
				}
			})
		}
	}
	t.Run("ancestor symlink", func(t *testing.T) {
		s, dir := newFixture(t)
		s.Close()
		link := filepath.Join(t.TempDir(), "alias")
		os.Symlink(filepath.Dir(dir), link)
		if other, e := OpenExisting(filepath.Join(link, filepath.Base(dir)), fixtureBinding, fixtureAgent); e == nil {
			other.Close()
			t.Fatal("symlink ancestor accepted")
		}
	})
	t.Run("directory mode", func(t *testing.T) {
		s, dir := newFixture(t)
		s.Close()
		os.Chmod(dir, 0755)
		if other, e := OpenExisting(dir, fixtureBinding, fixtureAgent); e == nil {
			other.Close()
			t.Fatal("public directory accepted")
		}
	})
}
func TestSequenceExhaustionPreservesFloor(t *testing.T) {
	s, dir := newFixture(t)
	a := reserve(t, s)
	if e := s.StageFailure(context.Background(), a, "collection_failed"); e != nil {
		t.Fatal(e)
	}
	w := next(t, s)
	if e := s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	r := s.inner.record
	r.Floor = MaxSequence
	gid, _ := generationID(MaxSequence)
	terminal, _ := failureBody(diskRecord{Floor: MaxSequence, Generation: gid, AttemptedAt: fixtureAt.Format("2006-01-02T15:04:05.999999999Z07:00")}, "collection_failed")
	terminalWork := makeWork("failure", terminal)
	r.Last = ackFor(terminalWork, receipt(t, terminalWork))
	if e := s.inner.save(r); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, dir)
	before := directoryBytes(t, dir)
	if _, e := s.Allocate(context.Background(), fixtureAt); !errors.Is(e, ErrSequence) {
		t.Fatal("sequence wrapped", e)
	}
	unchanged(t, dir, before)
}
func generationID(seq uint64) (string, error) { return inventorywire.GenerationID(fixtureAgent, seq) }

func TestAllocationFaultPhasesPreserveUncertainty(t *testing.T) {
	for _, phase := range []string{"marker-sync", "file-sync", "rename", "directory-sync"} {
		t.Run(phase, func(t *testing.T) {
			s, dir := newFixture(t)
			store := s.inner.store.(*linuxStorage)
			calls := 0
			if phase == "rename" {
				store.ops.rename = func(int, string, int, string) error { return unix.EIO }
			} else {
				store.ops.sync = func(fd int) error {
					calls++
					if phase == "marker-sync" && calls == 1 || phase == "file-sync" && calls == 2 || phase == "directory-sync" && calls == 3 {
						return unix.EIO
					}
					return unix.Fsync(fd)
				}
			}
			if _, e := s.Allocate(context.Background(), fixtureAt); e == nil {
				t.Fatal("fault ignored")
			}
			if _, e := s.SequenceFloor(); e == nil {
				t.Fatal("failed handle remained live")
			}
			s.Close()
			before := directoryBytes(t, dir)
			other, e := OpenExisting(dir, fixtureBinding, fixtureAgent)
			if phase == "directory-sync" {
				if e != nil {
					t.Fatal(e)
				}
				defer other.Close()
				w := next(t, other)
				if w.Sequence != 1 || w.Operation != "failure" {
					t.Fatal("published reservation lost")
				}
			} else {
				if !errors.Is(e, ErrUncertain) {
					if other != nil {
						other.Close()
					}
					t.Fatal("uncertainty cleared", e)
				}
			}
			unchanged(t, dir, before)
		})
	}
}
func TestStageFaultPhasesNeverRecollectOrExposePrefix(t *testing.T) {
	for _, phase := range []string{"pack-marker-sync", "pack-file-sync", "pack-rename", "pack-directory-sync", "ledger-marker-sync", "ledger-file-sync", "ledger-rename", "ledger-directory-sync"} {
		t.Run(phase, func(t *testing.T) {
			s, dir := newFixture(t)
			a := reserve(t, s)
			m, c := payloads(t, a, 513)
			store := s.inner.store.(*linuxStorage)
			calls := 0
			if strings.HasSuffix(phase, "rename") {
				store.ops.rename = func(a int, old string, b int, new string) error {
					if phase == "pack-rename" && new == packName || phase == "ledger-rename" && new == stateName {
						return unix.EIO
					}
					return unix.Renameat(a, old, b, new)
				}
			} else {
				nth := map[string]int{"pack-marker-sync": 1, "pack-file-sync": 2, "pack-directory-sync": 3, "ledger-marker-sync": 4, "ledger-file-sync": 5, "ledger-directory-sync": 6}[phase]
				store.ops.sync = func(fd int) error {
					calls++
					if calls == nth {
						return unix.EIO
					}
					return unix.Fsync(fd)
				}
			}
			if e := s.Stage(context.Background(), a, m, c); e == nil {
				t.Fatal("fault ignored")
			}
			s.Close()
			before := directoryBytes(t, dir)
			other, e := OpenExisting(dir, fixtureBinding, fixtureAgent)
			if phase == "ledger-directory-sync" {
				if e != nil {
					t.Fatal(e)
				}
				defer other.Close()
				w := next(t, other)
				if w.Operation != "begin" || w.Sequence != 1 {
					t.Fatal("published generation lost")
				}
			} else {
				if !errors.Is(e, ErrUncertain) {
					if other != nil {
						other.Close()
					}
					t.Fatal("uncertainty did not fail closed", e)
				}
			}
			unchanged(t, dir, before)
		})
	}
}
func TestRetirementRecoversAfterDeletionFsyncFailure(t *testing.T) {
	s, dir := newFixture(t)
	stageFixture(t, s, 0)
	w := next(t, s)
	if e := s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	w = next(t, s)
	ack := receipt(t, w)
	store := s.inner.store.(*linuxStorage)
	calls := 0
	store.ops.sync = func(fd int) error {
		calls++
		if calls == 4 {
			return unix.EIO
		}
		return unix.Fsync(fd)
	}
	if e := s.Acknowledge(w, ack); e == nil {
		t.Fatal("fault ignored")
	}
	s.Close()
	before := directoryBytes(t, dir)
	if e := ValidateExisting(dir, fixtureBinding, fixtureAgent); e != nil {
		t.Fatal("read-only validation of retiring state", e)
	}
	unchanged(t, dir, before)
	s, e := OpenExisting(dir, fixtureBinding, fixtureAgent)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Acknowledge(w, ack); e != nil {
		t.Fatal("retirement receipt replay", e)
	}
	if _, ok, e := s.NextWork(); e != nil || ok {
		t.Fatal("retirement incomplete")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal("retirement cleanup incomplete")
	}
	if reserve(t, s).Sequence != 2 {
		t.Fatal("retirement floor lost")
	}
}

func TestStageCancellationAfterDurableMarkerFailsClosed(t *testing.T) {
	s, dir := newFixture(t)
	a := reserve(t, s)
	m, c := payloads(t, a, 513)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := s.inner.store.(*linuxStorage)
	calls := 0
	store.ops.sync = func(fd int) error {
		calls++
		if calls == 1 {
			cancel()
		}
		return unix.Fsync(fd)
	}
	if e := s.Stage(ctx, a, m, c); !errors.Is(e, ErrUncertain) {
		t.Fatal("post-marker cancellation discarded uncertainty", e)
	}
	s.Close()
	before := directoryBytes(t, dir)
	if other, e := OpenExisting(dir, fixtureBinding, fixtureAgent); !errors.Is(e, ErrUncertain) {
		if other != nil {
			other.Close()
		}
		t.Fatal("cancel marker reset", e)
	}
	unchanged(t, dir, before)
}
func TestStageCancellationAfterPackWriteCompletesJournal(t *testing.T) {
	s, dir := newFixture(t)
	a := reserve(t, s)
	m, c := payloads(t, a, 513)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := s.inner.store.(*linuxStorage)
	calls := 0
	store.ops.sync = func(fd int) error {
		calls++
		if calls == 2 {
			cancel()
		}
		return unix.Fsync(fd)
	}
	if e := s.Stage(ctx, a, m, c); e != nil {
		t.Fatal("publication did not finish bounded transition", e)
	}
	s = reopen(t, s, dir)
	if next(t, s).Operation != "begin" {
		t.Fatal("publication lost on cancellation")
	}
}
func TestReadyMissingOrChangedPackFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing", "changed", "replaced"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := newFixture(t)
			stageFixture(t, s, 513)
			path := filepath.Join(dir, packName)
			switch kind {
			case "missing":
				os.Remove(path)
			case "changed":
				f, _ := os.OpenFile(path, os.O_WRONLY, 0)
				f.WriteAt([]byte("x"), 20)
				f.Close()
			case "replaced":
				raw, _ := os.ReadFile(path)
				os.Remove(path)
				os.WriteFile(path, raw, 0600)
			}
			if _, _, e := s.NextWork(); e == nil {
				t.Fatal("changed pack ignored")
			}
		})
	}
	s, dir := newFixture(t)
	stageFixture(t, s, 513)
	s.Close()
	os.Remove(filepath.Join(dir, packName))
	before := directoryBytes(t, dir)
	if other, e := OpenExisting(dir, fixtureBinding, fixtureAgent); e == nil {
		other.Close()
		t.Fatal("missing pack adopted")
	}
	unchanged(t, dir, before)
}
