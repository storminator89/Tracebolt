package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var notesManager = strings.Repeat("a", 64)
var notesIdentity = strings.Repeat("b", 64)
var notesDevice = "agent_" + strings.Repeat("c", 32)
var notesNow = time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)

func notesGuard() error              { return nil }
func noteIDs(i int) (string, string) { s := fmt.Sprintf("%032x", i); return "noteop_" + s, "note_" + s }
func openNotesTest(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "notes.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func applyNotesTest(s *Store, i int, action, note, text string, rev uint64) (DeviceNotes, error) {
	op, id := noteIDs(i)
	if note == "" {
		note = id
	}
	return s.ApplyDeviceNote(context.Background(), notesManager, notesIdentity, notesDevice, op, action, note, text, rev, notesNow.Add(time.Duration(rev)*time.Second), notesGuard)
}
func TestDeviceNotesLifecycleReceiptsAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n, e := s.ReadDeviceNotes(context.Background(), notesManager, notesIdentity, notesDevice)
	if e != nil || n.Revision != 0 || n.Notes == nil || n.Operations == nil {
		t.Fatal(n, e)
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM device_notes").Scan(&count)
	if count != 0 {
		t.Fatal("read wrote state")
	}
	n, e = applyNotesTest(s, 1, "add", "", "First\nline\t✓", 0)
	if e != nil || n.Revision != 1 {
		t.Fatal(n, e)
	}
	note := n.Notes[0]
	n, e = applyNotesTest(s, 2, "archive", note.ID, "", 1)
	if e != nil || !n.Notes[0].Archived {
		t.Fatal(n, e)
	}
	n, e = applyNotesTest(s, 3, "restore", note.ID, "", 2)
	if e != nil || n.Notes[0].Archived || n.Notes[0].Text != note.Text || n.Notes[0].CreatedAt != note.CreatedAt {
		t.Fatal(n, e)
	}
	dup, e := applyNotesTest(s, 1, "add", "", note.Text, 0)
	if e != nil || !reflect.DeepEqual(n, dup) || dup.Operations[0].Revision != 1 {
		t.Fatal("duplicate changed state", e)
	}
	for _, tc := range []struct {
		text string
		rev  uint64
	}{{"Changed", 0}, {note.Text, 3}} {
		if _, e = applyNotesTest(s, 1, "add", "", tc.text, tc.rev); !errors.Is(e, ErrDeviceNotesConflict) {
			t.Fatal("operation rebound", e)
		}
	}
	if _, e = applyNotesTest(s, 4, "add", "", "Stale", 0); !errors.Is(e, ErrDeviceNotesConflict) {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	reopened, e := s.ReadDeviceNotes(context.Background(), notesManager, notesIdentity, notesDevice)
	if e != nil || !reflect.DeepEqual(n, reopened) {
		t.Fatal("not persistent", e)
	}
	other, e := s.ReadDeviceNotes(context.Background(), notesManager, strings.Repeat("d", 64), notesDevice)
	if e != nil || other.Revision != 0 {
		t.Fatal("identity inherited", e)
	}
}
func TestDeviceNotesInputAndStateValidation(t *testing.T) {
	s := openNotesTest(t)
	for _, text := range []string{"", " ", " leading", "trailing\n", "a\r\nb", "a\x00b", "a\x7fb", "a\u202eb", "a\u200db", string([]byte{0xff}), strings.Repeat("a", 2001), strings.Repeat("é", 1001)} {
		if _, e := applyNotesTest(s, 1, "add", "", text, 0); !errors.Is(e, ErrDeviceNotesInvalid) {
			t.Fatalf("accepted %q: %v", text, e)
		}
	}
	if _, e := applyNotesTest(s, 1, "add", "", strings.Repeat("é", 1000), 0); e != nil {
		t.Fatal(e)
	}
	_, note := noteIDs(1)
	if _, e := applyNotesTest(s, 2, "restore", note, "", 1); !errors.Is(e, ErrDeviceNotesConflict) {
		t.Fatal(e)
	}
	if _, e := applyNotesTest(s, 2, "archive", note, "unexpected", 1); !errors.Is(e, ErrDeviceNotesInvalid) {
		t.Fatal(e)
	}
	if _, e := applyNotesTest(s, 2, "edit", note, "replacement", 1); !errors.Is(e, ErrDeviceNotesInvalid) {
		t.Fatal(e)
	}
	if _, e := applyNotesTest(s, 2, "add", note, "replacement", 1); !errors.Is(e, ErrDeviceNotesInvalid) {
		t.Fatal(e)
	}
}
func TestDeviceNotesGuardsAndCancellationRollback(t *testing.T) {
	s := openNotesTest(t)
	op, note := noteIDs(1)
	denied := errors.New("denied")
	calls := 0
	guard := func() error {
		calls++
		if calls == 2 {
			return denied
		}
		return nil
	}
	_, e := s.ApplyDeviceNote(context.Background(), notesManager, notesIdentity, notesDevice, op, "add", note, "text", 0, notesNow, guard)
	if !errors.Is(e, denied) || calls != 2 {
		t.Fatal(e, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, e = s.ApplyDeviceNote(ctx, notesManager, notesIdentity, notesDevice, op, "add", note, "text", 0, notesNow, func() error {
		calls++
		if calls == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	n, e := s.ReadDeviceNotes(context.Background(), notesManager, notesIdentity, notesDevice)
	if e != nil || n.Revision != 0 {
		t.Fatal("rollback failed", n, e)
	}
}
func TestDeviceNotesConcurrentCAS(t *testing.T) {
	s := openNotesTest(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 1; i <= 2; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, e := applyNotesTest(s, i, "add", "", "text", 0); errs <- e }(i)
	}
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for e := range errs {
		if e == nil {
			success++
		} else if errors.Is(e, ErrDeviceNotesConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal(success, conflict)
	}
	n, e := s.ReadDeviceNotes(context.Background(), notesManager, notesIdentity, notesDevice)
	if e != nil || len(n.Notes) != 1 || n.Revision != 1 {
		t.Fatal(n, e)
	}
}
func TestDeviceNotesCapacity(t *testing.T) {
	t.Run("notes", func(t *testing.T) {
		s := openNotesTest(t)
		for i := 1; i <= MaxDeviceNotes; i++ {
			if _, e := applyNotesTest(s, i, "add", "", "text", uint64(i-1)); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := applyNotesTest(s, 26, "add", "", "text", 25); !errors.Is(e, ErrDeviceNotesLimit) {
			t.Fatal(e)
		}
	})
	t.Run("receipts", func(t *testing.T) {
		s := openNotesTest(t)
		n, e := applyNotesTest(s, 1, "add", "", "text", 0)
		if e != nil {
			t.Fatal(e)
		}
		note := n.Notes[0].ID
		for i := 2; i <= MaxDeviceNoteOperations; i++ {
			action := "archive"
			if i%2 == 1 {
				action = "restore"
			}
			if _, e = applyNotesTest(s, i, action, note, "", uint64(i-1)); e != nil {
				t.Fatal(i, e)
			}
		}
		if _, e = applyNotesTest(s, 251, "restore", note, "", 250); !errors.Is(e, ErrDeviceNotesLimit) {
			t.Fatal(e)
		}
		n, e = applyNotesTest(s, 1, "add", "", "text", 0)
		if e != nil || len(n.Operations) != 250 {
			t.Fatal(e)
		}
	})
	t.Run("notebooks", func(t *testing.T) {
		s := openNotesTest(t)
		op, note := noteIDs(1)
		for i := 0; i <= MaxDeviceNotebooks; i++ {
			_, e := s.ApplyDeviceNote(context.Background(), notesManager, fmt.Sprintf("%064x", i+1), notesDevice, op, "add", note, "text", 0, notesNow, notesGuard)
			if i < MaxDeviceNotebooks && e != nil || i == MaxDeviceNotebooks && !errors.Is(e, ErrDeviceNotesLimit) {
				t.Fatal(i, e)
			}
		}
	})
}
func TestDeviceNotesCorruptionRejected(t *testing.T) {
	for _, kind := range []string{"manager", "identity", "device", "revision", "digest", "duplicate", "state", "unknown", "noncanonical"} {
		t.Run(kind, func(t *testing.T) {
			s := openNotesTest(t)
			n, e := applyNotesTest(s, 1, "add", "", "text", 0)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "manager":
				n.Manager = strings.Repeat("d", 64)
			case "identity":
				n.Identity = strings.Repeat("d", 64)
			case "device":
				n.DeviceID = "agent_" + strings.Repeat("d", 32)
			case "revision":
				n.Revision++
			case "digest":
				n.Operations[0].RequestDigest = strings.Repeat("d", 64)
			case "duplicate":
				n.Notes = append(n.Notes, n.Notes[0])
			case "state":
				n.Notes[0].Archived = true
			}
			raw, _ := json.Marshal(n)
			if kind == "unknown" {
				raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
			}
			if kind == "noncanonical" {
				raw = append([]byte(" "), raw...)
			}
			if _, e = s.db.Exec(`UPDATE device_notes SET body=?`, raw); e != nil {
				t.Fatal(e)
			}
			if _, e = s.ReadDeviceNotes(context.Background(), notesManager, notesIdentity, notesDevice); !errors.Is(e, ErrDeviceNotesInvalid) {
				t.Fatal("corruption accepted", e)
			}
			if _, e = applyNotesTest(s, 2, "add", "", "other", 1); !errors.Is(e, ErrDeviceNotesInvalid) {
				t.Fatal("corruption replaced", e)
			}
		})
	}
}

func TestDeviceNotesRejectInvalidBindingAndIntent(t *testing.T) {
	s := openNotesTest(t)
	op, note := noteIDs(1)
	if _, e := s.ReadDeviceNotes(context.Background(), "invalid", notesIdentity, notesDevice); !errors.Is(e, ErrDeviceNotesInvalid) {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		op, note string
		rev      uint64
		now      time.Time
		guard    func() error
	}{
		{strings.ToUpper(op), note, 0, notesNow, notesGuard},
		{op, note, MaxDeviceNoteRevision, notesNow, notesGuard},
		{op, note, 0, time.Time{}, notesGuard},
		{op, note, 0, notesNow, nil},
	} {
		if _, e := s.ApplyDeviceNote(context.Background(), notesManager, notesIdentity, notesDevice, tc.op, "add", tc.note, "text", tc.rev, tc.now, tc.guard); !errors.Is(e, ErrDeviceNotesInvalid) {
			t.Fatal(e)
		}
	}
	n, e := applyNotesTest(s, 1, "add", "", "kept", 0)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	_, e = s.ApplyDeviceNote(context.Background(), notesManager, notesIdentity, notesDevice, "noteop_"+fmt.Sprintf("%032x", 2), "archive", note, "", 1, notesNow.Add(time.Second), func() error {
		calls++
		if calls == 2 {
			return ErrDeviceNotesConflict
		}
		return nil
	})
	if !errors.Is(e, ErrDeviceNotesConflict) {
		t.Fatal(e)
	}
	got, e := s.ReadDeviceNotes(context.Background(), notesManager, notesIdentity, notesDevice)
	if e != nil || !reflect.DeepEqual(n, got) {
		t.Fatal("existing state changed on final guard failure", e)
	}
}

func TestDeviceNotesRetainTimestampFloorAcrossRequests(t *testing.T) {
	s := openNotesTest(t)
	n, err := applyNotesTest(s, 1, "add", "", "first", 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err = applyNotesTest(s, 2, "add", "", "later", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"add", "archive"} {
		op, id := noteIDs(3)
		text := "backdated"
		if action == "archive" {
			id = n.Notes[0].ID
			text = ""
		}
		_, err = s.ApplyDeviceNote(context.Background(), notesManager, notesIdentity, notesDevice, op, action, id, text, 2, notesNow, notesGuard)
		if !errors.Is(err, ErrDeviceNotesConflict) {
			t.Fatal("backdated operation accepted", action, err)
		}
		current, e := s.ReadDeviceNotes(context.Background(), notesManager, notesIdentity, notesDevice)
		if e != nil || !reflect.DeepEqual(n, current) {
			t.Fatal("rollback changed notebook", e)
		}
	}
}
