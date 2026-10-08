package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/windowscontact"
)

var contactAt = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
var contactEpoch = strings.Repeat("1", 32)
var contactEpochNext = strings.Repeat("2", 32)

func contactInput(n int) windowscontact.Input {
	return windowscontact.Input{DeviceID: fmt.Sprintf("agent_%032x", n), Authorized: true, AuthorityUntil: contactAt.Add(365 * 24 * time.Hour), ReceivedAt: contactAt, Sequence: 1, InvitationID: fmt.Sprintf("invite_%032x", n), CertificateHash: strings.Repeat("3", 64)}
}
func contactStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "contact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func contactEvaluate(t *testing.T, s *Store, in windowscontact.Input, now time.Time) windowscontact.State {
	t.Helper()
	state, err := s.EvaluateWindowsContact(context.Background(), in, now, contactEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func contactRaw(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var raw []byte
	if err := s.db.QueryRow("SELECT body FROM windows_contact_devices WHERE id=?", id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWindowsContactDurableRestartAndReadOnlyGET(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contact.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	in := contactInput(1)
	at := contactAt.Add(121 * time.Second)
	contactEvaluate(t, s, in, at)
	before := contactEvaluate(t, s, in, at.Add(30*time.Second))
	raw := contactRaw(t, s, in.DeviceID)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loaded, err := s.WindowsContactState(context.Background(), in.DeviceID)
	if err != nil || !reflect.DeepEqual(loaded, before) {
		t.Fatal("restart erased durable record", err)
	}
	if got := loaded.View(in, at.Add(45*time.Second), contactEpochNext); got.Status != "unknown" {
		t.Fatal("restart reused current status", got)
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WindowsContactState(context.Background(), in.DeviceID); err != nil {
		t.Fatal("GET wrote", err)
	}
	if _, err = s.WindowsContactStates(context.Background()); err != nil {
		t.Fatal("list wrote", err)
	}
	if missing, err := s.WindowsContactState(context.Background(), contactInput(2).DeviceID); err != nil || missing.Status != "unknown" {
		t.Fatal(err, missing)
	}
	if !bytes.Equal(raw, contactRaw(t, s, in.DeviceID)) {
		t.Fatal("reads changed bytes")
	}
	if _, err = s.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	state, err := s.EvaluateWindowsContact(context.Background(), in, at.Add(60*time.Second), contactEpochNext)
	if err != nil || state.Status != "pending" || len(state.Incidents) != 0 || !state.PendingSince.Equal(at.Add(60*time.Second)) {
		t.Fatal("restart reconstructed stopped time", err, state)
	}
	state, err = s.EvaluateWindowsContact(context.Background(), in, at.Add(120*time.Second), contactEpochNext)
	if err != nil || state.Status != "overdue" || len(state.Incidents) != 1 {
		t.Fatal(err, state)
	}
}

func TestWindowsContactCancelledAndFailedTransactionsDoNotChangeHistory(t *testing.T) {
	s := contactStore(t)
	in := contactInput(1)
	at := contactAt.Add(121 * time.Second)
	contactEvaluate(t, s, in, at)
	contactEvaluate(t, s, in, at.Add(time.Minute))
	before := contactRaw(t, s, in.DeviceID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.EvaluateWindowsContact(ctx, in, at.Add(90*time.Second), contactEpoch); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !bytes.Equal(before, contactRaw(t, s, in.DeviceID)) {
		t.Fatal("cancellation changed history")
	}
	if _, err := s.db.Exec(`CREATE TRIGGER contact_fail BEFORE UPDATE ON windows_contact_devices BEGIN SELECT RAISE(ABORT,'fixture abort'); END`); err != nil {
		t.Fatal(err)
	}
	in.Sequence++
	in.ReceivedAt = at.Add(90 * time.Second)
	if _, err := s.EvaluateWindowsContact(context.Background(), in, in.ReceivedAt, contactEpoch); err == nil {
		t.Fatal("fixture write failure ignored")
	}
	if !bytes.Equal(before, contactRaw(t, s, in.DeviceID)) {
		t.Fatal("failed write partially changed history")
	}
	if _, err := s.db.Exec("DROP TRIGGER contact_fail"); err != nil {
		t.Fatal(err)
	}
	state := contactEvaluate(t, s, in, in.ReceivedAt)
	if state.RecoverySince == nil {
		t.Fatal(state)
	}
	before = contactRaw(t, s, in.DeviceID)
	in.CertificateHash = "bad"
	if _, err := s.EvaluateWindowsContact(context.Background(), in, in.ReceivedAt, contactEpoch); err == nil {
		t.Fatal("invalid binding accepted")
	}
	if !bytes.Equal(before, contactRaw(t, s, in.DeviceID)) {
		t.Fatal("invalid input mutated history")
	}
}

func TestWindowsContactNeverTouchesHealthAnalysisOrAlarms(t *testing.T) {
	s := contactStore(t)
	in := contactInput(1)
	at := contactAt.Add(121 * time.Second)
	for i := 0; i <= 2; i++ {
		contactEvaluate(t, s, in, at.Add(time.Duration(i)*30*time.Second))
	}
	in.Sequence++
	in.ReceivedAt = at.Add(90 * time.Second)
	for i := 0; i <= 2; i++ {
		contactEvaluate(t, s, in, in.ReceivedAt.Add(time.Duration(i)*30*time.Second))
	}
	for _, table := range []string{"health_devices", "health_analyses", "alarm_outbox"} {
		var exists int
		if err := s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists == 0 {
			t.Fatalf("test isolation target missing: %s", table)
		}
		var count int
		if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("Windows contact leaked into %s", table)
		}
	}
}

func TestWindowsContactConcurrentEvaluationOneOpenIncident(t *testing.T) {
	s := contactStore(t)
	in := contactInput(1)
	at := contactAt.Add(121 * time.Second)
	contactEvaluate(t, s, in, at)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.EvaluateWindowsContact(context.Background(), in, at.Add(time.Minute), contactEpoch); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	state, err := s.WindowsContactState(context.Background(), in.DeviceID)
	if err != nil || len(state.Incidents) != 1 || state.NextID != 1 || state.Status != "overdue" {
		t.Fatal(err, state)
	}
}

func TestWindowsContactDeviceLimitAndBoundedList(t *testing.T) {
	s := contactStore(t)
	for i := 1; i <= windowscontact.MaxDevices; i++ {
		contactEvaluate(t, s, contactInput(i), contactAt)
	}
	if _, err := s.EvaluateWindowsContact(context.Background(), contactInput(26), contactAt, contactEpoch); !errors.Is(err, windowscontact.ErrInvalid) {
		t.Fatal("device cap", err)
	}
	states, err := s.WindowsContactStates(context.Background())
	if err != nil || len(states) != windowscontact.MaxDevices {
		t.Fatal(err, len(states))
	}
	state := windowscontact.New()
	if err := state.Evaluate(contactInput(26), contactAt, contactEpoch); err != nil {
		t.Fatal(err)
	}
	raw, _ := windowscontact.Encode(state)
	if _, err := s.db.Exec("INSERT INTO windows_contact_devices(id,body) VALUES(?,?)", state.DeviceID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WindowsContactStates(context.Background()); !errors.Is(err, windowscontact.ErrInvalid) {
		t.Fatal("oversized ledger became valid list", err)
	}
	if _, err := s.EvaluateWindowsContact(context.Background(), contactInput(1), contactAt, contactEpoch); !errors.Is(err, windowscontact.ErrInvalid) {
		t.Fatal("oversized ledger allowed existing-device mutation", err)
	}
}

func TestWindowsContactCannotTransferBoundHistory(t *testing.T) {
	s := contactStore(t)
	in := contactInput(1)
	at := contactAt.Add(121 * time.Second)
	contactEvaluate(t, s, in, at)
	contactEvaluate(t, s, in, at.Add(time.Minute))
	before := contactRaw(t, s, in.DeviceID)
	for _, change := range []func(*windowscontact.Input){
		func(in *windowscontact.Input) { in.CertificateHash = strings.Repeat("4", 64) },
		func(in *windowscontact.Input) { in.InvitationID = contactInput(2).InvitationID },
	} {
		changed := in
		change(&changed)
		if _, err := s.EvaluateWindowsContact(context.Background(), changed, at.Add(90*time.Second), contactEpochNext); !errors.Is(err, windowscontact.ErrInvalid) {
			t.Fatal("replacement identity adopted history", err)
		}
		if !bytes.Equal(before, contactRaw(t, s, in.DeviceID)) {
			t.Fatal("replacement identity changed retained history")
		}
		state, err := s.WindowsContactState(context.Background(), in.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		view := state.View(changed, at.Add(90*time.Second), contactEpochNext)
		if len(view.Incidents) != 0 || view.EvaluatedAt != nil || view.Status != "unknown" {
			t.Fatal("replacement identity received prior history", view)
		}
	}
}

func TestWindowsContactCorruptionNeverErasesLedger(t *testing.T) {
	for _, kind := range []string{"minimal", "unknown-field", "duplicate-key", "wrong-device", "noncanonical", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			s := contactStore(t)
			in := contactInput(1)
			contactEvaluate(t, s, in, contactAt)
			raw := contactRaw(t, s, in.DeviceID)
			switch kind {
			case "minimal":
				raw = []byte(`{"version":1}`)
			case "unknown-field":
				raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"extra":1`), 1)
			case "duplicate-key":
				raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			case "wrong-device":
				raw = bytes.Replace(raw, []byte(in.DeviceID), []byte(contactInput(2).DeviceID), 1)
			case "noncanonical":
				raw = append(raw, ' ')
			case "oversize":
				raw = []byte(`{"x":"` + strings.Repeat("a", windowscontact.MaxStateBytes) + `"}`)
				if _, err := s.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec("UPDATE windows_contact_devices SET body=? WHERE id=?", raw, in.DeviceID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.WindowsContactState(context.Background(), in.DeviceID); !errors.Is(err, windowscontact.ErrInvalid) {
				t.Fatal("corrupt read accepted", err)
			}
			if _, err := s.WindowsContactStates(context.Background()); !errors.Is(err, windowscontact.ErrInvalid) {
				t.Fatal("corrupt list accepted", err)
			}
			if _, err := s.EvaluateWindowsContact(context.Background(), in, contactAt.Add(time.Minute), contactEpoch); !errors.Is(err, windowscontact.ErrInvalid) {
				t.Fatal("corrupt evaluate accepted", err)
			}
			if !bytes.Equal(raw, contactRaw(t, s, in.DeviceID)) {
				t.Fatal("failure erased/replaced corruption")
			}
		})
	}
}

func TestWindowsContactFreshSchemaIsEmptyAndCanonicalIdentityRequired(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	states, err := s.WindowsContactStates(ctx)
	if err != nil || len(states) != 0 {
		t.Fatal(err, states)
	}
	for _, id := range []string{"", "fixture", "agent_" + strings.Repeat("0", 32), "agent_" + strings.Repeat("A", 32)} {
		if _, err := s.WindowsContactState(ctx, id); !errors.Is(err, windowscontact.ErrInvalid) {
			t.Fatal("noncanonical key read", id, err)
		}
		in := contactInput(1)
		in.DeviceID = id
		if _, err := s.EvaluateWindowsContact(ctx, in, contactAt, contactEpoch); !errors.Is(err, windowscontact.ErrInvalid) {
			t.Fatal("noncanonical key written", id, err)
		}
	}
}
