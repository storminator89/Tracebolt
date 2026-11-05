package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
)

func contactPolicyRequest() windowscontact.PolicyRequest {
	return windowscontact.PolicyRequest{ExpectedRevision: 0, RequestID: strings.Repeat("a", 32), GraceSeconds: 900, Acknowledged: true}
}

func TestWindowsContactPolicyDurableExplicitAndReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	in := contactInput(1)
	now := contactAt
	clock := func() time.Time { return now }
	guard := func(time.Time) error { return nil }
	before, err := s.WindowsContactState(context.Background(), in.DeviceID)
	if err != nil || before.Policy != nil {
		t.Fatal(err, before)
	}
	state, err := s.ConfigureWindowsContact(context.Background(), in, contactPolicyRequest(), contactEpoch, clock, guard)
	if err != nil || state.Policy == nil || !state.Policy.AwaitingFreshReport || state.GraceSeconds() != 900 || len(state.Incidents) != 0 {
		t.Fatal(err, state)
	}
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
	if err != nil || loaded.PolicyRevision() != 1 || !bytes.Equal(raw, contactRaw(t, s, in.DeviceID)) {
		t.Fatal(err, loaded)
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WindowsContactStates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WindowsContactState(context.Background(), in.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err = s.ConfigureWindowsContact(context.Background(), in, contactPolicyRequest(), contactEpoch, clock, guard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, contactRaw(t, s, in.DeviceID)) {
		t.Fatal("exact replay changed policy or evidence")
	}
}

func TestWindowsContactPolicyLostUsedStateFailsClosed(t *testing.T) {
	for _, missing := range []string{"state", "marker"} {
		t.Run(missing, func(t *testing.T) {
			s := contactStore(t)
			in := contactInput(1)
			_, err := s.ConfigureWindowsContact(context.Background(), in, contactPolicyRequest(), contactEpoch, func() time.Time { return contactAt }, func(time.Time) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			table := "windows_contact_devices"
			if missing == "marker" {
				table = "windows_contact_policy_used"
			}
			if _, err = s.db.Exec("DELETE FROM " + table); err != nil {
				t.Fatal(err)
			}
			if _, err = s.WindowsContactState(context.Background(), in.DeviceID); err == nil {
				t.Fatal("missing used state accepted")
			}
			if _, err = s.WindowsContactStates(context.Background()); err == nil {
				t.Fatal("missing used state omitted by list")
			}
			if _, err = s.EvaluateWindowsContact(context.Background(), in, contactAt, contactEpoch); err == nil {
				t.Fatal("evaluator repaired missing policy")
			}
			if _, err = s.WindowsIncidentSnapshot(context.Background()); err == nil {
				t.Fatal("inbox consumed contact state with broken policy fence")
			}
			tx, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = notificationCurrent(context.Background(), tx, WindowsIncidentTarget{DeviceID: in.DeviceID, Domain: "contact"}, windowscapacity.Input{Input: in}, contactAt, contactAt)
			tx.Rollback()
			if err == nil {
				t.Fatal("notification consumed contact state with broken policy fence")
			}
		})
	}
}

func TestWindowsContactPolicyTransactionGuardsRollback(t *testing.T) {
	for _, kind := range []string{"consent", "identity", "revision", "guard", "rollback", "write"} {
		t.Run(kind, func(t *testing.T) {
			s := contactStore(t)
			in := contactInput(1)
			contactEvaluate(t, s, in, contactAt)
			before := contactRaw(t, s, in.DeviceID)
			req := contactPolicyRequest()
			now := contactAt
			calls := 0
			guard := func(time.Time) error {
				calls++
				if kind == "guard" && calls == 2 {
					return errors.New("authority ended")
				}
				return nil
			}
			clock := func() time.Time {
				if kind == "rollback" {
					now = now.Add(-time.Second)
				}
				return now
			}
			switch kind {
			case "consent":
				req.Acknowledged = false
			case "identity":
				in.CertificateHash = strings.Repeat("4", 64)
			case "revision":
				req.ExpectedRevision = 2
			case "write":
				if _, err := s.db.Exec(`CREATE TRIGGER policy_fail BEFORE UPDATE ON windows_contact_devices BEGIN SELECT RAISE(ABORT,'fixture abort'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.ConfigureWindowsContact(context.Background(), in, req, contactEpoch, clock, guard); err == nil {
				t.Fatal("unsafe write accepted")
			}
			if !bytes.Equal(before, contactRaw(t, s, in.DeviceID)) {
				t.Fatal("failed policy changed bytes")
			}
			var used int
			if err := s.db.QueryRow("SELECT count(*) FROM windows_contact_policy_used").Scan(&used); err != nil || used != 0 {
				t.Fatal("failed policy retained marker", used, err)
			}
		})
	}
}
