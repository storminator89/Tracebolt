package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/windowsservicehealth"
)

func TestFleetGroupServiceExactSelectionAndPolicySemantics(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in := serviceHealthInput(1, 0, "stopped")
	target := WindowsMaintenanceTarget{DeviceID: in.DeviceID, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Domain: "service"}
	_, selection := groupMaintenanceSelection(t, s, target)
	save := func(sel FleetGroupMaintenanceSelection, names []string, enabled bool, revision uint64, at time.Time) (windowsservicehealth.State, error) {
		return s.ConfigureFleetGroupService(ctx, sel, in, enabled, names, revision, func() time.Time { return at }, func(time.Time) error { return nil })
	}
	for _, change := range []string{"group", "revision", "identity", "manager"} {
		bad := selection
		switch change {
		case "group":
			bad.GroupID = "group_" + strings.Repeat("2", 32)
		case "revision":
			bad.GroupRevision++
		case "identity":
			bad.Identity = strings.Repeat("c", 64)
		case "manager":
			bad.Manager = strings.Repeat("d", 64)
		}
		if _, err := save(bad, []string{"FixtureService"}, true, 0, contactAt); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal(change, err)
		}
	}
	for _, names := range [][]string{{"fixtureservice"}, {"Missing"}, {"FixtureService", "FixtureService"}} {
		if _, err := save(selection, names, true, 0, contactAt); err == nil {
			t.Fatal("unreported/ambiguous name accepted", names)
		}
	}
	state, err := save(selection, []string{"FixtureService"}, true, 0, contactAt)
	if err != nil || state.Policy.Revision != 1 || state.Checks[0].Status != "unknown" {
		t.Fatal(state, err)
	}
	if _, err = save(selection, []string{"FixtureService"}, true, 0, contactAt); err == nil {
		t.Fatal("stale revision accepted")
	}
	raw := serviceHealthRaw(t, s, in.DeviceID)
	state, err = save(selection, []string{"FixtureService"}, true, 1, contactAt)
	if err != nil || state.Policy.Revision != 1 || !bytes.Equal(raw, serviceHealthRaw(t, s, in.DeviceID)) {
		t.Fatal("same-value save changed ledger", err)
	}
	// No inventory means no new/re-enabled expectation; retained removal/disable
	// remains possible without claiming that the device or selected service healed.
	state, err = save(selection, []string{"FixtureService"}, false, 1, contactAt.Add(121*time.Second))
	if err != nil || state.Policy.Enabled || state.Policy.Revision != 2 {
		t.Fatal("disable requires inventory", err)
	}
	if _, err = save(selection, []string{"FixtureService"}, true, 2, contactAt.Add(121*time.Second)); err == nil {
		t.Fatal("stale inventory enabled policy")
	}
	states, err := s.WindowsMaintenance(ctx)
	if err != nil || len(states) != 0 {
		t.Fatal("policy created maintenance", err)
	}
}

func TestFleetGroupServiceFinalGuardRollsBack(t *testing.T) {
	s := contactStore(t)
	in := serviceHealthInput(1, 0, "running")
	calls := 0
	_, err := s.ConfigureWindowsServiceGuarded(context.Background(), in, true, []string{"FixtureService"}, 0, func() time.Time { return contactAt }, func(time.Time) error {
		calls++
		if calls == 3 {
			return windowsservicehealth.ErrInvalid
		}
		return nil
	})
	if err == nil {
		t.Fatal("failed final guard committed")
	}
	states, e := s.WindowsServiceStates(context.Background())
	if e != nil || len(states) != 0 {
		t.Fatal("rollback wrote ledger", e)
	}
}

func TestFleetGroupServiceFinalSourceAgeAndRollback(t *testing.T) {
	for _, offset := range []time.Duration{121 * time.Second, -time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			s := contactStore(t)
			in := serviceHealthInput(1, 0, "running")
			calls := 0
			_, err := s.ConfigureWindowsServiceGuarded(context.Background(), in, true, []string{"FixtureService"}, 0, func() time.Time {
				calls++
				if calls >= 4 {
					return contactAt.Add(offset)
				}
				return contactAt
			}, func(time.Time) error { return nil })
			if err == nil {
				t.Fatal("final source age/rollback accepted")
			}
			states, e := s.WindowsServiceStates(context.Background())
			if e != nil || len(states) != 0 {
				t.Fatal("failed check wrote ledger", e)
			}
		})
	}
}

func TestFleetGroupServiceRechecksAfterSQLWait(t *testing.T) {
	for _, failure := range []string{"group-revision", "membership", "identity", "deleted", "expiry", "session", "source-age"} {
		t.Run(failure, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			in := serviceHealthInput(1, 0, "running")
			target := WindowsMaintenanceTarget{DeviceID: in.DeviceID, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Domain: "service"}
			g, selection := groupMaintenanceSelection(t, s, target)
			conn, err := s.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			waits := s.db.Stats().WaitCount
			var shifted atomic.Bool
			result := make(chan error, 1)
			clock := func() time.Time {
				if shifted.Load() {
					switch failure {
					case "expiry":
						return in.AuthorityUntil
					case "source-age":
						return contactAt.Add(121 * time.Second)
					}
				}
				return contactAt
			}
			go func() {
				_, e := s.ConfigureFleetGroupService(ctx, selection, in, true, []string{"FixtureService"}, 0, clock, func(at time.Time) error {
					if !at.Before(in.AuthorityUntil) || failure == "session" && shifted.Load() {
						return windowsservicehealth.ErrInvalid
					}
					return nil
				})
				result <- e
			}()
			until := time.Now().Add(5 * time.Second)
			for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if s.db.Stats().WaitCount == waits {
				conn.Close()
				t.Fatal("did not wait for SQLite")
			}
			switch failure {
			case "group-revision":
				g.Revision++
			case "membership":
				g.Members = []FleetGroupMember{}
			case "identity":
				g.Members[0].Identity = strings.Repeat("c", 64)
			}
			if failure == "deleted" {
				_, err = conn.ExecContext(ctx, "DELETE FROM fleet_groups WHERE id=?", g.ID)
			} else {
				raw, _ := json.Marshal(g)
				_, err = conn.ExecContext(ctx, "UPDATE fleet_groups SET body=? WHERE id=?", raw, g.ID)
			}
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			shifted.Store(true)
			conn.Close()
			if err = <-result; err == nil {
				t.Fatal("expired/stale authority committed after SQLite wait")
			}
			states, e := s.WindowsServiceStates(ctx)
			if e != nil || len(states) != 0 {
				t.Fatal("failed after-wait guard wrote state", e)
			}
		})
	}
}

func TestFleetGroupServicePreservesIncidentTruth(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	before := serviceHealthOpen(t, s)
	in := serviceHealthInput(1, 121, "running")
	target := WindowsMaintenanceTarget{DeviceID: in.DeviceID, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Domain: "service"}
	_, selection := groupMaintenanceSelection(t, s, target)
	next, err := s.ConfigureFleetGroupService(ctx, selection, in, false, []string{"FixtureService"}, before.Policy.Revision, func() time.Time { return in.ReceivedAt }, func(time.Time) error { return nil })
	if err != nil || next.Policy.Enabled || len(next.Incidents) != 1 || next.Incidents[0].ClosedReason != "policy-changed" || next.Incidents[0].ResolvedAt == nil || next.Incidents[0].RecoveryObservation != nil {
		t.Fatal("group policy claimed service recovery", next, err)
	}
	if next.SequenceFloor != before.SequenceFloor || !next.ReceiptFloor.Equal(*before.ReceiptFloor) || !next.CaptureFloor.Equal(*before.CaptureFloor) || next.Incidents[0].LastBadObservation != before.Incidents[0].LastBadObservation {
		t.Fatal("group policy changed evidence floors or source observations")
	}
}
