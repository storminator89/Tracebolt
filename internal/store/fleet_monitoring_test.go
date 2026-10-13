package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsresource"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var monitoringOK = func() error { return nil }

func monitoringFixture(t *testing.T) (*Store, string, string, FleetMonitoringChange) {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "monitoring.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	manager, id := strings.Repeat("a", 64), "group_"+strings.Repeat("1", 32)
	in := capacityInput(1, 0, 95)
	c := FleetMonitoringChange{DeviceID: in.DeviceID, Metric: "disk", Identity: strings.Repeat("b", 64), InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Inherit: true}
	if _, e = s.SaveFleetGroup(context.Background(), manager, id, "Office", []FleetGroupMember{{c.DeviceID, c.Identity}}, 0, false, monitoringOK); e != nil {
		t.Fatal(e)
	}
	return s, manager, id, c
}
func monitoringSnapshot(t *testing.T, s *Store, manager, id string) (FleetMonitoringAssignment, FleetMonitoringDefinition) {
	t.Helper()
	a, e := s.FleetMonitoringAssignments(context.Background())
	if e != nil || len(a) != 1 {
		t.Fatal(a, e)
	}
	d, e := s.FleetMonitoringDefinition(context.Background(), manager, id)
	if e != nil {
		t.Fatal(e)
	}
	return a[0], d
}
func TestFleetMonitoringDefaultOffAndExactConsent(t *testing.T) {
	s, manager, id, c := monitoringFixture(t)
	ctx := context.Background()
	d, e := s.FleetMonitoringDefinition(ctx, manager, id)
	if e != nil || d.Revision != 0 || len(d.Settings) != 0 {
		t.Fatal(d, e)
	}
	a, e := s.FleetMonitoringAssignments(ctx)
	if e != nil || len(a) != 0 {
		t.Fatal(a, e)
	}
	if e = s.SaveFleetMonitoring(ctx, manager, id, 1, 0, false, []FleetMonitoringSetting{{"disk", true, 90}}, []FleetMonitoringChange{c}, monitoringOK); e == nil {
		t.Fatal("unchecked opt-in accepted")
	}
	if a, e = s.FleetMonitoringAssignments(ctx); e != nil || len(a) != 0 {
		t.Fatal("failed consent wrote")
	}
}
func TestFleetMonitoringSyncRestartSameValueOverrideAndStaleRace(t *testing.T) {
	for _, metric := range []string{"disk", "cpu", "memory"} {
		t.Run(metric, func(t *testing.T) {
			s, manager, id, c := monitoringFixture(t)
			ctx := context.Background()
			c.Metric = metric
			if e := s.SaveFleetMonitoring(ctx, manager, id, 1, 0, true, []FleetMonitoringSetting{{metric, true, 90}}, []FleetMonitoringChange{c}, monitoringOK); e != nil {
				t.Fatal(e)
			}
			a, d := monitoringSnapshot(t, s, manager, id)
			in := capacityInput(1, 0, 95)
			if e := s.ReconcileFleetMonitoring(ctx, in, a, d, 1, contactAt, monitoringOK); e != nil {
				t.Fatal(e)
			}
			applied, d := monitoringSnapshot(t, s, manager, id)
			if applied.AppliedRevision != 1 || applied.Revision != 2 || applied.PolicyRevision != 1 {
				t.Fatal(applied)
			}
			if e := s.ReconcileFleetMonitoring(ctx, in, a, d, 1, contactAt, monitoringOK); !errors.Is(e, ErrFleetMonitoringConflict) && !errors.Is(e, windowscapacity.ErrInvalid) {
				t.Fatal("stale replay accepted", e)
			}
			state, e := monitoringPolicy(ctx, s.db, c.DeviceID, metric)
			if e != nil || !state.Policy.Enabled {
				t.Fatal(state, e)
			}
			// Durable reopen does not reset ownership or applied revision.
			var path string
			s.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path)
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s2, e := Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer s2.Close()
			s = s2
			reopened, _ := monitoringSnapshot(t, s, manager, id)
			if reopened != applied {
				t.Fatal("restart changed assignment")
			}
			if metric == "disk" {
				_, e = s.ConfigureWindowsCapacity(ctx, in, true, 90, 1, contactAt)
			} else {
				_, e = s.ConfigureWindowsResource(ctx, in, windowsresource.Kind(metric), true, 90, 1, contactAt)
			}
			if e != nil {
				t.Fatal(e)
			}
			manual, _ := monitoringSnapshot(t, s, manager, id)
			if manual.Active || manual.Status != "manual-override" || manual.Revision != 3 {
				t.Fatal("same-value save kept ownership", manual)
			}
			if e = s.ReconcileFleetMonitoring(ctx, in, applied, d, 1, contactAt, monitoringOK); !errors.Is(e, ErrFleetMonitoringConflict) {
				t.Fatal("stale reconciler overwrote manual Save", e)
			}
			state, e = monitoringPolicy(ctx, s.db, c.DeviceID, metric)
			if e != nil || state.Policy.Revision != 1 {
				t.Fatal("same-value override changed policy", state, e)
			}
		})
	}
}
func TestFleetMonitoringOwnershipRemovalReaddAndDelete(t *testing.T) {
	s, manager, id, c := monitoringFixture(t)
	ctx := context.Background()
	settings := []FleetMonitoringSetting{{"disk", true, 90}}
	if e := s.SaveFleetMonitoring(ctx, manager, id, 1, 0, true, settings, []FleetMonitoringChange{c}, monitoringOK); e != nil {
		t.Fatal(e)
	}
	a, d := monitoringSnapshot(t, s, manager, id)
	if e := s.ReconcileFleetMonitoring(ctx, capacityInput(1, 0, 95), a, d, 1, contactAt, monitoringOK); e != nil {
		t.Fatal(e)
	}
	other := "group_" + strings.Repeat("2", 32)
	members := []FleetGroupMember{{c.DeviceID, c.Identity}}
	if _, e := s.SaveFleetGroup(ctx, manager, other, "Other", members, 0, false, monitoringOK); e != nil {
		t.Fatal(e)
	}
	c.ExpectedRevision = 2
	c.ExpectedPolicyRevision = 1
	if e := s.SaveFleetMonitoring(ctx, manager, other, 1, 0, true, settings, []FleetMonitoringChange{c}, monitoringOK); !errors.Is(e, ErrFleetMonitoringConflict) {
		t.Fatal("two owners", e)
	}
	raw := capacityRaw(t, s, c.DeviceID)
	if _, e := s.SaveFleetGroup(ctx, manager, id, "Office", nil, 1, false, monitoringOK); e != nil {
		t.Fatal(e)
	}
	a, _ = monitoringSnapshot(t, s, manager, id)
	if a.Active || a.Status != "stopped" {
		t.Fatal("remove did not disarm", a)
	}
	if _, e := s.SaveFleetGroup(ctx, manager, id, "Office", members, 2, false, monitoringOK); e != nil {
		t.Fatal(e)
	}
	after, _ := monitoringSnapshot(t, s, manager, id)
	if after != a {
		t.Fatal("re-add revived assignment")
	}
	if !bytes.Equal(raw, capacityRaw(t, s, c.DeviceID)) {
		t.Fatal("disarm changed last policy")
	}
	if _, e := s.SaveFleetGroup(ctx, manager, id, "Office", nil, 3, true, monitoringOK); e != nil {
		t.Fatal(e)
	}
	a, _ = monitoringSnapshot(t, s, manager, id)
	if a.Active {
		t.Fatal("delete revived")
	}
}
func TestFleetMonitoringFinalGuardRollbackAndRevisions(t *testing.T) {
	s, manager, id, c := monitoringFixture(t)
	ctx := context.Background()
	settings := []FleetMonitoringSetting{{"disk", true, 90}}
	if e := s.SaveFleetMonitoring(ctx, manager, id, 1, 0, true, settings, []FleetMonitoringChange{c}, monitoringOK); e != nil {
		t.Fatal(e)
	}
	a, d := monitoringSnapshot(t, s, manager, id)
	calls := 0
	deny := func() error {
		calls++
		if calls == 2 {
			return ErrFleetMonitoringConflict
		}
		return nil
	}
	if e := s.ReconcileFleetMonitoring(ctx, capacityInput(1, 0, 95), a, d, 1, contactAt, deny); !errors.Is(e, ErrFleetMonitoringConflict) {
		t.Fatal(e)
	}
	after, _ := monitoringSnapshot(t, s, manager, id)
	state, e := s.WindowsCapacityState(ctx, c.DeviceID)
	if e != nil || after != a || state.DeviceID != "" {
		t.Fatal("failed final guard committed", after, state, e)
	}
	c.ExpectedRevision = 1
	for _, change := range []func(*FleetMonitoringChange){func(v *FleetMonitoringChange) { v.ExpectedRevision = 0 }, func(v *FleetMonitoringChange) { v.ExpectedPolicyRevision = 1 }, func(v *FleetMonitoringChange) { v.Identity = strings.Repeat("f", 64) }} {
		bad := c
		change(&bad)
		if e = s.SaveFleetMonitoring(ctx, manager, id, 1, 1, true, settings, []FleetMonitoringChange{bad}, monitoringOK); !errors.Is(e, ErrFleetMonitoringConflict) {
			t.Fatal("stale assignment accepted", e)
		}
	}
	if e = s.SaveFleetMonitoring(ctx, manager, id, 2, 1, true, settings, []FleetMonitoringChange{c}, monitoringOK); !errors.Is(e, ErrFleetMonitoringConflict) {
		t.Fatal("stale group accepted", e)
	}
	if e = s.SaveFleetMonitoring(ctx, manager, id, 1, 0, true, settings, []FleetMonitoringChange{c}, monitoringOK); !errors.Is(e, ErrFleetMonitoringConflict) {
		t.Fatal("stale definition accepted", e)
	}
	replaced := capacityInput(1, 0, 95)
	replaced.CertificateHash = strings.Repeat("f", 64)
	if e = s.ReconcileFleetMonitoring(ctx, replaced, a, d, 1, contactAt, monitoringOK); !errors.Is(e, ErrFleetMonitoringConflict) {
		t.Fatal("replacement inherited", e)
	}
}
func TestFleetMonitoringBoundedCanonicalAndNoNewMemberAdoption(t *testing.T) {
	s, manager, id, _ := monitoringFixture(t)
	ctx := context.Background()
	members := []FleetGroupMember{}
	changes := []FleetMonitoringChange{}
	for n := 1; n <= 25; n++ {
		in := capacityInput(n, 0, 95)
		identity := fmt.Sprintf("%064x", n)
		members = append(members, FleetGroupMember{in.DeviceID, identity})
		for _, metric := range []string{"disk", "cpu", "memory"} {
			changes = append(changes, FleetMonitoringChange{DeviceID: in.DeviceID, Metric: metric, Identity: identity, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Inherit: true})
		}
	}
	if _, e := s.SaveFleetGroup(ctx, manager, id, "Office", members, 1, false, monitoringOK); e != nil {
		t.Fatal(e)
	}
	settings := []FleetMonitoringSetting{{"disk", true, 90}, {"cpu", false, 80}, {"memory", true, 85}}
	if e := s.SaveFleetMonitoring(ctx, manager, id, 2, 0, true, settings, changes, monitoringOK); e != nil {
		t.Fatal(e)
	}
	before, e := s.FleetMonitoringAssignments(ctx)
	if e != nil || len(before) != 75 {
		t.Fatal(len(before), e)
	}
	in := capacityInput(26, 0, 95)
	members = append(members, FleetGroupMember{in.DeviceID, strings.Repeat("f", 64)})
	if _, e = s.SaveFleetGroup(ctx, manager, id, "Office", members, 2, false, monitoringOK); e != nil {
		t.Fatal(e)
	}
	after, e := s.FleetMonitoringAssignments(ctx)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("new member adopted", e)
	}
	extra := FleetMonitoringChange{DeviceID: in.DeviceID, Metric: "disk", Identity: strings.Repeat("f", 64), InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Inherit: true}
	if e = s.SaveFleetMonitoring(ctx, manager, id, 3, 1, true, nil, []FleetMonitoringChange{extra}, monitoringOK); !errors.Is(e, ErrLimit) {
		t.Fatal("75-target bound ignored", e)
	}
	if _, e = s.db.Exec("UPDATE fleet_monitoring_assignments SET body=body || ' '"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.FleetMonitoringAssignments(ctx); !errors.Is(e, ErrFleetMonitoringInvalid) {
		t.Fatal("corrupt metadata repaired", e)
	}
}
func TestFleetMonitoringPreservesIncidentFloorsAndPolicyChanged(t *testing.T) {
	s, manager, id, c := monitoringFixture(t)
	ctx := context.Background()
	state := capacityOpen(t, s)
	c.ExpectedPolicyRevision = state.Policy.Revision
	if e := s.SaveFleetMonitoring(ctx, manager, id, 1, 0, true, []FleetMonitoringSetting{{"disk", true, 80}}, []FleetMonitoringChange{c}, monitoringOK); e != nil {
		t.Fatal(e)
	}
	a, d := monitoringSnapshot(t, s, manager, id)
	if e := s.ReconcileFleetMonitoring(ctx, capacityInput(1, 60, 95), a, d, 1, capacityInput(1, 60, 95).ReceivedAt, monitoringOK); e != nil {
		t.Fatal(e)
	}
	after, e := s.WindowsCapacityState(ctx, c.DeviceID)
	if e != nil || len(after.Incidents) != 1 || after.Incidents[0].ClosedReason != "policy-changed" || after.Incidents[0].RecoveryObservation != nil {
		t.Fatal(after, e)
	}
	if after.SequenceFloor != state.SequenceFloor || !reflect.DeepEqual(after.ReceiptFloor, state.ReceiptFloor) || !reflect.DeepEqual(after.CaptureFloor, state.CaptureFloor) {
		t.Fatal("evidence floors changed")
	}
}
