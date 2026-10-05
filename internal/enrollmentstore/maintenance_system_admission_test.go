package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/systemwire"
	"reflect"
	"testing"
	"time"
)

// A controlled occupied database connection makes maintenance hold exactly the
// existing shared inventory admission slot. No production source or timer runs.
func TestCompleteMaintenanceAdmissionRetainsSystemRetryContract(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeOverview(ctx); e != nil {
		t.Fatal("fixture overview schema")
	}
	raw := systemRaw(t, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at))
	conn, e := s.db.Conn(ctx)
	if e != nil {
		t.Fatal("fixture occupied connection")
	}
	defer conn.Close()
	before := s.db.Stats().WaitCount
	maintenance := make(chan error, 1)
	go func() { _, e := s.MaintainInventoryStep(ctx, 0, at); maintenance <- e }()
	for s.db.Stats().WaitCount == before {
		select {
		case <-ctx.Done():
			t.Fatal("maintenance did not enter bounded connection wait")
		case <-maintenance:
			t.Fatal("maintenance completed before controlled connection release")
		case <-time.After(time.Millisecond):
		}
	}
	// The same maintenance admission also protects operator metadata reads.
	packages, packageErr := s.InventoryView(ctx, snap.Approval.DeviceID, at)
	overview, overviewErr := s.OverviewView(ctx, snap.Approval.DeviceID, at)
	if !errors.Is(packageErr, ErrInventoryBusy) || !reflect.DeepEqual(packages, InventoryStatus{}) || !errors.Is(overviewErr, ErrInventoryBusy) || !reflect.DeepEqual(overview, OverviewStatus{}) {
		t.Fatal("maintenance contention did not preserve empty typed operator backpressure")
	}
	receipt, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at)
	if !errors.Is(e, ErrInventoryBusy) || receipt != (systemwire.Receipt{}) {
		t.Fatal("maintenance contention did not return empty typed busy result")
	}
	if e = conn.Close(); e != nil {
		t.Fatal("fixture connection release")
	}
	select {
	case e = <-maintenance:
		if e != nil {
			t.Fatal("controlled maintenance failed")
		}
	case <-ctx.Done():
		t.Fatal("controlled maintenance did not finish")
	}
	packages, packageErr = s.InventoryView(ctx, snap.Approval.DeviceID, at)
	overview, overviewErr = s.OverviewView(ctx, snap.Approval.DeviceID, at)
	if packageErr != nil || overviewErr != nil || packages.DeviceID != snap.Approval.DeviceID || packages.Complete != nil || overview.DeviceID != snap.Approval.DeviceID || overview.Processes.Complete != nil || overview.Volumes.Complete != nil {
		t.Fatal("operator retry did not preserve authorized awaiting state")
	}
	receipt, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at)
	if e != nil || receipt.Sequence != 1 || !receipt.CollectedAt.Equal(at) {
		t.Fatal("exact system retry after maintenance failed")
	}
	repeated, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(time.Second))
	if e != nil || repeated != receipt {
		t.Fatal("system retry refreshed original receipt")
	}
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, at.Add(time.Second))
	if e != nil || view.Sequence == nil || *view.Sequence != 1 || view.Status != "fresh" || view.Latest == nil || !view.Latest.CollectedAt.Equal(at) {
		t.Fatal("system retry lost current authority or original capture age")
	}
	t.Log("synthetic proof: maintenance admission returns typed busy; exact system retry preserves sequence, authority and original receipt")
}
