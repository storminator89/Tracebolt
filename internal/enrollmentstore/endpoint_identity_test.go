package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/systemwire"
	"testing"
	"time"
)

func endpointRaw(t *testing.T, device string, seq uint64, at time.Time) []byte {
	t.Helper()
	system := systemFixtureSnapshot(t, device, seq, 2, at)
	snapshot := endpointidentity.Empty(system.GenerationID, at, endpointidentity.ReasonNotCollected)
	name := "fixture-reported-host"
	snapshot.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, Value: &name}
	raw, e := systemwire.EncodeEndpoint(seq, system, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestEndpointIdentityExactRetryRestartOrdinaryReportsDoNotRefresh(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	device := snap.Approval.DeviceID
	before, e := s.EndpointIdentityView(ctx, device, at)
	if e != nil || before.Status != "not_collected" || before.Latest != nil {
		t.Fatal("old-v3 default", e)
	}
	raw := endpointRaw(t, device, 1, at)
	receipt, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(time.Minute))
	if e != nil || retry != receipt {
		t.Fatal("exact retry changed", e)
	}
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), append([]byte(" "), raw...), at.Add(time.Minute)); !errors.Is(e, ErrSystemConflict) {
		t.Fatal("body mutation retry allowed")
	}
	if s.Close() != nil {
		t.Fatal("close")
	}
	s = f.open(t, path)
	view, e := s.EndpointIdentityView(ctx, device, at.Add(time.Minute))
	if e != nil || view.Status != "fresh" || view.Latest == nil || *view.Latest.ReportedHostname.Value != "fixture-reported-host" || *view.Sequence != 1 {
		t.Fatal("restart view", e)
	}
	later := at.Add(3 * time.Minute)
	system := systemFixtureSnapshot(t, device, 2, 0, later)
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 2, system), later); e != nil {
		t.Fatal(e)
	}
	view, e = s.EndpointIdentityView(ctx, device, later)
	if e != nil || view.Status != "stale" || view.Latest == nil || !view.Latest.CollectedAt.Equal(at) || *view.Sequence != 1 || !view.ReceivedAt.Equal(at) {
		t.Fatal("ordinary report refreshed identity", e)
	}
	if e = s.transact(ctx, func(tx *transaction) error {
		if tx.credentials[snap.InvitationID].Replay.Sequence != 0 || len(tx.inventory) != 0 {
			t.Fatal("other ledger advanced")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestEndpointIdentityExpiryCleanupAndRevocation(t *testing.T) {
	_, s, _, snap, cert := systemLongFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	device := snap.Approval.DeviceID
	raw := endpointRaw(t, device, 1, at)
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at); e != nil {
		t.Fatal(e)
	}
	expired := at.Add(SystemRetention)
	view, e := s.EndpointIdentityView(ctx, device, expired)
	if e != nil || view.Status != "expired" || view.Latest != nil {
		t.Fatal("expired values visible", e)
	}
	cleanup, e := s.SystemCleanup(ctx, device, expired)
	if e != nil || !cleanup.ClearedEndpointIdentity {
		t.Fatal("endpoint cleanup", e)
	}
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, expired); e != nil {
		t.Fatal("cleanup erased exact latest receipt", e)
	}
	if e = s.transact(ctx, func(tx *transaction) error {
		r := tx.system[snap.InvitationID]
		if r.EndpointIdentity == nil || r.EndpointIdentity.Snapshot != nil || r.Receipt.Sequence != 1 {
			t.Fatal("cleanup lost floor or retained payload")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// Revoke through the normal lifecycle rather than editing the authority.
	revoke := control(snap, 7)
	revoke.Now = expired.Add(time.Second).Unix()
	if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	view, e = s.EndpointIdentityView(ctx, device, expired.Add(2*time.Second))
	if e != nil || view.Status != "revoked" || view.Latest != nil {
		t.Fatal("revoked metadata exposed", e)
	}
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, expired.Add(2*time.Second)); e == nil {
		t.Fatal("revoked exact retry accepted")
	}
}
func TestEndpointIdentityPreservesOldAuthorityJSON(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	saveSystemFixture(t, s, snap, cert, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 0, at), at)
	if e := s.transact(ctx, func(tx *transaction) error {
		r := tx.system[snap.InvitationID]
		raw, _ := json.Marshal(r)
		if bytes.Contains(raw, []byte("endpointIdentity")) {
			t.Fatal("old-v3 serialized authority widened")
		}
		legacy := struct {
			Receipt       systemwire.Receipt  `json:"receipt"`
			Latest        *systemSnapshotMeta `json:"latest"`
			Services      *systemComplete     `json:"services"`
			Sockets       *systemComplete     `json:"sockets"`
			MaintenanceAt *time.Time          `json:"maintenanceAt"`
		}{r.Receipt, r.Latest, r.Services, r.Sockets, r.MaintenanceAt}
		old, _ := json.Marshal(legacy)
		if !bytes.Equal(old, raw) {
			t.Fatal("old JSON bytes changed")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestEndpointExpiredCleanupSurvivesLaterOrdinaryFrame(t *testing.T) {
	_, s, _, snap, cert := systemLongFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	device := snap.Approval.DeviceID
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), endpointRaw(t, device, 1, at), at); e != nil {
		t.Fatal(e)
	}
	later := at.Add(SystemRetention + time.Second)
	if _, e := s.SystemCleanup(ctx, device, later); e != nil {
		t.Fatal(e)
	}
	ordinary := systemFixtureSnapshot(t, device, 2, 0, later.Add(time.Second))
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 2, ordinary), later.Add(time.Second)); e != nil {
		t.Fatal("new normal frame after cleanup", e)
	}
	view, e := s.EndpointIdentityView(ctx, device, later.Add(time.Second))
	if e != nil || view.Status != "expired" || view.Latest != nil || view.Sequence == nil || *view.Sequence != 1 {
		t.Fatal("expired identity revived or receipt lost", e)
	}
}
