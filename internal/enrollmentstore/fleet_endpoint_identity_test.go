package enrollmentstore

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"reflect"
	"testing"
	"time"
)

func TestFleetEndpointIdentityPreservesSingleReadAndOriginalBytes(t *testing.T) {
	_, s, _, snap, cert := systemLongFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	raw := endpointRaw(t, snap.Approval.DeviceID, 1, at)
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at); err != nil {
		t.Fatal(err)
	}
	before := journalBody(t, s, snap.InvitationID)
	for _, age := range []time.Duration{time.Second, 121 * time.Second, SystemRetention} {
		single, err := s.EndpointIdentityView(ctx, snap.Approval.DeviceID, at.Add(age))
		if err != nil {
			t.Fatal(err)
		}
		fleet, err := s.FleetEndpointIdentityView(ctx, at.Add(age))
		if err != nil {
			t.Fatal(err)
		}
		if len(fleet.Items) != 1 || !reflect.DeepEqual(fleet.Items[0], single) || !fleet.ServerNow.Equal(single.ServerNow) {
			t.Fatalf("fleet changed original single-view semantics: %+v", fleet)
		}
	}
	if !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("display read changed retained bytes")
	}
	revoke := control(snap, 7)
	revoke.Now = at.Add(SystemRetention + time.Second).Unix()
	if _, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	fleet, err := s.FleetEndpointIdentityView(ctx, at.Add(SystemRetention+2*time.Second))
	if err != nil || len(fleet.Items) != 1 || fleet.Items[0].Status != "revoked" || fleet.Items[0].Latest != nil || fleet.Items[0].Sequence != nil {
		t.Fatal("revoked metadata visible", err)
	}
}

func TestFleetEndpointIdentityReadAdmissionCancellationAndPostCommitAge(t *testing.T) {
	_, s, _, snap, cert := systemLongFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	if _, err := s.SaveSystemObservation(context.Background(), snap.InvitationID, cert.CertificateHash(), endpointRaw(t, snap.Approval.DeviceID, 1, at), at); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.FleetEndpointIdentityView(ctx, at); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read accepted", err)
	}
	release, err := s.systemReadAdmission(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.FleetEndpointIdentityView(context.Background(), at); !errors.Is(err, ErrInventoryBusy) {
		t.Fatal("fleet bypassed shared bounded admission", err)
	}
	release()
	calls := 0
	clock := func() time.Time {
		calls++
		if calls > 1 {
			return at.Add(SystemRetention)
		}
		return at
	}
	v, err := s.FleetEndpointIdentityView(WithSystemViewClock(context.Background(), clock), at)
	if err != nil || calls != 2 || len(v.Items) != 1 || v.Items[0].Status != "expired" || v.Items[0].Latest != nil {
		t.Fatal("post-commit original retention not checked", err, calls)
	}
	v, err = s.FleetEndpointIdentityView(context.Background(), at)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := v.RecheckAt(time.Unix(snap.Intent.NotAfter, 0).UTC())
	if err != nil || checked.Items[0].Status != "expired" || checked.Items[0].Latest != nil {
		t.Fatal("output certificate expiry not checked", err)
	}
	v.Items = make([]EndpointIdentityView, FleetEndpointIdentityLimit+1)
	if _, err = v.RecheckAt(at); !errors.Is(err, ErrStorage) {
		t.Fatal("oversized projection accepted")
	}
}

func TestFleetEndpointIdentityCertificateExpiryKeepsHealthyMember(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	at := time.Unix(snap.Intent.NotAfter, 0).UTC().Add(-time.Minute)
	if _, err := s.SaveSystemObservation(context.Background(), snap.InvitationID, cert.CertificateHash(), endpointRaw(t, snap.Approval.DeviceID, 1, at), at); err != nil {
		t.Fatal(err)
	}
	before := journalBody(t, s, snap.InvitationID)
	item, err := s.EndpointIdentityView(context.Background(), snap.Approval.DeviceID, at)
	if err != nil {
		t.Fatal(err)
	}
	// Two independently authorized immutable read states; the second certificate
	// remains live through the first certificate's boundary.
	healthy := item
	healthy.DeviceID = "agent_healthy_fleet_fixture"
	authority := *item.readState
	authority.certificateNotAfter += 3600
	healthy.readState = &authority
	fleet := FleetEndpointIdentityView{SchemaVersion: "tracebolt.fleet-endpoint-identity.v1", ServerNow: at, Items: []EndpointIdentityView{item, healthy}}
	atExpiry := time.Unix(snap.Intent.NotAfter, 0).UTC()
	if err := fleet.ValidateAt(at); err != nil {
		t.Fatal("live encoded fleet rejected", err)
	}
	if err := fleet.ValidateAt(atExpiry); !errors.Is(err, enrollmentstate.ErrExpired) {
		t.Fatal("encoded collected fleet survived certificate expiry", err)
	}
	checked, err := fleet.RecheckAt(atExpiry)
	if err != nil {
		t.Fatal(err)
	}
	expired := checked.Items[0]
	if expired.Status != "expired" || expired.Latest != nil || expired.Sequence != nil || expired.ReceivedAt != nil || expired.ExpiresAt != nil {
		t.Fatal("authority expiry must use valid empty wire form")
	}
	if checked.Items[1].Status != "fresh" || checked.Items[1].Latest == nil || checked.Items[1].Sequence == nil {
		t.Fatal("healthy member lost metadata")
	}
	if !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("normalization changed durable receipt")
	}
	rolled, err := checked.RecheckAt(at)
	if err != nil || !reflect.DeepEqual(rolled, checked) {
		t.Fatal("rollback revived expired member", err)
	}
}
