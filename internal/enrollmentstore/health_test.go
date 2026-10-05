package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/systeminventory"
	"testing"
	"time"
)

func TestHealthReadsOriginalAcceptedAgeAndExplicitServices(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	raw, _ := operationalFrame(t, 1, at, false)
	receipt, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at)
	if e != nil {
		t.Fatal(e)
	}
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 3, at)
	snapshot.Services.Items[0].Runtime = &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "failed", SubState: "failed"}
	snapshot.Services.Items[1].Runtime = &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}
	saveSystemFixture(t, s, snap, cert, 1, snapshot, at)
	selected := map[string][]string{snap.Approval.DeviceID: {"fixture-00000.service", "missing.service"}}
	inputs, e := s.HealthInputs(ctx, selected, at.Add(time.Minute))
	if e != nil || len(inputs) != 1 {
		t.Fatal(e)
	}
	in := inputs[0]
	if !in.Authorized || !in.ReceivedAt.Equal(receipt.ReceivedAt) || len(in.Services) != 1 || in.Services["fixture-00000.service"].State != "failed" || !in.Services["fixture-00000.service"].ObservedAt.Equal(at) {
		t.Fatalf("bad source: %+v", in)
	}
	unselected, e := s.HealthInputs(ctx, map[string][]string{}, at)
	if e != nil || len(unselected[0].Services) != 0 {
		t.Fatal("collected unselected services")
	}
	stale, e := s.HealthInputs(ctx, selected, at.Add(3*time.Minute))
	if e != nil || len(stale[0].Services) != 0 {
		t.Fatal("stale services reused")
	}
	// A fresh failed latest section must not use a retained good generation.
	later := at.Add(30 * time.Second)
	failed := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 0, later)
	failed.Services = systeminventory.Empty(failed.GenerationID, later, systeminventory.ReasonPermissionDenied).Services
	saveSystemFixture(t, s, snap, cert, 2, failed, later)
	inputs, e = s.HealthInputs(ctx, selected, later)
	if e != nil || len(inputs[0].Services) != 0 {
		t.Fatal("failed latest promoted last-good cache")
	}
	// Authority termination hides readings but does not fabricate recovery.
	c := control(snap, 7)
	c.Now = later.Unix()
	if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: c, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	inputs, e = s.HealthInputs(ctx, selected, later)
	if e != nil || inputs[0].Authorized || !inputs[0].ReceivedAt.IsZero() || len(inputs[0].Services) != 0 {
		t.Fatal("revoked readings exposed", e)
	}
}

func TestHealthRejectsClockBeforeCurrentIdentityAuthority(t *testing.T) {
	_, s, _, snap, _ := completeFixture(t)
	for _, now := range []time.Time{time.Unix(snap.UpdatedAt-1, 0).UTC(), time.Unix(snap.Intent.NotBefore-1, 0).UTC(), time.Unix(snap.Intent.NotAfter, 0).UTC()} {
		inputs, e := s.HealthInputs(context.Background(), map[string][]string{}, now)
		if e == nil && len(inputs) > 0 && inputs[0].Authorized {
			t.Fatalf("identity authorized at %s", now)
		}
	}
}
