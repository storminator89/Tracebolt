package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"testing"
	"time"
)

// A week-long synthetic certificate lets the tests distinguish 24-hour sample
// retention from certificate expiry (the ordinary fixture expires after a day).
func activeHistoryFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f, s, path := fixtureStore(t)
	ctx := context.Background()
	snap, e := s.CreateInvitation(ctx, f.createCommand())
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(snap, 2), ClaimID: f.challenge.ClaimID}, f.claim(t))
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(snap, 3), DeviceID: id("agent", 1), KeyFingerprint: snap.Claim.KeyFingerprint})
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: f.control(snap, 4), IntentID: id("intent", 1), SerialHex: "00000000000000000000000000000001", TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 7*86400})
	if e != nil {
		t.Fatal(e)
	}
	intent, e := s.SigningIntent(ctx, snap.InvitationID, snap.UpdatedAt)
	if e != nil {
		t.Fatal(e)
	}
	cert := f.issue(t, intent)
	snap, e = s.CommitIssued(ctx, control(snap, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	c := control(snap, 6)
	snap, e = s.Activate(ctx, c, f.activation(t, cert, c))
	if e != nil {
		t.Fatal(e)
	}
	return f, s, path, snap, cert
}
func measuredResourceFrame(t *testing.T, seq uint64, at time.Time, value float64) []byte {
	t.Helper()
	raw := sampleFrame(t, seq, at)
	var f lanstore.Frame
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	f.Observation.Observation.CPU.Value = &value
	f.Observation.Observation.CPU.Quality = "healthy"
	out, e := json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestResourceHistoryAuthenticMinuteSamplesRetryRestartAndRevocation(t *testing.T) {
	f, s, path, snap, cert := activeHistoryFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0)
	initial, e := s.ResourceHistory(ctx, snap.Approval.DeviceID, at)
	if e != nil || initial.Status != "awaiting" || len(initial.Points) != 0 {
		t.Fatal("invented pre-upgrade history", e)
	}
	for i, offset := range []time.Duration{0, 10 * time.Second, 3 * time.Minute} {
		ts := at.Add(offset)
		raw := measuredResourceFrame(t, uint64(i+1), ts, float64(i))
		if _, e = s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, ts); e != nil {
			t.Fatal(e)
		}
	}
	v, e := s.ResourceHistory(ctx, snap.Approval.DeviceID, at.Add(3*time.Minute))
	if e != nil || len(v.Points) != 2 || v.Points[0].Sequence != "2" || *v.Points[0].CPU.Value != 1 || v.Points[0].Memory.Value != nil || v.Points[0].Memory.Quality != "unknown" {
		t.Fatalf("bad authentic history %#v %v", v, e)
	}
	original := v.Points[1]
	raw := measuredResourceFrame(t, 3, at.Add(3*time.Minute), 2)
	if r, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(4*time.Minute)); e != nil || !r.Duplicate {
		t.Fatal("retry", e)
	}
	s.Close()
	s = f.open(t, path)
	v, e = s.ResourceHistory(ctx, snap.Approval.DeviceID, at.Add(4*time.Minute))
	if e != nil || len(v.Points) != 2 || !v.Points[1].ReceivedAt.Equal(original.ReceivedAt) {
		t.Fatal("restart/retry changed point", e)
	}
	if _, e = s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), measuredResourceFrame(t, 2, at.Add(5*time.Minute), 5), at.Add(5*time.Minute)); !errors.Is(e, lanstore.ErrReplay) {
		t.Fatal("replay accepted", e)
	}
	revoke := control(snap, 20)
	revoke.Now = at.Add(6 * time.Minute).Unix()
	if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	v, e = s.ResourceHistory(ctx, snap.Approval.DeviceID, at.Add(7*time.Minute))
	if e != nil || v.Status != "revoked" || len(v.Points) != 0 {
		t.Fatal("revoked content visible", e)
	}
}
func TestResourceHistoryCollectionRetentionClockSkewAndExpiry(t *testing.T) {
	_, s, _, snap, cert := activeHistoryFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0)
	// Existing ingress explicitly tolerates thirty seconds of endpoint clock skew.
	raw := measuredResourceFrame(t, 1, at.Add(30*time.Second), 0)
	if _, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at); e != nil {
		t.Fatal("history narrowed ingress clock contract", e)
	}
	v, e := s.ResourceHistory(ctx, snap.Approval.DeviceID, at)
	if e != nil || len(v.Points) != 0 {
		t.Fatal("future sample graphed", e)
	}
	v, e = s.ResourceHistory(ctx, snap.Approval.DeviceID, at.Add(30*time.Second))
	if e != nil || len(v.Points) != 1 || *v.Points[0].CPU.Value != 0 {
		t.Fatal("real zero/skew sample lost", e)
	}
	v, e = s.ResourceHistory(ctx, snap.Approval.DeviceID, at.Add(24*time.Hour+31*time.Second))
	if e != nil || len(v.Points) != 0 || v.Status != "awaiting" {
		t.Fatal("expired sample retained in response", e)
	}
	// Unknown IDs never read another identity, even in the same private database.
	if _, e = s.ResourceHistory(ctx, id("agent", 999), at); !errors.Is(e, enrollmentstate.ErrNotFound) {
		t.Fatal("unknown identity accepted", e)
	}
	v, e = s.ResourceHistory(ctx, snap.Approval.DeviceID, time.Unix(snap.Intent.NotAfter, 0))
	if e != nil || v.Status != "expired" || len(v.Points) != 0 {
		t.Fatal("expired identity readable", e)
	}
}
func TestResourceHistoryOptionalSchemaPreservesExistingIdentityAndNoBackfill(t *testing.T) {
	f, s, path, snap, cert := activeHistoryFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0)
	raw := sampleFrame(t, 1, at)
	if _, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at); e != nil {
		t.Fatal(e)
	}
	// Model a pre-upgrade database that has an authentic latest sample but no
	// optional history table. Opening it must not replay that sample as new data.
	if _, e := s.db.Exec(`DROP INDEX enrollment_resource_history_age; DROP TABLE enrollment_resource_history`); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = f.open(t, path)
	v, e := s.ResourceHistory(ctx, snap.Approval.DeviceID, at.Add(time.Minute))
	if e != nil || len(v.Points) != 0 {
		t.Fatal("legacy sample backfilled", e)
	}
	retry, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(time.Minute))
	if e != nil || !retry.Duplicate {
		t.Fatal("legacy identity/replay lost", e)
	}
	if _, e = s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), sampleFrame(t, 2, at.Add(time.Minute)), at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	v, e = s.ResourceHistory(ctx, snap.Approval.DeviceID, at.Add(time.Minute))
	if e != nil || len(v.Points) != 1 || v.Points[0].Sequence != "2" {
		t.Fatal("new sample not retained", e)
	}
}

func TestResourceHistoryMinuteBoundAndMaintenanceDoNotChangeReplay(t *testing.T) {
	_, s, _, snap, cert := activeHistoryFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0)
	// Populate a full day in one transaction, using the same bounded retention
	// writer as accepted ingress. A real final frame establishes the replay floor.
	e := s.transact(ctx, func(tx *transaction) error {
		for i := 0; i < 1500; i++ {
			ts := at.Add(time.Duration(i) * time.Minute)
			var frame lanstore.Frame
			if json.Unmarshal(sampleFrame(t, uint64(i+1), ts), &frame) != nil {
				t.Fatal("fixture")
			}
			if e := retainResourcePoint(ctx, tx, snap.InvitationID, uint64(i+1), frame.Observation.Observation, ts); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	last := at.Add(1500 * time.Minute)
	raw := sampleFrame(t, 1501, last)
	receipt, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, last)
	if e != nil {
		t.Fatal(e)
	}
	view, e := s.ResourceHistory(ctx, snap.Approval.DeviceID, last)
	if e != nil || len(view.Points) != 1441 || view.Points[0].Sequence != "61" || view.Points[1440].Sequence != "1501" {
		t.Fatal("history not bounded to authentic last day", len(view.Points), e)
	}
	// Bounded maintenance removes only retired history rows, not the current frame
	// or replay receipt. Run enough steps to remove the finite synthetic history.
	for i := 0; i < 6; i++ {
		if e = s.transact(ctx, func(tx *transaction) error { return pruneResourceHistory(ctx, tx, last.Add(25*time.Hour)) }); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e = s.db.QueryRow(`SELECT count(*) FROM enrollment_resource_history`).Scan(&count); e != nil || count != 0 {
		t.Fatal("retired history not reclaimed", e, count)
	}
	retry, e := s.SaveObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, last.Add(25*time.Hour))
	if e != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("maintenance changed replay floor", e)
	}
}

func TestResourceHistoryEncodedViewLifetime(t *testing.T) {
	now := time.Unix(testNow, 0).UTC()
	v := EmptyResourceHistory(id("agent", 1), now, "available")
	v.certificateNotAfter = now.Add(time.Minute).Unix()
	v.Points = []ResourcePoint{{CollectedAt: now.Add(-ResourceHistoryRetention + time.Second), ReceivedAt: now}}
	if e := v.ValidateAt(now.Add(500 * time.Millisecond)); e != nil {
		t.Fatal("valid encoded window rejected", e)
	}
	if e := v.ValidateAt(now.Add(2 * time.Second)); !errors.Is(e, enrollmentstate.ErrExpired) {
		t.Fatal("encoding crossed retention unnoticed", e)
	}
	v.Points[0].CollectedAt = now
	if e := v.ValidateAt(now.Add(time.Minute)); !errors.Is(e, enrollmentstate.ErrExpired) {
		t.Fatal("encoding crossed certificate expiry unnoticed", e)
	}
	if len(v.Points) != 1 || !v.ServerNow.Equal(now) {
		t.Fatal("validation mutated encoded snapshot")
	}
}
