package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/operational"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func operationalFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f := newFixture(t)
	f.config.Binding.CollectionProfile = operational.CollectionProfile
	f.challenge.CollectionProfile = operational.CollectionProfile
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	path := filepath.Join(t.TempDir(), "private", "operations.db")
	s := f.open(t, path)
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snapshot, e := s.CommitIssued(context.Background(), control(snapshot, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	c := control(snapshot, 6)
	snapshot, e = s.Activate(context.Background(), c, f.activation(t, cert, c))
	if e != nil {
		t.Fatal(e)
	}
	return f, s, path, snapshot, cert
}
func operationalFrame(t *testing.T, sequence uint64, at time.Time, service bool) ([]byte, operational.Snapshot) {
	t.Helper()
	basic := sampleFrame(t, sequence, at)
	var frame lanstore.Frame
	if json.Unmarshal(basic, &frame) != nil {
		t.Fatal("basic fixture")
	}
	op := operational.Empty(at, operational.ReasonNotImplemented)
	if service {
		m := op.Sections.Services.Meta
		m.Quality = operational.Healthy
		m.Reason = operational.ReasonNone
		m.Complete = true
		m.ObservedCount = 1
		m.CountExact = true
		op.Sections.Services = operational.ServiceSection{Meta: m, Items: []operational.Service{{Name: "fixture.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"}}}
	}
	if operational.Validate(op) != nil {
		t.Fatal("operational fixture invalid")
	}
	frame.SchemaVersion = lanstore.FrameOperationalVersion
	frame.Operational = &op
	raw, e := json.Marshal(frame)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, at); e != nil {
		t.Fatal(e)
	}
	return raw, op
}
func TestOperationalProfileRetentionReplayExpiryAndReopen(t *testing.T) {
	f, s, path, identity, cert := operationalFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	raw, first := operationalFrame(t, 1, at, true)
	receipt, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, at)
	if e != nil {
		t.Fatal("save operational", e)
	}
	view, e := s.OperationalView(ctx, identity.Approval.DeviceID, at)
	if e != nil || view.Status != "fresh" || view.Snapshot == nil || view.LastGood.Services == nil {
		t.Fatal("fresh operational view", e)
	}
	if view.LastGood.Services.Meta.Quality != "stale" || view.LastGood.Services.Meta.GenerationID != first.GenerationID {
		t.Fatal("retained provenance")
	}
	later := at.Add(time.Second)
	next, second := operationalFrame(t, 2, later, false)
	if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), next, later); e != nil {
		t.Fatal("partial observation", e)
	}
	view, e = s.OperationalView(ctx, identity.Approval.DeviceID, later)
	if e != nil || view.Snapshot.GenerationID != second.GenerationID || view.LastGood.Services.Meta.GenerationID != first.GenerationID || !view.LastGood.Services.Meta.ObservedAt.Equal(at) {
		t.Fatal("last-good replaced by unknown", e)
	}
	s.Close()
	s = f.open(t, path)
	duplicate, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), next, later.Add(time.Minute))
	if e != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(later) {
		t.Fatal("exact retry refreshed age", e)
	}
	stale, e := s.OperationalView(ctx, identity.Approval.DeviceID, later.Add(3*time.Minute))
	if e != nil || stale.Status != "stale" || stale.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("freshness or receipt changed", e)
	}
	expired, e := s.OperationalView(ctx, identity.Approval.DeviceID, later.Add(25*time.Hour))
	if e != nil || expired.Snapshot != nil || expired.LastGood.Services != nil {
		t.Fatal("expired view retained sections", e)
	}
	s.Close()
	s = f.open(t, path)
	var stored operationalRecord
	if e = s.transact(ctx, func(tx *transaction) error { stored = tx.operational[identity.InvitationID]; return nil }); e != nil || stored.LastGood.Services != nil {
		t.Fatal("last-good expiry not durable", e)
	}
}
func TestOperationalRejectsProfileMismatchAndNewSequenceOldCollection(t *testing.T) {
	_, s, _, identity, cert := operationalFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	basic := sampleFrame(t, 1, at)
	if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), basic, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("basic frame widened profile", e)
	}
	raw, op := operationalFrame(t, 1, at, true)
	if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, at); e != nil {
		t.Fatal(e)
	}
	var old lanstore.Frame
	json.Unmarshal(raw, &old)
	later := sampleFrame(t, 2, at.Add(time.Second))
	var next lanstore.Frame
	json.Unmarshal(later, &next)
	next.SchemaVersion = lanstore.FrameOperationalVersion
	next.Operational = &op
	changed, _ := json.Marshal(next)
	if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), changed, at.Add(time.Second)); !errors.Is(e, lanstore.ErrReplay) {
		t.Fatal("old operational collection refreshed", e)
	}
	view, e := s.OperationalView(ctx, identity.Approval.DeviceID, at.Add(time.Second))
	if e != nil || *view.Sequence != 1 || !view.ReceivedAt.Equal(at) {
		t.Fatal("failed frame changed state", e)
	}
	_, basicStore, _, basicID, basicCert := activeFixture(t)
	if _, e := basicStore.SaveObservation(ctx, basicID.InvitationID, basicCert.CertificateHash(), raw, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("operational frame accepted by basic identity", e)
	}
}
func TestOperationalSchemaCannotAdoptBasicStore(t *testing.T) {
	f, s, path := fixtureStore(t)
	s.Close()
	before, _ := os.ReadFile(path)
	f.config.Binding.CollectionProfile = operational.CollectionProfile
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	if other, e := Open(path, f.config, f.issuerDER); e == nil {
		other.Close()
		t.Fatal("basic store silently migrated")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("rejected profile altered database")
	}
}
