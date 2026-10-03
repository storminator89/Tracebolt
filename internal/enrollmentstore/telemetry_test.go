package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
)

func sampleFrame(t testing.TB, sequence uint64, at time.Time) []byte {
	t.Helper()
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Disposable fixture", CollectedAt: at}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Fixture OS", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at, AgentVersion: "test", CPU: metric, Memory: metric, Disk: metric, Uptime: "unknown", Tags: []string{"read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "test", GeneratedAt: at, Platform: "linux", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	raw, err := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: sequence, Observation: b})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal(err)
	}
	return raw
}
func activeFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f, s, path := fixtureStore(t)
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snapshot, err := s.CommitIssued(context.Background(), control(snapshot, 5), cert)
	if err != nil {
		t.Fatal(err)
	}
	c := control(snapshot, 6)
	snapshot, err = s.Activate(context.Background(), c, f.activation(t, cert, c))
	if err != nil {
		t.Fatal(err)
	}
	return f, s, path, snapshot, cert
}
func TestTelemetryReplayFloorAndExactReceiptSurviveRestart(t *testing.T) {
	f, s, path, snapshot, cert := activeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 123456789)
	raw := sampleFrame(t, 1, at)
	receipt, err := s.SaveObservation(ctx, snapshot.InvitationID, cert.CertificateHash(), raw, at)
	if err != nil || receipt.Sequence != 1 || !receipt.ReceivedAt.Equal(at) {
		t.Fatal(err)
	}
	s.Close()
	s = f.open(t, path)
	retry, err := s.SaveObservation(ctx, snapshot.InvitationID, cert.CertificateHash(), raw, at.Add(3*time.Minute))
	if err != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("exact stale retry refreshed telemetry or failed")
	}
	changed := sampleFrame(t, 1, at.Add(3*time.Minute))
	if _, err = s.SaveObservation(ctx, snapshot.InvitationID, cert.CertificateHash(), changed, at.Add(3*time.Minute)); !errors.Is(err, lanstore.ErrReplay) {
		t.Fatal(err)
	}
	second := sampleFrame(t, 2, at.Add(3*time.Minute))
	if _, err = s.SaveObservation(ctx, snapshot.InvitationID, cert.CertificateHash(), second, at.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LatestObservations(ctx)
	if err != nil || len(rows) != 1 || rows[0].Receipt.Sequence != 2 || rows[0].Device.ID != snapshot.Approval.DeviceID || rows[0].Device.Status != "unknown" {
		t.Fatal("latest observation not bound to durable identity")
	}
	revoke := control(snapshot, 20)
	revoke.Now = at.Add(3*time.Minute + time.Second).Unix()
	if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveObservation(ctx, snapshot.InvitationID, cert.CertificateHash(), second, at.Add(4*time.Minute)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("revoked duplicate accepted")
	}
}
func TestTelemetryRejectsWrongCertificateAndPartialActivation(t *testing.T) {
	f, s, _ := fixtureStore(t)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snapshot, err := s.CommitIssued(ctx, control(snapshot, 5), cert)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(testNow+10, 0)
	raw := sampleFrame(t, 1, at)
	if _, err = s.SaveObservation(ctx, snapshot.InvitationID, cert.CertificateHash(), raw, at); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("unactivated identity saved telemetry")
	}
	c := control(snapshot, 6)
	snapshot, err = s.Activate(ctx, c, f.activation(t, cert, c))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveObservation(ctx, snapshot.InvitationID, f.config.Binding.IssuerFingerprint, raw, at); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("wrong certificate accepted")
	}
	if _, err = s.SaveObservation(ctx, snapshot.InvitationID, cert.CertificateHash(), raw, time.Unix(snapshot.Intent.NotAfter, 0)); !errors.Is(err, enrollmentstate.ErrExpired) {
		t.Fatal("expired certificate accepted")
	}
	rows, err := s.LatestObservations(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal("rejected telemetry mutated current observation")
	}
}
