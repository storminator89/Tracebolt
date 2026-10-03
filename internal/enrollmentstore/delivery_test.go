package enrollmentstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

func TestDeliveryRequiresPurposeBoundProofAndPersistsExactRetry(t *testing.T) {
	f, s, path := fixtureStore(t)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snapshot, err := s.CommitIssued(ctx, control(snapshot, 5), cert)
	if err != nil {
		t.Fatal(err)
	}
	c := control(snapshot, 10)
	purposeStatus := f.status(t, enrollmentcrypto.PurposeStatus, c.RequestID, c.Now)
	if raw, err := s.DeliverCredential(ctx, c, purposeStatus); !errors.Is(err, enrollmentstate.ErrProof) || raw != nil {
		t.Fatal("status proof delivered credential")
	}
	proof := f.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now)
	if _, err = s.ReadStatus(ctx, c.InvitationID, proof, time.Unix(c.Now, 0)); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("credential proof read status")
	}
	raw, err := s.DeliverCredential(ctx, c, proof)
	if err != nil || !bytes.Equal(raw, cert.DER()) {
		t.Fatalf("delivery failed: %v", err)
	}
	var recorded Delivery
	if err = s.transact(ctx, func(tx *transaction) error { recorded = tx.credentials[snapshot.InvitationID].Delivery; return nil }); err != nil {
		t.Fatal(err)
	}
	if recorded.Count != 1 || recorded.FirstAt != c.Now || recorded.LastAt != c.Now {
		t.Fatal("delivery ledger missing")
	}
	s.Close()
	s = f.open(t, path)
	c.Now++
	c.ExpectedRevision--
	raw, err = s.DeliverCredential(ctx, c, f.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now))
	if err != nil || !bytes.Equal(raw, cert.DER()) {
		t.Fatalf("delivery retry failed: %v", err)
	}
	if err = s.transact(ctx, func(tx *transaction) error {
		if tx.credentials[snapshot.InvitationID].Delivery != recorded {
			t.Fatal("exact retry refreshed delivery metadata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c.ExpectedRevision = snapshot.Revision
	c.RequestID = id("request", 11)
	c.Now++
	if _, err = s.DeliverCredential(ctx, c, f.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now)); err != nil {
		t.Fatal(err)
	}
	revoke := control(snapshot, 20)
	revoke.Now = c.Now + 1
	snapshot, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked})
	if err != nil {
		t.Fatal(err)
	}
	c.Now = revoke.Now + 1
	if raw, err = s.DeliverCredential(ctx, c, f.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now)); !errors.Is(err, enrollmentstate.ErrState) || raw != nil {
		t.Fatal("revoked identity delivered credential")
	}
	got, err := s.ReadStatus(ctx, c.InvitationID, f.status(t, enrollmentcrypto.PurposeStatus, c.RequestID, c.Now), time.Unix(c.Now, 0))
	if err != nil || got.State != enrollmentstate.Revoked {
		t.Fatal("bound key could not read terminal outcome")
	}
}
func TestDeliveryWriteFailureNeverReturnsDER(t *testing.T) {
	f, s, _ := fixtureStore(t)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snapshot, err := s.CommitIssued(ctx, control(snapshot, 5), cert)
	if err != nil {
		t.Fatal(err)
	}
	c := control(snapshot, 10)
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	raw, err := s.DeliverCredential(ctx, c, f.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now))
	if err == nil || raw != nil {
		t.Fatal("failed delivery returned uncommitted DER")
	}
	if _, err = s.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	err = s.transact(ctx, func(tx *transaction) error {
		if tx.credentials[snapshot.InvitationID].Delivery != (Delivery{}) {
			t.Fatal("failed delivery recorded metadata")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestDeliveryFreshProofExpiryAndStoredCertificateLookup(t *testing.T) {
	f, s, _ := fixtureStore(t)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snapshot, err := s.CommitIssued(ctx, control(snapshot, 5), cert)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.CertificateForVerification(ctx, snapshot.InvitationID)
	if err != nil || stored.Intent() != intent || !bytes.Equal(stored.DER(), cert.DER()) {
		t.Fatal("persisted certificate verification mismatch")
	}
	c := control(snapshot, 10)
	proof := f.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now)
	c.Now = proof.ExpiresAt()
	if _, err = s.DeliverCredential(ctx, c, proof); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal(err)
	}
	c.Now = snapshot.DeadlineAt
	if _, err = s.DeliverCredential(ctx, c, f.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now)); !errors.Is(err, enrollmentstate.ErrExpired) {
		t.Fatal(err)
	}
}

func TestDeliveryRejectsCrossOriginAndWrongApprovedKeyProofs(t *testing.T) {
	f, s, _ := fixtureStore(t)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snapshot, err := s.CommitIssued(ctx, control(snapshot, 5), cert)
	if err != nil {
		t.Fatal(err)
	}
	c := control(snapshot, 10)
	other := f
	other.challenge.Origin = "https://other.example"
	if _, err = s.DeliverCredential(ctx, c, other.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now)); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("cross-origin delivery accepted")
	}
	other = newFixture(t)
	other.challenge = f.challenge
	if _, err = s.DeliverCredential(ctx, c, other.status(t, enrollmentcrypto.PurposeCredential, c.RequestID, c.Now)); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("another generated key retrieved credential")
	}
}
