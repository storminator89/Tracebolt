package enrollmentstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
)

func TestCurrentCredentialAuthorityKeepsAnchorAndRejectsRetiredLeaf(t *testing.T) {
	f, s, _, snapshot, anchor := activeFixture(t)
	intent := anchor.Intent()
	intent.IntentID = id("intent", 201)
	intent.RequestID = id("request", 201)
	intent.SerialHex = "000000000000000000000000000000c9"
	intent.NotAfter += 86400
	current := f.issue(t, intent)
	at := time.Unix(testNow+20, 0)
	rollback := errors.New("fixture authority checks only")
	err := s.transact(context.Background(), func(tx *transaction) error {
		original := tx.credentials[snapshot.InvitationID]
		c := original
		c.Renewal = &renewalRecord{Current: renewalLeaf{Intent: current.Intent(), DER: current.DER(), CertificateHash: current.CertificateHash(), Generation: 2, ActivatedAt: at.Unix(), RequestID: intent.RequestID}, UpdatedAt: at.Unix()}
		tx.credentials[snapshot.InvitationID] = c
		if err := tx.authorizeCurrentCredential(snapshot, anchor.CertificateHash(), at); !errors.Is(err, enrollmentstate.ErrProof) {
			t.Fatal("retired bare hash was accepted", err)
		}
		if err := tx.authorizeCurrentCredential(snapshot, current.CertificateHash(), at); err != nil {
			t.Fatal("current leaf rejected", err)
		}
		if err := tx.authorizeCurrentCredential(snapshot, current.CertificateHash(), time.Unix(snapshot.Intent.NotAfter+1, 0)); err != nil {
			t.Fatal("renewed identity expired at anchor lifetime", err)
		}
		if err := tx.authorizeCurrentCredential(snapshot, current.CertificateHash(), time.Unix(intent.NotAfter, 0)); !errors.Is(err, enrollmentstate.ErrExpired) {
			t.Fatal("current expiry not enforced", err)
		}
		if err := tx.authorizeCurrentCredential(snapshot, current.CertificateHash(), at.Add(-time.Second)); !errors.Is(err, enrollmentstate.ErrInvalid) {
			t.Fatal("renewal clock rollback accepted", err)
		}
		tx.ctx = WithAuthenticatedCertificate(context.Background(), current.CertificateHash())
		if err := tx.authorizeCurrentCredential(snapshot, anchor.CertificateHash(), at); err != nil {
			t.Fatal("current transport did not map to stable grant anchor", err)
		}
		tx.ctx = WithAuthenticatedCertificate(context.Background(), anchor.CertificateHash())
		for _, supplied := range []string{anchor.CertificateHash(), current.CertificateHash()} {
			if err := tx.authorizeCurrentCredential(snapshot, supplied, at); !errors.Is(err, enrollmentstate.ErrProof) {
				t.Fatal("stale in-flight transport survived activation", err)
			}
		}
		tx.ctx = WithAuthenticatedCertificate(context.Background(), current.CertificateHash())
		revoked := snapshot
		revoked.State = enrollmentstate.Revoked
		if err := tx.authorizeCurrentCredential(revoked, anchor.CertificateHash(), at); !errors.Is(err, enrollmentstate.ErrState) {
			t.Fatal("renewal bypassed identity-wide revocation", err)
		}
		stored, err := tx.engine.Get(snapshot.InvitationID)
		if err != nil || stored != snapshot || !bytes.Equal(tx.credentials[snapshot.InvitationID].DER, original.DER) {
			t.Fatal("renewal authorization changed immutable anchor", err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
}

func TestPendingRenewalCandidateHasNoOrdinaryAuthority(t *testing.T) {
	f, s, _, snapshot, anchor := activeFixture(t)
	intent := anchor.Intent()
	intent.IntentID = id("intent", 202)
	intent.RequestID = id("request", 202)
	intent.SerialHex = "000000000000000000000000000000ca"
	intent.NotAfter += 86400
	candidate := f.issue(t, intent)
	at := time.Unix(testNow+20, 0)
	rollback := errors.New("fixture authority checks only")
	err := s.transact(context.Background(), func(tx *transaction) error {
		c := tx.credentials[snapshot.InvitationID]
		c.Renewal = initialRenewal(anchor, snapshot.Activation.At, 1)
		c.Renewal.Candidate = &renewalCandidate{Leaf: renewalLeaf{Intent: candidate.Intent(), DER: candidate.DER(), CertificateHash: candidate.CertificateHash(), Generation: 2}}
		tx.credentials[snapshot.InvitationID] = c
		if err := tx.authorizeCurrentCredential(snapshot, anchor.CertificateHash(), at); err != nil {
			t.Fatal("candidate prematurely retired current leaf", err)
		}
		if err := tx.authorizeCurrentCredential(snapshot, candidate.CertificateHash(), at); !errors.Is(err, enrollmentstate.ErrProof) {
			t.Fatal("unactivated candidate authorized telemetry", err)
		}
		tx.ctx = WithAuthenticatedCertificate(context.Background(), candidate.CertificateHash())
		if err := tx.authorizeCurrentCredential(snapshot, anchor.CertificateHash(), at); !errors.Is(err, enrollmentstate.ErrProof) {
			t.Fatal("candidate transport mapped to active anchor", err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
}
