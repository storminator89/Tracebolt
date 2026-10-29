package customerv3owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
)

func (f *fixture) original(ctx context.Context, _ customerclaim.Metadata, digest string) (customerpending.AuthorityLease, error) {
	if digest != f.managerDigest {
		return nil, ErrConflict
	}
	return lease{check: func() error {
		if !f.allowed {
			return errors.New("authority revoked")
		}
		return ctx.Err()
	}}, nil
}

func (f *fixture) certificateFixture(t *testing.T) (CertificateRequest, customerissuance.VerifiedCertificate) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.deviceKey = key
	expect := f.claim(t, key, 1)
	intent, err := f.store.Commit(context.Background(), f.pending, request(expect, 1), f.issuer, f.root, f.clock, f.acquire, f.live, f.storage)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(intent.Approval.Candidate.Pending.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	serial, ok := new(big.Int).SetString(intent.SerialHex, 16)
	if !ok {
		t.Fatal("serial")
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: intent.Approval.Candidate.DeviceID}, NotBefore: time.Unix(intent.NotBefore, 0), NotAfter: time.Unix(intent.NotAfter, 0), SignatureAlgorithm: x509.PureEd25519, BasicConstraintsValid: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, AuthorityKeyId: bytes.Clone(f.issuerCert.SubjectKeyId)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.issuerCert, pub, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := customerissuance.VerifyIssued(der, f.issuer, f.root, intent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return CertificateRequest{ClaimID: expect.ClaimID, IntentID: intent.IntentID, IntentDigest: proof.IntentDigest()}, proof
}

func (f *fixture) commitCertificate(ctx context.Context, req CertificateRequest, proof customerissuance.VerifiedCertificate) (CertificateRecord, error) {
	return f.store.CommitCertificate(ctx, f.pending, req, proof, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage)
}

func (f *fixture) issuance(ctx context.Context, intent customerissuance.Intent, digest string) (IssuanceAuthorityLease, error) {
	actual, err := customerissuance.Digest(intent)
	if err != nil || actual != digest || intent.Approval.Actor.Mode != "shared" || intent.Approval.Actor.ID != "" {
		return nil, ErrInvalid
	}
	return lease{check: func() error {
		if f.issuanceRevoked {
			return errors.New("approval revoked")
		}
		return f.issuerGuard(ctx, intent.Approval.Candidate.Pending.IssuerFingerprint)
	}}, nil
}

func TestCertificateBoundToStoredIntentAndRename(t *testing.T) {
	f := newFixture(t, "sqlite")
	req, proof := f.certificateFixture(t)
	f.revision++          // The reviewed revision remains in the intent, not live rename policy.
	f.sessionEnded = true // Approval was already committed under the original session.
	r, err := f.commitCertificate(context.Background(), req, proof)
	if err != nil {
		t.Fatal(err)
	}
	if r.IntentDigest != req.IntentDigest || r.CertificateHash != proof.CertificateHash() || !bytes.Equal(r.DER, proof.DER()) {
		t.Fatal("binding or bytes changed")
	}
	rows, err := f.store.CertificateRecords(context.Background())
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].DER, proof.DER()) {
		t.Fatal("certificate not durably retained", err)
	}
	if _, err = f.commitCertificate(context.Background(), req, proof); !errors.Is(err, ErrConflict) {
		t.Fatal("replay was not rejected", err)
	}
}

func TestCertificateGuardsAndOriginalBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fixture, *CertificateRequest)
	}{
		{"wrong intent", func(_ *fixture, r *CertificateRequest) { r.IntentID = id("intent", 999) }},
		{"wrong claim", func(_ *fixture, r *CertificateRequest) { r.ClaimID = id("claim", 999) }},
		{"wrong digest", func(_ *fixture, r *CertificateRequest) {
			r.IntentDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"authority revoked", func(f *fixture, _ *CertificateRequest) { f.allowed = false }},
		{"approval revoked", func(f *fixture, _ *CertificateRequest) { f.issuanceRevoked = true }},
		{"issuer revoked", func(f *fixture, _ *CertificateRequest) { f.issuerRevoked = true }},
		{"deadline expired", func(f *fixture, _ *CertificateRequest) { f.now = f.now.Add(customerpending.PendingLifetime) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "sqlite")
			r, p := f.certificateFixture(t)
			tc.mutate(f, &r)
			if _, err := f.commitCertificate(context.Background(), r, p); err == nil {
				t.Fatal("unexpected commit")
			}
			rows, err := f.store.CertificateRecords(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatal("failed attempt retained result", err)
			}
		})
	}
}

func TestCertificateLostCommitAcknowledgement(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-cert-lost-%d", driverSequence.Add(1))
	sql.Register(name, d)
	f := newFixture(t, name)
	r, p := f.certificateFixture(t)
	d.fail.Store(true)
	if _, err := f.commitCertificate(context.Background(), r, p); !errors.Is(err, ErrUncertain) {
		t.Fatal("ambiguous commit reported as success", err)
	}
	rows, err := f.store.CertificateRecords(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal("reconciliation lost commit", err)
	}
	if _, err = f.commitCertificate(context.Background(), r, p); !errors.Is(err, ErrConflict) {
		t.Fatal("uncertain result replayed", err)
	}
}

func TestCertificateConcurrentSingleCommit(t *testing.T) {
	f := newFixture(t, "sqlite")
	r, p := f.certificateFixture(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.commitCertificate(context.Background(), r, p)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted, conflicts := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatalf("accepted=%d conflicts=%d", accepted, conflicts)
	}
	rows, err := f.store.CertificateRecords(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal("single result not retained", err)
	}
}

func TestCertificateLateSuccessfulCommitIsUncertain(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-cert-late-%d", driverSequence.Add(1))
	sql.Register(name, d)
	f := newFixture(t, name)
	r, p := f.certificateFixture(t)
	d.delayCommit.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := f.commitCertificate(ctx, r, p); !errors.Is(err, ErrUncertain) {
		t.Fatal("late commit reported as success", err)
	}
	rows, err := f.store.CertificateRecords(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal("late commit not reconcilable", err)
	}
}

func TestCertificateIssuanceLeaseCannotMutateStoredIntent(t *testing.T) {
	f := newFixture(t, "sqlite")
	r, p := f.certificateFixture(t)
	mutating := func(ctx context.Context, intent customerissuance.Intent, digest string) (IssuanceAuthorityLease, error) {
		l, err := f.issuance(ctx, intent, digest)
		if err != nil {
			return nil, err
		}
		intent.Approval.Candidate.Pending.PublicKeyDER[0] ^= 1
		return l, nil
	}
	_, err := f.store.CommitCertificate(context.Background(), f.pending, r, p, f.issuer, f.root, f.clock, f.original, mutating, f.storage)
	if err != nil {
		t.Fatal("callback slice mutated protected local intent", err)
	}
	rows, err := f.store.CertificateRecords(context.Background())
	if err != nil || len(rows) != 1 || rows[0].IntentDigest != r.IntentDigest {
		t.Fatal("original binding changed", err)
	}
}

func TestCertificateRejectsChangedOriginalPendingRecord(t *testing.T) {
	f := newFixture(t, "sqlite")
	r, p := f.certificateFixture(t)
	var raw []byte
	if err := f.pendingDB.QueryRow(`SELECT body FROM customer_pending_claims WHERE claim_id=?`, r.ClaimID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var pending customerpending.Record
	if err := json.Unmarshal(raw, &pending); err != nil {
		t.Fatal(err)
	}
	pending.RequestID = id("request", 999)
	raw, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pendingDB.Exec(`UPDATE customer_pending_claims SET body=? WHERE claim_id=?`, raw, r.ClaimID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.commitCertificate(context.Background(), r, p); err == nil {
		t.Fatal("altered original pending record accepted", err)
	}
}
