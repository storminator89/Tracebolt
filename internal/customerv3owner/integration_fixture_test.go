package customerv3owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerproofdomain"
	"localrmm/internal/customerv3proof"
	"localrmm/internal/enrollmentissuer"
)

// This joins actual source packages using temporary fixture stores, keys and
// permissive fixture leases. It is NOT a manager, HTTP, host or Windows test.
func TestCustomerV3CrossPackageFixtureClaimToActivation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "sqlite")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(f.issuer)
	fingerprint := hex.EncodeToString(h[:])
	pool, err := customerchallenge.New(customerchallenge.Binding{ManagerID: f.manager, Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: fingerprint}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	budget := customerbudget.New()
	domain, err := customerproofdomain.NewWithBudget(pool, f.pending, f.clock, func(ctx context.Context, m customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return f.original(ctx, m, f.managerDigest)
	}, budget)
	if err != nil {
		t.Fatal(err)
	}
	customer, profile, claimID := id("customer", 2), id("profile", 3), id("claim", 1)
	challenge, err := pool.Issue("192.0.2.1", customer, profile, claimID)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	claimRequest := id("request", 1)
	claimMessage, err := customerclaim.SigningMessage(challenge, claimRequest, csr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(challenge, claimRequest, csr, ed25519.Sign(key, claimMessage), f.now)
	if err != nil {
		t.Fatal(err)
	}
	record, err := domain.Admit(ctx, challenge.Challenge, raw)
	if err != nil {
		t.Fatal(err)
	}
	if record.CustomerID != customer || record.InstallerProfileID != profile || record.ClaimID != claimID {
		t.Fatal("claim binding changed")
	}
	if _, err = domain.Admit(ctx, challenge.Challenge, raw); err == nil {
		t.Fatal("claim challenge replay accepted")
	}
	expected := customerpending.ReviewExpectation{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, ClaimID: record.ClaimID, ClaimHash: record.ClaimHash, KeyFingerprint: record.KeyFingerprint, ManagerDigest: f.managerDigest, CustomerRevision: f.revision, DeadlineAt: record.DeadlineAt}
	review := request(expected, 1)
	review.Decision.Acknowledged = false
	if _, err = f.store.Commit(ctx, f.pending, review, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage); err == nil {
		t.Fatal("unacknowledged review accepted")
	}
	rows, err := f.store.Records(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal("unapproved intent retained", err)
	}
	review.Decision.Acknowledged = true
	review.Decision.FingerprintCompared = false
	if _, err = f.store.Commit(ctx, f.pending, review, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage); err == nil {
		t.Fatal("review without fingerprint comparison accepted")
	}
	review.Decision.FingerprintCompared = true
	intent, err := f.store.Commit(ctx, f.pending, review, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := enrollmentissuer.New(f.issuer, f.root, f.issuerKey, fingerprint, f.now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := issuer.SignCustomer(ctx, intent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := f.commitCertificate(ctx, CertificateRequest{ClaimID: claimID, IntentID: intent.IntentID, IntentDigest: verified.IntentDigest()}, verified)
	if err != nil {
		t.Fatal(err)
	}
	status, err := pool.IssueStatus("192.0.2.1", customer, profile, claimID)
	if err != nil {
		t.Fatal(err)
	}
	m := customerclaim.Metadata{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, Origin: record.Origin, AgentOrigin: record.AgentOrigin, IssuerFingerprint: record.IssuerFingerprint, ClaimID: record.ClaimID, RequestID: record.RequestID, KeyFingerprint: record.KeyFingerprint, CSRHash: record.CSRHash, ClaimHash: record.ClaimHash, ComparisonCode: record.ComparisonCode}
	statusID := id("request", 30)
	statusMessage, err := customerclaim.StatusSigningMessage(status, m, record.PublicKeyDER, statusID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	statusRaw, err := customerclaim.EncodeStatus(status, m, record.PublicKeyDER, statusID, ed25519.Sign(key, statusMessage), f.now)
	if err != nil {
		t.Fatal(err)
	}
	var public customerissuance.PublicIntent
	err = f.store.WithPublicProjection(ctx, f.pending, pool, budget, status.Challenge, statusRaw, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(p customerissuance.PublicIntent, guard func() error) error {
		if e := guard(); e != nil {
			return e
		}
		public = p
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"actor", "customerRevision", "operationId", "csr", "publicKeyDer", "comparisonCode", "managerDigest"} {
		if bytes.Contains(bytes.ToLower(encoded), bytes.ToLower([]byte(v))) {
			t.Fatal("private review field disclosed", v)
		}
	}
	local := customerissuance.LocalPublicBinding{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, ClaimID: record.ClaimID, IssuerFingerprint: record.IssuerFingerprint, Origin: record.Origin, AgentOrigin: record.AgentOrigin, DeadlineAt: record.DeadlineAt, PublicKeyDER: bytes.Clone(record.PublicKeyDER)}
	requestCredential := func(view customerissuance.PublicIntent) (CredentialRequest, error) {
		c, e := pool.IssueCredentialV3("192.0.2.1", customer, profile, claimID)
		if e != nil {
			return CredentialRequest{}, e
		}
		requestID := id("request", 31)
		message, e := customerv3proof.SigningMessagePublic(view, local, record.ClaimHash, customerv3proof.Credential, c, requestID, "", f.now)
		if e != nil {
			return CredentialRequest{}, e
		}
		return CredentialRequest{ClaimID: local.ClaimID, IntentID: view.IntentID, IntentDigest: view.IntentDigest, RequestID: requestID, Nonce: c.Challenge, Signature: ed25519.Sign(key, message)}, nil
	}
	wrongPublic := public
	wrongPublic.IntentID = id("intent", 999)
	wrongIntent, err := requestCredential(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	routingContext := customerclaim.Context{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, Origin: record.Origin, AgentOrigin: record.AgentOrigin, IssuerFingerprint: record.IssuerFingerprint, ClaimID: record.ClaimID, Challenge: wrongIntent.Nonce, ExpiresAt: f.now.Unix() + int64(customerclaim.MaxChallengeLifetime/time.Second)}
	correctBytes, err := customerv3proof.SigningMessagePublic(public, local, record.ClaimHash, customerv3proof.Credential, routingContext, wrongIntent.RequestID, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	changedBytes, err := customerv3proof.SigningMessagePublic(wrongPublic, local, record.ClaimHash, customerv3proof.Credential, routingContext, wrongIntent.RequestID, "", f.now)
	if err != nil || !bytes.Equal(correctBytes, changedBytes) {
		t.Fatal("routing ID unexpectedly changed legacy proof bytes", err)
	}
	if err = f.store.WithCredential(ctx, f.pending, pool, budget, wrongIntent, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(customerissuance.PublicIntent, []byte, func() error) error {
		t.Fatal("mismatched intent disclosed certificate")
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatal("changed intent ID accepted with original digest", err)
	}
	cr, err := requestCredential(public)
	if err != nil {
		t.Fatal(err)
	}
	// An unrelated device key cannot use the original claim, even with the
	// exact server-derived challenge and all public routing fields.
	_, foreignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad := cr
	foreignChallenge := customerclaim.Context{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, Origin: record.Origin, AgentOrigin: record.AgentOrigin, IssuerFingerprint: record.IssuerFingerprint, ClaimID: record.ClaimID, Challenge: cr.Nonce, ExpiresAt: f.now.Unix() + int64(customerclaim.MaxChallengeLifetime/time.Second)}
	foreignMessage, err := customerv3proof.SigningMessagePublic(public, local, record.ClaimHash, customerv3proof.Credential, foreignChallenge, cr.RequestID, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	bad.Signature = ed25519.Sign(foreignKey, foreignMessage)
	if err = f.store.WithCredential(ctx, f.pending, pool, budget, bad, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(customerissuance.PublicIntent, []byte, func() error) error {
		t.Fatal("foreign key disclosed certificate")
		return nil
	}); err == nil {
		t.Fatal("foreign key accepted")
	}
	if err = f.store.WithCredential(ctx, f.pending, pool, budget, cr, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(customerissuance.PublicIntent, []byte, func() error) error {
		t.Fatal("failed proof refunded challenge")
		return nil
	}); err == nil {
		t.Fatal("failed proof did not consume challenge")
	}
	cr, err = requestCredential(public)
	if err != nil {
		t.Fatal(err)
	}
	var leaf []byte
	err = f.store.WithCredential(ctx, f.pending, pool, budget, cr, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(p customerissuance.PublicIntent, der []byte, guard func() error) error {
		if e := guard(); e != nil {
			return e
		}
		if p != public {
			return errors.New("projection changed")
		}
		leaf = bytes.Clone(der)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf, cert.DER) {
		t.Fatal("delivery differed from committed certificate")
	}
	if err = f.store.WithCredential(ctx, f.pending, pool, budget, cr, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(customerissuance.PublicIntent, []byte, func() error) error {
		t.Fatal("credential replay disclosed")
		return nil
	}); err == nil {
		t.Fatal("credential challenge replay accepted")
	}
	leafProof, err := customerissuance.VerifyPublicLeaf(leaf, f.issuer, f.root, public, local, f.now)
	if err != nil {
		t.Fatal(err)
	}
	requestActivation := func(view customerissuance.PublicIntent) (ActivationRequest, error) {
		c, e := pool.IssueActivationV3("192.0.2.1", customer, profile, claimID)
		if e != nil {
			return ActivationRequest{}, e
		}
		requestID := id("request", 32)
		message, e := customerv3proof.SigningMessagePublic(view, local, record.ClaimHash, customerv3proof.Activation, c, requestID, leafProof.CertificateHash(), f.now)
		if e != nil {
			return ActivationRequest{}, e
		}
		return ActivationRequest{ClaimID: local.ClaimID, IntentID: view.IntentID, IntentDigest: view.IntentDigest, RequestID: requestID, Nonce: c.Challenge, Signature: ed25519.Sign(key, message)}, nil
	}
	wrongActivation, err := requestActivation(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Activate(ctx, f.pending, pool, budget, wrongActivation, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage); !errors.Is(err, ErrConflict) {
		t.Fatal("activation accepted changed intent ID with original digest", err)
	}
	ar, err := requestActivation(public)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := f.store.Activate(ctx, f.pending, pool, budget, ar, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage)
	if err != nil {
		t.Fatal(err)
	}
	if activated.IntentDigest != public.IntentDigest || activated.CertificateHash != leafProof.CertificateHash() || activated.KeyFingerprint != record.KeyFingerprint {
		t.Fatal("activation binding changed")
	}
	if _, err = f.store.Activate(ctx, f.pending, pool, budget, ar, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage); err == nil {
		t.Fatal("activation replay accepted")
	}
	activations, err := f.store.ActivationRecords(ctx)
	if err != nil || len(activations) != 1 || activations[0] != activated {
		t.Fatal("activation not retained", err)
	}
	if budget.InUse() != 0 || strings.Contains(string(encoded), record.ComparisonCode) {
		t.Fatal("budget or data boundary failed")
	}
}
