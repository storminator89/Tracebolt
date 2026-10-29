package enrollmentservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"path/filepath"
	"testing"
)

func TestSelfClaimRequiresProofAndOperatorApproval(t *testing.T) {
	f := newFixture(t, "tls")
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	f.path = filepath.Join(t.TempDir(), "private", "windows.db")
	f.restart(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{37}, 32))
	c := challenge(t, f, id("invite", 90), id("claim", 90), "claim")
	message, err := enrollmentcrypto.ClaimSigningMessage(c.Context, id("request", 90), csr, secret, f.now)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": "tls", "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": c.Context.InvitationID, "claimId": c.Context.ClaimID, "requestId": id("request", 90), "challenge": c.Context.Challenge, "invitationSecret": secret, "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	pending, err := f.service.SelfClaim(context.Background(), c.Context.Challenge, body)
	if err != nil || pending.State != enrollmentstate.ClaimedPending {
		t.Fatal("self claim", err)
	}
	if _, err := f.service.SelfClaim(context.Background(), c.Context.Challenge, body); !errors.Is(err, ErrChallenge) {
		t.Fatal("challenge reused", err)
	}
	c, b := status(t, f, pending.InvitationID, pending.Claim.ClaimID, "credential", 91, key)
	if _, err := f.service.CredentialEnvelope(context.Background(), c.Context.Challenge, b); err == nil {
		t.Fatal("credential before operator approval")
	}
	approved, err := f.service.Approve(context.Background(), pending.InvitationID, id("request", 92), pending.Claim.KeyFingerprint, pending.Revision)
	if err != nil || approved.State != enrollmentstate.Approved {
		t.Fatal(err)
	}
	c, b = status(t, f, pending.InvitationID, pending.Claim.ClaimID, "status", 93, key)
	issued, err := f.service.Status(context.Background(), c.Context.Challenge, b)
	if err != nil || issued.State != enrollmentstate.Issued {
		t.Fatal("approved self claim did not issue", err)
	}
	c, b = status(t, f, pending.InvitationID, pending.Claim.ClaimID, "credential", 94, key)
	credential, err := f.service.CredentialEnvelope(context.Background(), c.Context.Challenge, b)
	if err != nil || credential.Intent.DeviceID != approved.Approval.DeviceID {
		t.Fatal("credential mismatch", err)
	}
}

func TestSelfClaimDoesNotEnableOtherDomains(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		f := newFixture(t, transport)
		if f.service.SelfClaimAvailable() {
			t.Fatal("basic domain exposes self claim")
		}
		f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
		f.path = filepath.Join(t.TempDir(), "private", "windows.db")
		f.restart(t)
		if f.service.SelfClaimAvailable() != (transport == "tls") {
			t.Fatal("transport mismatch")
		}
	}
}
