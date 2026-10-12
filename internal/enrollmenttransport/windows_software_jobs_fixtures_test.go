package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
)

// Synthetic identities only: all private keys are generated in test memory,
// and no listener, agent service, host grant, or native executor is started.
func enrollWindowsSoftwareJobObserver(t *testing.T, seed *fixture, index int) *fixture {
	t.Helper()
	copy := *seed
	f := &copy
	_, f.key = key(t)
	ctx := context.Background()
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index)}, 32))
	hash, _ := enrollmentcrypto.InvitationHash(secret)
	var err error
	f.snapshot, err = f.store.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: id("invite", index), RequestID: id("request", index*10+1), InvitationHash: hex.EncodeToString(hash[:]), Platform: "windows", Now: f.now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	f.challenge = enrollmentcrypto.ChallengeContext{ManagerInstanceID: f.config.Binding.InstanceID, Profile: "tls", Origin: f.config.Binding.Origin, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, InvitationID: f.snapshot.InvitationID, ClaimID: id("claim", index), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32)), ExpiresAt: f.now.Unix() + 60}
	if f.config.AutomaticRenewal {
		f.challenge.RenewalPolicy = enrollmentcrypto.RenewalPolicySameKey
		f.challenge.AgentOrigin = f.config.RenewalAgentOrigin
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, f.key)
	if err != nil {
		t.Fatal(err)
	}
	message, err := enrollmentcrypto.ClaimSigningMessage(f.challenge, id("request", index*10+2), csr, secret, f.now)
	if err != nil {
		t.Fatal(err)
	}
	c := f.challenge
	body := map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.ManagerInstanceID, "profile": c.Profile, "origin": c.Origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "requestId": id("request", index*10+2), "challenge": c.Challenge, "invitationSecret": secret, "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))}
	if f.config.AutomaticRenewal {
		body["schemaVersion"] = enrollmentcrypto.RenewableClaimVersion
		body["renewalPolicy"] = c.RenewalPolicy
		body["agentOrigin"] = c.AgentOrigin
	}
	raw, _ := json.Marshal(body)
	claim, err := enrollmentcrypto.VerifyClaim(raw, c, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(index*10 + 2), ClaimID: c.ClaimID}, claim)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(index*10 + 3), DeviceID: id("agent", index), KeyFingerprint: claim.KeyFingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: f.control(index*10 + 4), IntentID: id("intent", index), SerialHex: fmt.Sprintf("%032x", index), TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: f.now.Unix() - 30, NotAfter: f.now.Add(24 * time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := f.store.SigningIntent(ctx, f.snapshot.InvitationID, f.now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	f.cert, err = f.issuer.Sign(ctx, intent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.CommitIssued(ctx, f.control(index*10+5), f.cert)
	if err != nil {
		t.Fatal(err)
	}
	control := f.control(index*10 + 6)
	message, err = enrollmentcrypto.ActivationSigningMessage(c, intent, control.RequestID, f.cert.CertificateHash(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": intent.ManagerInstanceID, "profile": intent.Profile, "origin": intent.Origin, "deviceId": intent.DeviceID, "intentId": intent.IntentID, "certificateHash": f.cert.CertificateHash(), "requestId": control.RequestID, "challenge": c.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	activation, err := enrollmentcrypto.VerifyActivation(raw, f.cert, c, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Activate(ctx, control, activation)
	if err != nil {
		t.Fatal(err)
	}
	f.pair = tls.Certificate{Certificate: [][]byte{f.cert.DER(), f.issuer.IssuerDER()}, PrivateKey: f.key}
	return f
}

func newWindowsSoftwareJobRenewableObserver(t *testing.T) *fixture {
	t.Helper()
	seed := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileWindowsInventory, true)
	copy := *seed
	copy.config.AutomaticRenewal = true
	copy.config.RenewalAgentOrigin = copy.config.Binding.Origin
	copy.path = filepath.Join(t.TempDir(), "private", "renewable.sqlite")
	var err error
	copy.store, err = enrollmentstore.Open(copy.path, copy.config, copy.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { copy.store.Close() })
	return enrollWindowsSoftwareJobObserver(t, &copy, 71)
}

func windowsSoftwareJobRenewalProof(t *testing.T, f *fixture, hash, purpose string, index int) enrollmentcrypto.VerifiedRenewal {
	t.Helper()
	clock := func() time.Time { return f.now }
	c, err := f.store.RenewalContext(context.Background(), f.snapshot.InvitationID, f.snapshot.Claim.ClaimID, hash, purpose, clock)
	if err != nil {
		t.Fatal(err)
	}
	c.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{88}, 32))
	c.ExpiresAt = f.now.Unix() + 60
	message, err := enrollmentcrypto.RenewalSigningMessage(c, id("request", index), f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := enrollmentcrypto.RenewalProofJSON(c, id("request", index), ed25519.Sign(f.key, message))
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := enrollmentcrypto.VerifyRenewal(raw, public, c, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func prepareWindowsSoftwareJobRenewal(t *testing.T, f *fixture) enrollmentcrypto.VerifiedCertificate {
	t.Helper()
	clock := func() time.Time { return f.now }
	ctx := context.Background()
	proof := windowsSoftwareJobRenewalProof(t, f, f.cert.CertificateHash(), enrollmentcrypto.PurposeRenewalIssue, 801)
	intent, revision, err := f.store.BeginRenewal(ctx, proof, id("intent", 801), fmt.Sprintf("%032x", 801), f.now.Unix()-30, f.now.Add(7*24*time.Hour-30*time.Second).Unix(), clock)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := f.issuer.Sign(ctx, intent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CommitRenewal(ctx, proof, revision, candidate, clock); err != nil {
		t.Fatal(err)
	}
	return candidate
}
