package enrollmentservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
)

func activatedRenewalFixture(t *testing.T, platform ...string) (*fixture, enrollmentstate.Snapshot, ed25519.PrivateKey) {
	t.Helper()
	f := newFixture(t, "tls", true)
	ctx := context.Background()
	os := "linux"
	if len(platform) == 1 {
		os = platform[0]
	}
	pending, key := claimForPlatform(t, f, os)
	_, e := f.service.Approve(ctx, pending.InvitationID, id("request", 4), pending.Claim.KeyFingerprint, pending.Revision)
	if e != nil {
		t.Fatal(e)
	}
	c, b := status(t, f, pending.InvitationID, pending.Claim.ClaimID, "status", 5, key)
	_, e = f.service.Status(ctx, c.Context.Challenge, b)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := f.store.CertificateForVerification(ctx, pending.InvitationID)
	if e != nil {
		t.Fatal(e)
	}
	c = challenge(t, f, pending.InvitationID, pending.Claim.ClaimID, "activation")
	m, e := enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), id("request", 7), cert.CertificateHash(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ = json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": cert.Intent().DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": id("request", 7), "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, m))})
	active, e := f.service.Activate(ctx, c.Context.Challenge, b)
	if e != nil {
		t.Fatal(e)
	}
	return f, active, key
}
func renewalProof(t *testing.T, f *fixture, active enrollmentstate.Snapshot, key ed25519.PrivateKey, hash, purpose string, n int) (RenewalChallenge, []byte) {
	t.Helper()
	c, e := f.service.RenewalChallenge(context.Background(), "127.0.0.1", active.InvitationID, active.Claim.ClaimID, hash, purpose)
	if e != nil {
		t.Fatal(e)
	}
	m, e := enrollmentcrypto.RenewalSigningMessage(c.Context, id("request", n), f.now)
	if e != nil {
		t.Fatal(e)
	}
	b, e := enrollmentcrypto.RenewalProofJSON(c.Context, id("request", n), ed25519.Sign(key, m))
	if e != nil {
		t.Fatal(e)
	}
	return c, b
}
func TestRenewalSameKeyExactRetryActivationRetirementAndRestart(t *testing.T) {
	f, active, key := activatedRenewalFixture(t)
	ctx := context.Background()
	anchor, e := f.store.CertificateForVerification(ctx, active.InvitationID)
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < MaxRecords-1; n++ {
		if _, err := f.service.CreateInvitation(ctx, id("request", 1000+n), "linux"); err != nil {
			t.Fatal(err)
		}
	}
	f.now = time.Unix(active.Intent.NotAfter, 0).Add(-47 * time.Hour)
	c, b := renewalProof(t, f, active, key, anchor.CertificateHash(), enrollmentcrypto.PurposeRenewalIssue, 100)
	issued, e := f.service.Renew(ctx, c.Context.Challenge, b)
	if e != nil || issued.Candidate == nil {
		t.Fatalf("issue: %v", e)
	}
	if issued.CredentialGeneration != 1 || issued.Candidate.CredentialGeneration != 2 || issued.Candidate.Intent.KeyGeneration != 1 || issued.Candidate.Intent.KeyFingerprint != anchor.Intent().KeyFingerprint {
		t.Fatal("identity changed")
	}
	if issued.Candidate.Intent.NotAfter-issued.Candidate.Intent.NotBefore != enrollmentcrypto.RenewalLifetimeSeconds {
		t.Fatal("renewal lifetime")
	}
	candidateDER, _ := base64.RawStdEncoding.DecodeString(issued.Candidate.CertificateDER)
	if _, e = f.store.AuthorizeCertificate(ctx, candidateDER, f.now); e == nil {
		t.Fatal("candidate authorized telemetry")
	}
	f.restart(t)
	c, b = renewalProof(t, f, active, key, anchor.CertificateHash(), enrollmentcrypto.PurposeRenewalIssue, 100)
	retry, e := f.service.Renew(ctx, c.Context.Challenge, b)
	if e != nil || retry.Candidate == nil || *retry.Candidate != *issued.Candidate {
		t.Fatal("exact issuance retry changed", e)
	}
	c, b = renewalProof(t, f, active, key, issued.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 101)
	activated, e := f.service.ActivateRenewal(ctx, c.Context.Challenge, b)
	if e != nil || activated.CredentialGeneration != 2 || activated.Candidate != nil {
		t.Fatal("activation", e)
	}
	if _, e = f.store.AuthorizeCertificate(ctx, anchor.DER(), f.now); e == nil {
		t.Fatal("retired predecessor authorized")
	}
	if got, e := f.store.AuthorizeCertificate(ctx, candidateDER, f.now); e != nil || got != active {
		t.Fatal("new leaf did not map to unchanged anchor", e)
	}
	f.now = time.Unix(active.Intent.NotAfter+1, 0)
	f.restart(t)
	c, b = renewalProof(t, f, active, key, activated.Current.CertificateHash, enrollmentcrypto.PurposeRenewalStatus, 102)
	reconciled, e := f.service.RenewalStatus(ctx, c.Context.Challenge, b)
	if e != nil || reconciled.CredentialGeneration != 2 {
		t.Fatal("lost activation did not reconcile after old expiry", e)
	}
	original, e := f.store.CertificateForVerification(ctx, active.InvitationID)
	if e != nil || !bytes.Equal(original.DER(), anchor.DER()) || original.Intent() != anchor.Intent() {
		t.Fatal("anchor mutated", e)
	}
	_, e = f.service.Terminate(ctx, active.InvitationID, id("request", 103), active.Revision, enrollmentstate.Revoked)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.AuthorizeCertificate(ctx, candidateDER, f.now); e == nil {
		t.Fatal("revoked renewed leaf authorized")
	}
	c, b = renewalProof(t, f, active, key, activated.Current.CertificateHash, enrollmentcrypto.PurposeRenewalStatus, 104)
	revoked, e := f.service.RenewalStatus(ctx, c.Context.Challenge, b)
	if e != nil || revoked.Status != "revoked" {
		t.Fatal("terminal status", e)
	}
}
func TestRenewalBlocksBeforeWindowWrongPurposeAndExpiredPredecessor(t *testing.T) {
	f, active, key := activatedRenewalFixture(t)
	ctx := context.Background()
	c, b := renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalIssue, 110)
	if _, e := f.service.Renew(ctx, c.Context.Challenge, b); e == nil {
		t.Fatal("issued before renewal window")
	}
	f.now = time.Unix(active.Intent.NotAfter, 0).Add(-time.Hour)
	c, b = renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalStatus, 111)
	if _, e := f.service.Renew(ctx, c.Context.Challenge, b); e == nil {
		t.Fatal("cross-purpose proof accepted")
	}
	c, b = renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalIssue, 112)
	v, e := f.service.Renew(ctx, c.Context.Challenge, b)
	if e != nil {
		t.Fatal(e)
	}
	f.now = time.Unix(active.Intent.NotAfter, 0)
	c, b = renewalProof(t, f, active, key, v.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 113)
	if _, e = f.service.ActivateRenewal(ctx, c.Context.Challenge, b); e == nil {
		t.Fatal("expired predecessor activated successor")
	}
}
func TestRenewalDisableKeepsCurrentCredentialAndStatus(t *testing.T) {
	f, active, key := activatedRenewalFixture(t)
	ctx := context.Background()
	v, e := f.service.DisableRenewal(ctx, active.InvitationID, id("request", 120), active.Revision)
	if e != nil || v.Enabled || v.Status != "blocked" {
		t.Fatal("disable", e)
	}
	cert, e := f.store.CertificateForVerification(ctx, active.InvitationID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.AuthorizeCertificate(ctx, cert.DER(), f.now); e != nil {
		t.Fatal("disable revoked active credential", e)
	}
	f.now = time.Unix(active.Intent.NotAfter, 0).Add(-time.Hour)
	c, b := renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalIssue, 121)
	if _, e = f.service.Renew(ctx, c.Context.Challenge, b); e == nil {
		t.Fatal("disabled issued successor")
	}
}

func TestRenewalWindowsTelemetryBeyondAnchorExpiryPreservesReplay(t *testing.T) {
	f, active, key := activatedRenewalFixture(t, "windows")
	ctx := context.Background()
	f.now = time.Unix(active.Intent.NotAfter, 0).Add(-time.Hour)
	c, b := renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalIssue, 150)
	issued, e := f.service.Renew(ctx, c.Context.Challenge, b)
	if e != nil {
		t.Fatal(e)
	}
	c, b = renewalProof(t, f, active, key, issued.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 151)
	activated, e := f.service.ActivateRenewal(ctx, c.Context.Challenge, b)
	if e != nil {
		t.Fatal(e)
	}
	f.now = time.Unix(active.Intent.NotAfter+10, 0)
	der, e := base64.RawStdEncoding.DecodeString(activated.Current.CertificateDER)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := enrollmentcrypto.VerifyIssued(der, f.service.IssuerDER(), activated.Current.Intent, f.now)
	if e != nil {
		t.Fatal(e)
	}
	assertWindowsBasicTelemetry(t, f, active, cert)
	devices, e := f.service.Devices(ctx, f.now)
	if e != nil || len(devices) != 1 || devices[0].AgentCertificate.Renewal == nil || devices[0].AgentCertificate.Renewal.CredentialGeneration != 2 || devices[0].AgentCertificate.ExpiresAt.Unix() != activated.Current.Intent.NotAfter {
		t.Fatal("renewal current expiry projection", e)
	}
}

type afterRenewalSigner struct {
	Signer
	after func()
}

func (s afterRenewalSigner) Sign(ctx context.Context, i enrollmentcrypto.Intent, now time.Time) (enrollmentcrypto.VerifiedCertificate, error) {
	c, e := s.Signer.Sign(ctx, i, now)
	if s.after != nil {
		s.after()
	}
	return c, e
}
func TestRenewalSignerWaitCannotCrossPredecessorExpiryOrRevocation(t *testing.T) {
	for _, mode := range []string{"expiry", "revocation"} {
		t.Run(mode, func(t *testing.T) {
			f, active, key := activatedRenewalFixture(t)
			ctx := context.Background()
			f.now = time.Unix(active.Intent.NotAfter-10, 0)
			f.service.signer = afterRenewalSigner{Signer: f.issuer, after: func() {
				if mode == "expiry" {
					f.now = time.Unix(active.Intent.NotAfter, 0)
				} else {
					if _, e := f.service.Terminate(ctx, active.InvitationID, id("request", 160), active.Revision, enrollmentstate.Revoked); e != nil {
						t.Fatal(e)
					}
				}
			}}
			c, b := renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalIssue, 161)
			if _, e := f.service.Renew(ctx, c.Context.Challenge, b); e == nil {
				t.Fatal("signer wait crossed authority without rejection")
			}
			c, b = renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalStatus, 162)
			v, e := f.service.RenewalStatus(ctx, c.Context.Challenge, b)
			if e != nil || v.CredentialGeneration != 1 || v.Candidate != nil {
				t.Fatal("failed signer commit published candidate", e)
			}
		})
	}
}
func TestRenewalFinalActivationClockCannotCrossPredecessorExpiry(t *testing.T) {
	f, active, key := activatedRenewalFixture(t)
	ctx := context.Background()
	f.now = time.Unix(active.Intent.NotAfter-10, 0)
	c, b := renewalProof(t, f, active, key, active.Issuance.CertificateHash, enrollmentcrypto.PurposeRenewalIssue, 170)
	issued, e := f.service.Renew(ctx, c.Context.Challenge, b)
	if e != nil {
		t.Fatal(e)
	}
	c, b = renewalProof(t, f, active, key, issued.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 171)
	proof, e := f.service.renewalProof(ctx, c.Context.Challenge, enrollmentcrypto.PurposeRenewalActivate, b)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	clock := func() time.Time {
		calls++
		if calls >= 5 {
			return time.Unix(active.Intent.NotAfter, 0)
		}
		return f.now
	}
	if _, e = f.store.ActivateRenewal(ctx, proof, clock); e == nil || calls < 5 {
		t.Fatalf("final activation clock not enforced: calls %d, error %v", calls, e)
	}
	if _, e = f.store.AuthorizeCertificate(ctx, mustRenewalDER(t, issued.Current.CertificateDER), f.now); e != nil {
		t.Fatal("rolled-back activation retired predecessor", e)
	}
}
func mustRenewalDER(t *testing.T, v string) []byte {
	t.Helper()
	b, e := base64.RawStdEncoding.DecodeString(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestRenewalPolicyCannotAdoptExistingOrSignedHTTPIdentity(t *testing.T) {
	f := newFixture(t, "tls")
	f.store.Close()
	changed := f.config
	changed.AutomaticRenewal = true
	changed.RenewalAgentOrigin = "https://agent.test"
	if adopted, e := enrollmentstore.Open(f.path, changed, f.issuer.IssuerDER()); e == nil {
		adopted.Close()
		t.Fatal("existing configuration adopted renewal")
	}
	f.restart(t)
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			legacy := newFixture(t, profile)
			if _, e := legacy.service.Challenge("127.0.0.1", id("invite", 200), id("claim", 201), enrollmentcrypto.PurposeRenewalIssue); !errors.Is(e, enrollmentstate.ErrNotImplemented) {
				t.Fatal("legacy renewal did not fail explicitly", e)
			}
		})
	}
}

func TestRenewalDurableInitialIntentCannotExceedSevenDays(t *testing.T) {
	f := newFixture(t, "tls", true)
	ctx := context.Background()
	pending, _ := claim(t, f)
	approved, e := f.service.Approve(ctx, pending.InvitationID, id("request", 210), pending.Claim.KeyFingerprint, pending.Revision)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.store.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: enrollmentstate.Control{InvitationID: approved.InvitationID, RequestID: id("request", 211), ExpectedRevision: approved.Revision, Now: f.now.Unix()}, IntentID: id("intent", 212), SerialHex: strings.Repeat("1", 32), TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: f.now.Unix(), NotAfter: f.now.Unix() + enrollmentcrypto.RenewalLifetimeSeconds + 1})
	if !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("durable fresh intent exceeded policy TTL", e)
	}
	after, e := f.store.Get(ctx, approved.InvitationID)
	if e != nil || after != approved {
		t.Fatal("rejected oversized intent mutated identity", e)
	}
}
