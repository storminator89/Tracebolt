package enrollmentservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func id(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }

type fixture struct {
	service *Service
	store   *enrollmentstore.Store
	issuer  *enrollmentissuer.Issuer
	now     time.Time
	path    string
	config  enrollmentstate.Config
}

func newFixture(t *testing.T, profile string) *fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	ip, ik, _ := ed25519.GenerateKey(rand.Reader)
	rh := sha256.Sum256(rp)
	ih := sha256.Sum256(ip)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		t.Fatal("root fixture")
	}
	root, _ = x509.ParseCertificate(rd)
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable enrollment issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	der, e := x509.CreateCertificate(rand.Reader, intermediate, root, ip, rk)
	if e != nil {
		t.Fatal("issuer fixture")
	}
	fp := sha256.Sum256(der)
	issuer, e := enrollmentissuer.New(der, rd, ik, hex.EncodeToString(fp[:]), now)
	if e != nil {
		t.Fatal("issuer rejected", e)
	}
	origin := "https://manager.test"
	if profile == "http-test" {
		origin = "http://127.0.0.1:8443"
	}
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: id("manager", 1), Profile: profile, Origin: origin, CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit = MaxRecords
	cfg.InvitationLimit = MaxRecords
	cfg.PendingLimit = MaxRecords
	f := &fixture{now: now, issuer: issuer, config: cfg, path: filepath.Join(t.TempDir(), "private", "enrollment.db")}
	f.store, e = enrollmentstore.Open(f.path, cfg, issuer.IssuerDER())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.store.Close() })
	f.service, e = New(f.store, issuer, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) restart(t *testing.T) {
	t.Helper()
	f.store.Close()
	var e error
	f.store, e = enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
	if e != nil {
		t.Fatal(e)
	}
	f.service, e = New(f.store, f.issuer, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
}
func challenge(t *testing.T, f *fixture, invite, claim, purpose string) Challenge {
	t.Helper()
	c, e := f.service.Challenge("127.0.0.1", invite, claim, purpose)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func status(t *testing.T, f *fixture, invite, claim, purpose string, n int, key ed25519.PrivateKey) (Challenge, []byte) {
	t.Helper()
	c := challenge(t, f, invite, claim, purpose)
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	sum := sha256.Sum256(der)
	msg, e := enrollmentcrypto.StatusSigningMessage(c.Context, purpose, id("request", n), der, f.now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.StatusVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": invite, "claimId": claim, "keyFingerprint": hex.EncodeToString(sum[:]), "requestId": id("request", n), "purpose": purpose, "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, msg))})
	return c, b
}
func claim(t *testing.T, f *fixture) (enrollmentstate.Snapshot, ed25519.PrivateKey) {
	t.Helper()
	return claimForPlatform(t, f, "linux")
}
func claimForPlatform(t *testing.T, f *fixture, platform string) (enrollmentstate.Snapshot, ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	created, e := f.service.CreateInvitation(ctx, id("request", 1), platform)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []any{created, &created} {
		b, _ := json.Marshal(v)
		if bytes.Contains(b, []byte(created.Secret())) {
			t.Fatal("secret serialization")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%p", "%d", "%f"} {
			if strings.Contains(fmt.Sprintf(format, v), created.Secret()) {
				t.Fatal("secret formatting")
			}
		}
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored client name"}}, key)
	c := challenge(t, f, created.Snapshot().InvitationID, id("claim", 2), "claim")
	m, e := enrollmentcrypto.ClaimSigningMessage(c.Context, id("request", 2), csr, created.Secret(), f.now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": c.Context.InvitationID, "claimId": c.Context.ClaimID, "requestId": id("request", 2), "challenge": c.Context.Challenge, "invitationSecret": created.Secret(), "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, m))})
	pending, e := f.service.Claim(ctx, c.Context.Challenge, b)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Claim(ctx, c.Context.Challenge, b); !errors.Is(e, ErrChallenge) {
		t.Fatal("one-use challenge reused")
	}
	return pending, key
}
func TestDurableServiceApprovalIssuanceDeliveryActivation(t *testing.T) {
	for _, tc := range []struct{ platform, profile string }{{"linux", "tls"}, {"linux", "http-test"}, {"windows", "tls"}} {
		t.Run(tc.platform+"/"+tc.profile, func(t *testing.T) {
			f := newFixture(t, tc.profile)
			ctx := context.Background()
			pending, key := claimForPlatform(t, f, tc.platform)
			c, b := status(t, f, pending.InvitationID, pending.Claim.ClaimID, "credential", 3, key)
			if _, e := f.service.Credential(ctx, c.Context.Challenge, b); e == nil {
				t.Fatal("credential before approval")
			}
			approved, e := f.service.Approve(ctx, pending.InvitationID, id("request", 4), pending.Claim.KeyFingerprint, pending.Revision)
			if e != nil || approved.State != enrollmentstate.Approved {
				t.Fatal("approval failed", e)
			}
			f.restart(t)
			c, b = status(t, f, pending.InvitationID, pending.Claim.ClaimID, "status", 5, key)
			issued, e := f.service.Status(ctx, c.Context.Challenge, b)
			if e != nil || issued.State != enrollmentstate.Issued {
				t.Fatal("issuance failed", e)
			}
			c, b = status(t, f, pending.InvitationID, pending.Claim.ClaimID, "credential", 6, key)
			der, e := f.service.Credential(ctx, c.Context.Challenge, b)
			if e != nil {
				t.Fatal("delivery failed", e)
			}
			f.restart(t)
			c, b = status(t, f, pending.InvitationID, pending.Claim.ClaimID, "credential", 6, key)
			retry, e := f.service.Credential(ctx, c.Context.Challenge, b)
			if e != nil || !bytes.Equal(der, retry) {
				t.Fatal("exact credential retry changed")
			}
			cert, e := f.store.CertificateForVerification(ctx, pending.InvitationID)
			if e != nil {
				t.Fatal(e)
			}
			c = challenge(t, f, pending.InvitationID, pending.Claim.ClaimID, "activation")
			msg, e := enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), id("request", 7), cert.CertificateHash(), f.now)
			if e != nil {
				t.Fatal(e)
			}
			b, _ = json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": approved.Approval.DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": id("request", 7), "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, msg))})
			active, e := f.service.Activate(ctx, c.Context.Challenge, b)
			if e != nil || active.State != enrollmentstate.Activated {
				t.Fatal("activation failed", e)
			}
			if tc.platform == "windows" {
				assertWindowsBasicTelemetry(t, f, active, cert)
			}
			revoked, e := f.service.Terminate(ctx, pending.InvitationID, id("request", 8), active.Revision, enrollmentstate.Revoked)
			if e != nil {
				t.Fatal(e)
			}
			c, b = status(t, f, pending.InvitationID, pending.Claim.ClaimID, "credential", 9, key)
			if _, e = f.service.Credential(ctx, c.Context.Challenge, b); e == nil {
				t.Fatal("credential after revocation")
			}
			c, b = status(t, f, pending.InvitationID, pending.Claim.ClaimID, "status", 10, key)
			view, e := f.service.Status(ctx, c.Context.Challenge, b)
			if e != nil || view.State != revoked.State {
				t.Fatal("terminal status unavailable", e)
			}
		})
	}
}
func TestChallengeLimitsExpiryAndConfiguration(t *testing.T) {
	f := newFixture(t, "tls")
	for n := 0; n < 30; n++ {
		if _, e := f.service.Challenge("127.0.0.1", id("invite", 1), id("claim", 1), "claim"); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.service.Challenge("127.0.0.1", id("invite", 1), id("claim", 1), "claim"); !errors.Is(e, ErrBusy) {
		t.Fatal("peer limit")
	}
	f.now = f.now.Add(time.Minute)
	c := challenge(t, f, id("invite", 1), id("claim", 1), "status")
	if _, e := f.service.takeChallenge(c.Context.Challenge, "credential"); !errors.Is(e, ErrChallenge) {
		t.Fatal("cross-purpose challenge")
	}
	c = challenge(t, f, id("invite", 1), id("claim", 1), "status")
	f.now = f.now.Add(time.Minute)
	if _, e := f.service.takeChallenge(c.Context.Challenge, "status"); !errors.Is(e, ErrChallenge) {
		t.Fatal("expired challenge")
	}
	if _, e := f.service.CreateInvitation(context.Background(), id("request", 1), "darwin"); !errors.Is(e, ErrPlatform) {
		t.Fatal("unimplemented platform accepted")
	}
	cfg := f.config
	cfg.RecordLimit = 26
	other, e := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "wide.db"), cfg, f.issuer.IssuerDER())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = New(other, f.issuer, nil); !errors.Is(e, ErrConfiguration) {
		t.Fatal("oversized exposed runtime accepted")
	}
}
