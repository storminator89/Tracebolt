package enrollmentstore

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
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

const testNow = int64(1800000000)

func id(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }

type fixture struct {
	requestOffset int
	config        enrollmentstate.Config
	issuerDER     []byte
	issuerKey     ed25519.PrivateKey
	issuerCert    *x509.Certificate
	key           ed25519.PrivateKey
	csr           []byte
	secret        string
	challenge     enrollmentcrypto.ChallengeContext
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	pub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ski := sha256.Sum256(pub)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable in-memory test issuer"}, NotBefore: time.Unix(testNow-3600, 0), NotAfter: time.Unix(testNow+60*86400, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ski[:20]}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	binding := enrollmentstate.Binding{InstanceID: id("manager", 1), Origin: "https://manager.example", Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerFingerprint: hex.EncodeToString(sum[:])}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{config: enrollmentstate.DefaultConfig(binding), issuerDER: der, issuerKey: issuerKey, issuerCert: ca, key: key, csr: csr, secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{32}, 32)), challenge: enrollmentcrypto.ChallengeContext{ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, Origin: binding.Origin, CollectionProfile: binding.CollectionProfile, InvitationID: id("invite", 1), ClaimID: id("claim", 1), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{77}, 32)), ExpiresAt: testNow + 120}}
}
func (f fixture) open(t testing.TB, path string) *Store {
	t.Helper()
	if err := validateIssuer(f.config, f.issuerDER); err != nil {
		t.Fatal("test issuer validation failed")
	}
	s, err := Open(path, f.config, f.issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func fixtureStore(t testing.TB) (fixture, *Store, string) {
	t.Helper()
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "private", "enrollment.sqlite")
	return f, f.open(t, path), path
}
func (f fixture) createCommand() enrollmentstate.CreateCommand {
	h, _ := enrollmentcrypto.InvitationHash(f.secret)
	return enrollmentstate.CreateCommand{InvitationID: f.challenge.InvitationID, RequestID: f.request(1), InvitationHash: hex.EncodeToString(h[:]), Platform: "linux", Now: testNow}
}
func (f fixture) claim(t testing.TB) enrollmentcrypto.VerifiedClaim {
	t.Helper()
	c := f.challenge
	request := f.request(2)
	message, err := enrollmentcrypto.ClaimSigningMessage(c, request, f.csr, f.secret, time.Unix(testNow+1, 0))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.ManagerInstanceID, "profile": c.Profile, "origin": c.Origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "requestId": request, "challenge": c.Challenge, "invitationSecret": f.secret, "csr": base64.RawStdEncoding.EncodeToString(f.csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	proof, err := enrollmentcrypto.VerifyClaim(body, c, time.Unix(testNow+1, 0))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func control(s enrollmentstate.Snapshot, n int) enrollmentstate.Control {
	return enrollmentstate.Control{InvitationID: s.InvitationID, RequestID: id("request", n), ExpectedRevision: s.Revision, Now: s.UpdatedAt + 1}
}
func (f fixture) toIntent(t testing.TB, s *Store) (enrollmentstate.Snapshot, enrollmentcrypto.Intent) {
	t.Helper()
	ctx := context.Background()
	snapshot, err := s.CreateInvitation(ctx, f.createCommand())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(snapshot, 2), ClaimID: f.challenge.ClaimID}, f.claim(t))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(snapshot, 3), DeviceID: id("agent", f.requestOffset+1), KeyFingerprint: snapshot.Claim.KeyFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	c := enrollmentstate.IntentCommand{Control: f.control(snapshot, 4), IntentID: id("intent", f.requestOffset+1), SerialHex: fmt.Sprintf("%032x", f.requestOffset+1), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 86400}
	snapshot, err = s.BeginIssuance(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	i, err := s.SigningIntent(ctx, snapshot.InvitationID, snapshot.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, i
}
func (f fixture) issue(t testing.TB, i enrollmentcrypto.Intent) enrollmentcrypto.VerifiedCertificate {
	t.Helper()
	keyDER, err := base64.RawStdEncoding.DecodeString(i.PublicKeyDERBase64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := new(big.Int).SetString(i.SerialHex, 16)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: i.DeviceID}, NotBefore: time.Unix(i.NotBefore, 0), NotAfter: time.Unix(i.NotAfter, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, f.issuerCert, pub, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := enrollmentcrypto.VerifyIssued(der, f.issuerDER, i, time.Unix(testNow+4, 0))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func (f fixture) activation(t testing.TB, cert enrollmentcrypto.VerifiedCertificate, c enrollmentstate.Control) enrollmentcrypto.VerifiedActivation {
	t.Helper()
	challenge := f.challenge
	challenge.ExpiresAt = c.Now + 120
	i := cert.Intent()
	message, err := enrollmentcrypto.ActivationSigningMessage(challenge, i, c.RequestID, cert.CertificateHash(), time.Unix(c.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": i.ManagerInstanceID, "profile": i.Profile, "origin": i.Origin, "deviceId": i.DeviceID, "intentId": i.IntentID, "certificateHash": cert.CertificateHash(), "requestId": c.RequestID, "challenge": challenge.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	proof, err := enrollmentcrypto.VerifyActivation(body, cert, challenge, time.Unix(c.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func (f fixture) status(t testing.TB, purpose, request string, now int64) enrollmentcrypto.VerifiedStatus {
	t.Helper()
	key, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	c := f.challenge
	c.ExpiresAt = now + 120
	message, err := enrollmentcrypto.StatusSigningMessage(c, purpose, request, key, time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(key)
	raw, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.StatusVersion, "managerInstanceId": c.ManagerInstanceID, "profile": c.Profile, "origin": c.Origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "keyFingerprint": hex.EncodeToString(sum[:]), "requestId": request, "purpose": purpose, "challenge": c.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	proof, err := enrollmentcrypto.VerifyStatus(raw, key, c, time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func (f fixture) request(n int) string { return id("request", f.requestOffset+n) }
func (f fixture) control(s enrollmentstate.Snapshot, n int) enrollmentstate.Control {
	c := control(s, n)
	c.RequestID = f.request(n)
	return c
}
