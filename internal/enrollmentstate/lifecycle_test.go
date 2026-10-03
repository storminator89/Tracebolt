package enrollmentstate

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
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

// All issuer material is deterministic disposable test-only material. Nothing
// writes a credential, provisions trust, listens on a socket or uses a real CA.
type issuerFixture struct {
	key  ed25519.PrivateKey
	der  []byte
	cert *x509.Certificate
}

func issuer(t *testing.T, n int) issuerFixture {
	t.Helper()
	seed := sha256.Sum256([]byte(id("test-issuer", n)))
	key := ed25519.NewKeyFromSeed(seed[:])
	ski := sha256.Sum256(key.Public().(ed25519.PublicKey))
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(n)), Subject: pkix.Name{CommonName: "Disposable test-only issuer"}, NotBefore: time.Unix(testNow-3600, 0), NotAfter: time.Unix(testNow+60*86400, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ski[:20]}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issuerFixture{key: key, der: der, cert: cert}
}
func (f issuerFixture) fingerprint() string {
	h := sha256.Sum256(f.der)
	return hex.EncodeToString(h[:])
}
func (f issuerFixture) issue(t *testing.T, i enrollmentcrypto.Intent, now int64) enrollmentcrypto.VerifiedCertificate {
	t.Helper()
	raw, err := base64.RawStdEncoding.DecodeString(i.PublicKeyDERBase64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	serial, ok := new(big.Int).SetString(i.SerialHex, 16)
	if !ok {
		t.Fatal("invalid serial")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: i.DeviceID}, NotBefore: time.Unix(i.NotBefore, 0), NotAfter: time.Unix(i.NotAfter, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, f.cert, pub, f.key)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := enrollmentcrypto.VerifyIssued(der, f.der, i, time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func flowIntent(t *testing.T) (*Engine, claimFixture, issuerFixture, Snapshot, enrollmentcrypto.Intent) {
	t.Helper()
	ca := issuer(t, 1)
	b := binding()
	b.IssuerFingerprint = ca.fingerprint()
	e, err := New(DefaultConfig(b))
	if err != nil {
		t.Fatal(err)
	}
	f := newClaimFixture(t, 1)
	s := f.create(t, e)
	s, err = e.Claim(context.Background(), f.command(s, testNow+1), f.proof(t, testNow+1))
	if err != nil {
		t.Fatal(err)
	}
	s, err = e.Approve(context.Background(), ApproveCommand{Control: control(s, 102), DeviceID: id("agent", 1), KeyFingerprint: s.Claim.KeyFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	s, err = e.BeginIssuance(context.Background(), intentCommand(s, 1))
	if err != nil {
		t.Fatal(err)
	}
	i, err := e.SigningIntent(s.InvitationID, s.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	return e, f, ca, s, i
}
func activationProof(t *testing.T, f claimFixture, cert enrollmentcrypto.VerifiedCertificate, request string, now int64) enrollmentcrypto.VerifiedActivation {
	t.Helper()
	c := f.challenge
	c.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32))
	c.ExpiresAt = now + 120
	i := cert.Intent()
	message, err := enrollmentcrypto.ActivationSigningMessage(c, i, request, cert.CertificateHash(), time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": i.ManagerInstanceID, "profile": i.Profile, "origin": i.Origin, "deviceId": i.DeviceID, "intentId": i.IntentID, "certificateHash": cert.CertificateHash(), "requestId": request, "challenge": c.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := enrollmentcrypto.VerifyActivation(body, cert, c, time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestCompleteVerifiedLifecycleExactRetriesAndRevocation(t *testing.T) {
	e, f, ca, s, i := flowIntent(t)
	cert := ca.issue(t, i, s.UpdatedAt+1)
	c := control(s, 104)
	out, err := e.CommitIssued(context.Background(), c, cert)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != Issued || out.Issuance.CertificateHash != cert.CertificateHash() {
		t.Fatal("wrong issuance")
	}
	c.Now++
	retry, err := e.CommitIssued(context.Background(), c, cert)
	if err != nil || retry != out {
		t.Fatalf("issuance retry %v", err)
	}
	c = control(out, 105)
	proof := activationProof(t, f, cert, c.RequestID, c.Now)
	active, err := e.Activate(context.Background(), c, proof)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != Activated || active.Revision != 6 {
		t.Fatal("wrong activation")
	}
	c.Now++
	again, err := e.Activate(context.Background(), c, proof)
	if err != nil || again != active {
		t.Fatalf("activation retry %v", err)
	}
	newProof := activationProof(t, f, cert, c.RequestID, active.DeadlineAt+1)
	c.Now = active.DeadlineAt + 1
	again, err = e.Activate(context.Background(), c, newProof)
	if err != nil || again != active {
		t.Fatalf("active retry after pending window %v", err)
	}
	if _, err := e.CommitIssued(context.Background(), Control{InvitationID: active.InvitationID, RequestID: out.Issuance.RequestID, ExpectedRevision: 4, Now: c.Now}, cert); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	terminalControl := control(active, 190)
	terminalControl.Now = c.Now
	revoked, err := e.Terminate(context.Background(), TerminalCommand{Control: terminalControl, State: Revoked})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(context.Background(), c, newProof); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	unchanged(t, e, revoked)
}

func TestVerifiedCertificateCannotChangeRecordedIntent(t *testing.T) {
	for _, scenario := range []string{"instance", "origin", "profile", "invitation", "claim", "request", "identity", "intent", "key", "csr", "claim hash", "issuer", "serial", "validity"} {
		t.Run(scenario, func(t *testing.T) {
			e, _, ca, s, i := flowIntent(t)
			wrong := i
			switch scenario {
			case "instance":
				wrong.ManagerInstanceID = id("manager", 9)
			case "origin":
				wrong.Origin = "https://other.example"
			case "profile":
				wrong.Profile = "http-test"
				wrong.Origin = "http://manager.example"
			case "invitation":
				wrong.InvitationID = id("invite", 9)
			case "claim":
				wrong.ClaimID = id("claim", 9)
			case "request":
				wrong.RequestID = id("request", 9)
			case "identity":
				wrong.DeviceID = id("agent", 9)
			case "intent":
				wrong.IntentID = id("intent", 9)
			case "key":
				f := newClaimFixture(t, 9)
				p := f.proof(t, testNow+1)
				wrong.KeyFingerprint = p.KeyFingerprint()
				wrong.PublicKeyDERBase64 = base64.RawStdEncoding.EncodeToString(p.PublicKeyDER())
			case "csr":
				wrong.CSRHash = hash(999)
			case "claim hash":
				wrong.ClaimHash = hash(999)
			case "issuer":
				ca = issuer(t, 9)
				wrong.IssuerFingerprint = ca.fingerprint()
			case "serial":
				wrong.SerialHex = "ffffffffffffffffffffffffffffffff"
			case "validity":
				wrong.NotAfter--
			}
			proof := ca.issue(t, wrong, s.UpdatedAt+1)
			if _, err := e.CommitIssued(context.Background(), control(s, 104), proof); !errors.Is(err, ErrProof) {
				t.Fatalf("mismatch accepted: %v", err)
			}
			unchanged(t, e, s)
		})
	}
}

func TestIssueAndActivationCancellationExpiryAndCAS(t *testing.T) {
	e, f, ca, s, i := flowIntent(t)
	cert := ca.issue(t, i, s.UpdatedAt+1)
	c := control(s, 104)
	if _, err := e.CommitIssued(&cancelAtCommit{}, c, cert); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	wrongRevision := c
	wrongRevision.ExpectedRevision--
	if _, err := e.CommitIssued(context.Background(), wrongRevision, cert); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	expired := c
	expired.Now = s.DeadlineAt
	if _, err := e.CommitIssued(context.Background(), expired, cert); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	if _, err := e.SigningIntent(s.InvitationID, s.DeadlineAt); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	s, err := e.CommitIssued(context.Background(), c, cert)
	if err != nil {
		t.Fatal(err)
	}
	c = control(s, 105)
	proof := activationProof(t, f, cert, c.RequestID, c.Now)
	if _, err := e.Activate(&cancelAtCommit{}, c, proof); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	wrongRevision = c
	wrongRevision.ExpectedRevision--
	if _, err := e.Activate(context.Background(), wrongRevision, proof); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	expired = c
	expired.Now = proof.ExpiresAt()
	if _, err := e.Activate(context.Background(), expired, proof); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	wrongRequest := c
	wrongRequest.RequestID = id("request", 999)
	if _, err := e.Activate(context.Background(), wrongRequest, proof); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	wrongIntent := i
	wrongIntent.IntentID = id("intent", 999)
	wrongCert := ca.issue(t, wrongIntent, c.Now)
	wrongProof := activationProof(t, f, wrongCert, c.RequestID, c.Now)
	if _, err := e.Activate(context.Background(), c, wrongProof); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	terminal, err := e.Terminate(context.Background(), TerminalCommand{Control: control(s, 190), State: Canceled})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(context.Background(), c, proof); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	unchanged(t, e, terminal)
}

func TestConcurrentIssuanceAndActivationRetries(t *testing.T) {
	e, f, ca, s, i := flowIntent(t)
	cert := ca.issue(t, i, s.UpdatedAt+1)
	c := control(s, 104)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := e.CommitIssued(context.Background(), c, cert)
			if err != nil || out.Revision != 5 {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatal("concurrent issued retries failed")
	}
	s, _ = e.Get(s.InvitationID)
	c = control(s, 105)
	proof := activationProof(t, f, cert, c.RequestID, c.Now)
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := e.Activate(context.Background(), c, proof)
			if err != nil || out.Revision != 6 {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatal("concurrent activation retries failed")
	}
}
