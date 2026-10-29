package customerv3proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerapprovalstore"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/enrollmentcrypto"
)

func id(prefix, digit string) string { return prefix + "_" + strings.Repeat(digit, 32) }

type fixture struct {
	now  time.Time
	key  ed25519.PrivateKey
	i    customerissuance.Intent
	c    customerclaim.Context
	cert customerissuance.VerifiedCertificate
}

func makeFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	ip, ik, _ := ed25519.GenerateKey(rand.Reader)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("root")}
	rawRoot, e := x509.CreateCertificate(rand.Reader, rootT, rootT, rp, rk)
	if e != nil {
		t.Fatal(e)
	}
	root, _ := x509.ParseCertificate(rawRoot)
	issuerT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(8 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuer")}
	rawIssuer, e := x509.CreateCertificate(rand.Reader, issuerT, root, ip, rk)
	if e != nil {
		t.Fatal(e)
	}
	issuer, _ := x509.ParseCertificate(rawIssuer)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(rawIssuer)
	c := customerclaim.Context{ManagerID: id("manager", "1"), CustomerID: id("customer", "2"), InstallerProfileID: id("profile", "3"), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: hex.EncodeToString(h[:]), ClaimID: id("claim", "4"), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ExpiresAt: now.Unix() + 60}
	msg, e := customerclaim.SigningMessage(c, id("request", "5"), csr, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := customerclaim.Encode(c, id("request", "5"), csr, ed25519.Sign(key, msg), now)
	if e != nil {
		t.Fatal(e)
	}
	verified, e := customerclaim.Verify(raw, c, now)
	if e != nil {
		t.Fatal(e)
	}
	m := verified.Metadata()
	p := customerpending.Record{Version: "tracebolt.customer-pending.v1", ManagerID: m.ManagerID, CustomerID: m.CustomerID, InstallerProfileID: m.InstallerProfileID, Origin: m.Origin, AgentOrigin: m.AgentOrigin, IssuerFingerprint: m.IssuerFingerprint, ClaimID: m.ClaimID, RequestID: m.RequestID, KeyFingerprint: m.KeyFingerprint, CSRHash: m.CSRHash, ClaimHash: m.ClaimHash, ComparisonCode: m.ComparisonCode, PublicKeyDER: verified.PublicKeyDER(), CreatedAt: now.Unix() - 10, DeadlineAt: now.Unix() - 10 + int64(customerpending.PendingLifetime/time.Second)}
	ex := customerpending.ReviewExpectation{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, ClaimHash: p.ClaimHash, KeyFingerprint: p.KeyFingerprint, ManagerDigest: strings.Repeat("b", 64), CustomerRevision: 1, DeadlineAt: p.DeadlineAt}
	a, e := customerapproval.Build(ex, p, customerapproval.Decision{OperationID: id("request", "6"), DeviceID: id("agent", "7"), Acknowledged: true, FingerprintCompared: true}, now)
	if e != nil {
		t.Fatal(e)
	}
	i, e := customerissuance.Build(customerapprovalstore.Record{Version: "tracebolt.customer-approval-record.v1", Actor: customerapprovalstore.Actor{Mode: "shared"}, Candidate: a}, id("intent", "8"), strings.Repeat("9", 32), now, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	serial, _ := new(big.Int).SetString(i.SerialHex, 16)
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: a.DeviceID}, NotBefore: time.Unix(i.NotBefore, 0), NotAfter: time.Unix(i.NotAfter, 0), SignatureAlgorithm: x509.PureEd25519, BasicConstraintsValid: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, AuthorityKeyId: issuer.SubjectKeyId}
	der, e := x509.CreateCertificate(rand.Reader, leaf, issuer, pub, ik)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := customerissuance.VerifyIssued(der, rawIssuer, rawRoot, i, now)
	if e != nil {
		t.Fatal(e)
	}
	return fixture{now, key, i, c, cert}
}

func TestProofPurposesAndFreshness(t *testing.T) {
	f := makeFixture(t)
	req := id("request", "a")
	get, err := SigningMessage(f.i, Credential, f.c, req, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = SigningMessage(f.i, Credential, f.c, req, f.cert.CertificateHash(), f.now); err == nil {
		t.Fatal("credential proof requires no known certificate")
	}
	sig := ed25519.Sign(f.key, get)
	if Verify(f.i, f.cert, Credential, f.c, req, sig, f.now) != nil {
		t.Fatal("credential proof rejected")
	}
	if Verify(f.i, f.cert, Activation, f.c, req, sig, f.now) == nil {
		t.Fatal("credential proof activated")
	}
	activate, err := SigningMessage(f.i, Activation, f.c, req, f.cert.CertificateHash(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(f.i, f.cert, Activation, f.c, req, ed25519.Sign(f.key, activate), f.now) != nil {
		t.Fatal("activation proof rejected")
	}
	otherHashMsg, err := SigningMessage(f.i, Activation, f.c, req, strings.Repeat("f", 64), f.now)
	if err != nil || Verify(f.i, f.cert, Activation, f.c, req, ed25519.Sign(f.key, otherHashMsg), f.now) == nil {
		t.Fatal("different certificate hash accepted")
	}
	if Verify(f.i, f.cert, Credential, f.c, id("request", "b"), sig, f.now) == nil {
		t.Fatal("request substitution accepted")
	}
	c := f.c
	c.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	if Verify(f.i, f.cert, Credential, c, req, sig, f.now) == nil {
		t.Fatal("challenge substitution accepted")
	}
	if Verify(f.i, f.cert, Credential, f.c, req, sig, time.Unix(f.c.ExpiresAt, 0)) == nil {
		t.Fatal("expired challenge accepted")
	}
	if Verify(f.i, f.cert, Credential, f.c, req, sig, f.now) != nil {
		t.Fatal("verifier unexpectedly consumes challenge")
	}
	// Production must use a separate single-use, purpose-aware pool; the
	// signature verifier deliberately cannot prevent reuse of the same input.
}

func TestProofSubstitutionAndMalformedInput(t *testing.T) {
	f := makeFixture(t)
	req := id("request", "a")
	msg, _ := SigningMessage(f.i, Activation, f.c, req, f.cert.CertificateHash(), f.now)
	sig := ed25519.Sign(f.key, msg)
	for name, edit := range map[string]func(*customerclaim.Context){"manager": func(c *customerclaim.Context) { c.ManagerID = id("manager", "a") }, "customer": func(c *customerclaim.Context) { c.CustomerID = id("customer", "a") }, "profile": func(c *customerclaim.Context) { c.InstallerProfileID = id("profile", "a") }, "claim": func(c *customerclaim.Context) { c.ClaimID = id("claim", "a") }, "issuer": func(c *customerclaim.Context) { c.IssuerFingerprint = strings.Repeat("f", 64) }, "challenge": func(c *customerclaim.Context) { c.Challenge = "malformed" }} {
		t.Run(name, func(t *testing.T) {
			c := f.c
			edit(&c)
			if Verify(f.i, f.cert, Activation, c, req, sig, f.now) == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	other := makeFixture(t)
	if Verify(f.i, other.cert, Activation, f.c, req, sig, f.now) == nil {
		t.Fatal("other cert accepted")
	}
	if Verify(f.i, customerissuance.VerifiedCertificate{}, Activation, f.c, req, sig, f.now) == nil {
		t.Fatal("unverified cert accepted")
	}
	i := f.i
	i.IntentID = id("intent", "a")
	if Verify(i, f.cert, Activation, f.c, req, sig, f.now) == nil {
		t.Fatal("changed intent accepted")
	}
	if Verify(f.i, f.cert, Activation, f.c, req, []byte("v2 proof"), f.now) == nil {
		t.Fatal("v2 or malformed proof accepted")
	}
	status, err := customerclaim.StatusSigningMessage(f.c, customerclaim.Metadata{ManagerID: f.c.ManagerID, CustomerID: f.c.CustomerID, InstallerProfileID: f.c.InstallerProfileID, Origin: f.c.Origin, AgentOrigin: f.c.AgentOrigin, IssuerFingerprint: f.c.IssuerFingerprint, ClaimID: f.c.ClaimID, ClaimHash: f.i.Approval.Candidate.Pending.ClaimHash, KeyFingerprint: f.i.Approval.Candidate.Pending.KeyFingerprint, CSRHash: f.i.Approval.Candidate.Pending.CSRHash, RequestID: f.i.Approval.Candidate.Pending.RequestID, ComparisonCode: f.i.Approval.Candidate.Pending.ComparisonCode}, f.i.Approval.Candidate.Pending.PublicKeyDER, req, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(f.i, f.cert, Activation, f.c, req, ed25519.Sign(f.key, status), f.now) == nil {
		t.Fatal("other proof domain accepted")
	}
	v2 := enrollmentcrypto.ChallengeContext{ManagerInstanceID: f.c.ManagerID, Profile: "tls", Origin: f.c.Origin, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, InvitationID: id("invite", "a"), ClaimID: f.c.ClaimID, Challenge: f.c.Challenge, ExpiresAt: f.c.ExpiresAt}
	v2msg, err := enrollmentcrypto.StatusSigningMessage(v2, enrollmentcrypto.PurposeCredential, req, f.i.Approval.Candidate.Pending.PublicKeyDER, f.now)
	if err != nil {
		t.Fatal(err)
	}
	v2sig := ed25519.Sign(f.key, v2msg)
	if Verify(f.i, f.cert, Credential, f.c, req, v2sig, f.now) == nil || Verify(f.i, f.cert, Activation, f.c, req, v2sig, f.now) == nil {
		t.Fatal("v2 credential proof accepted in v3")
	}
}
