package windowscustomerflow

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
)

type pendingFixture struct {
	now           time.Time
	profile       []byte
	profileDigest string
	proof         customerclaim.Verified
	key           []byte
	deadline      int64
	consent       Consent
}

func pendingBindingFixture(t *testing.T) pendingFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ip, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, root, ip, rk)
	if err != nil {
		t.Fatal(err)
	}
	pemOf := func(b []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})) }
	profile := enrollmentclient.CustomerProfile{SchemaVersion: enrollmentclient.CustomerProfileVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Profile: "tls", EnrollmentOrigin: "https://manager.example.test:8443", AgentOrigin: "https://agent.example.test:8444", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, ServerCAPEM: pemOf(rootDER), IssuerRootPEM: pemOf(rootDER), IssuerPEM: pemOf(issuerDER)}
	profileRaw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profileHash := sha256.Sum256(profileRaw)
	issuerHash := sha256.Sum256(issuerDER)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	c := customerclaim.Context{ManagerID: profile.ManagerInstanceID, CustomerID: profile.CustomerID, InstallerProfileID: profile.InstallerProfileID, Origin: profile.EnrollmentOrigin, AgentOrigin: profile.AgentOrigin, IssuerFingerprint: hex.EncodeToString(issuerHash[:]), ClaimID: "claim_" + strings.Repeat("4", 32), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ExpiresAt: now.Unix() + 60}
	req := "request_" + strings.Repeat("5", 32)
	msg, err := customerclaim.SigningMessage(c, req, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(c, req, csr, ed25519.Sign(key, msg), now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := customerclaim.Verify(raw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	_, evidence, _ := fixture(t)
	return pendingFixture{now, profileRaw, hex.EncodeToString(profileHash[:]), proof, proof.PublicKeyDER(), now.Add(customerpending.PendingLifetime).Unix(), evidence.Consent}
}

func (f pendingFixture) candidate() (State, error) {
	return PendingCandidate(f.profile, f.profileDigest, f.proof, f.key, f.deadline, strings.Repeat("e", 64), strings.Repeat("f", 64), f.consent, f.now)
}

func TestPendingCandidateJoinsOriginalPublicInputs(t *testing.T) {
	f := pendingBindingFixture(t)
	s, err := f.candidate()
	if err != nil {
		t.Fatal(err)
	}
	m := f.proof.Metadata()
	if s.Phase != Pending || s.Binding.ClaimID != m.ClaimID || s.Binding.ClaimHash != m.ClaimHash || s.Binding.KeyFingerprint != m.KeyFingerprint || s.Binding.ProfileDigest != f.profileDigest || s.Binding.DeadlineAt != f.deadline {
		t.Fatal("original binding changed")
	}
	// The old short-lived challenge need not be refreshed just because the
	// confirmed pending response arrived after its expiry.
	late := f
	late.now = f.now.Add(time.Minute)
	if _, err = late.candidate(); err != nil {
		t.Fatal("confirmed pending candidate lost when challenge expired", err)
	}
	st := &fakeReceiptStore{schemaOK: true}
	j, err := attach(st)
	if err != nil {
		t.Fatal(err)
	}
	stored, _, err := j.Initialize(s.Binding, s.Consent, fixedClock(f.now), &fixtureGuard{})
	if err != nil || stored.Phase != Pending {
		t.Fatal("fixture receipt rejected", err)
	}
	// The receipt backend and guard are deliberately synthetic, not proof of
	// Windows ACLs, key protection, restart reconciliation or host authority.
}

func TestPendingCandidateRejectsUnboundInputsAndConsent(t *testing.T) {
	base := pendingBindingFixture(t)
	for name, mutate := range map[string]func(*pendingFixture){
		"zero proof": func(f *pendingFixture) { f.proof = customerclaim.Verified{} },
		"other key": func(f *pendingFixture) {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			f.key, _ = x509.MarshalPKIXPublicKey(k.Public())
		},
		"bad profile digest":   func(f *pendingFixture) { f.profileDigest = strings.Repeat("a", 64) },
		"profile bytes":        func(f *pendingFixture) { f.profile = append(bytes.Clone(f.profile), ' ') },
		"expired":              func(f *pendingFixture) { f.deadline = f.now.Unix() },
		"future deadline":      func(f *pendingFixture) { f.deadline = f.now.Add(customerpending.PendingLifetime + time.Second).Unix() },
		"no scope consent":     func(f *pendingFixture) { f.consent.Scopes.Acknowledged = false },
		"no finalizer consent": func(f *pendingFixture) { f.consent.AutomaticFinalizerAcknowledged = false },
		"v2 schema": func(f *pendingFixture) {
			f.profile = bytes.Replace(f.profile, []byte(enrollmentclient.CustomerProfileVersion), []byte("tracebolt.enrollment-bootstrap.v2"), 1)
			h := sha256.Sum256(f.profile)
			f.profileDigest = hex.EncodeToString(h[:])
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := base
			f.consent.Scopes.Scopes = append([]string(nil), base.consent.Scopes.Scopes...)
			mutate(&f)
			if _, err := f.candidate(); err == nil {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
	if _, err := PendingCandidate(base.profile, base.profileDigest, base.proof, base.key, base.deadline, "bad", strings.Repeat("f", 64), base.consent, base.now); err == nil {
		t.Fatal("invalid executable digest accepted")
	}
}

func TestPendingCandidateRejectsValidButDifferentProfile(t *testing.T) {
	f := pendingBindingFixture(t)
	for _, field := range []string{"ManagerInstanceID", "CustomerID", "InstallerProfileID", "EnrollmentOrigin", "AgentOrigin", "IssuerPEM"} {
		t.Run(field, func(t *testing.T) {
			var p enrollmentclient.CustomerProfile
			if err := json.Unmarshal(f.profile, &p); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "ManagerInstanceID":
				p.ManagerInstanceID = "manager_" + strings.Repeat("a", 32)
			case "CustomerID":
				p.CustomerID = "customer_" + strings.Repeat("a", 32)
			case "InstallerProfileID":
				p.InstallerProfileID = "profile_" + strings.Repeat("a", 32)
			case "EnrollmentOrigin":
				p.EnrollmentOrigin = "https://other.example.test:8443"
			case "AgentOrigin":
				p.AgentOrigin = "https://other.example.test:8444"
			case "IssuerPEM":
				p.IssuerPEM = p.IssuerRootPEM
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(raw)
			v := f
			v.profile = raw
			v.profileDigest = hex.EncodeToString(h[:])
			if _, err = v.candidate(); err == nil {
				t.Fatal("substituted profile accepted")
			}
		})
	}
}
