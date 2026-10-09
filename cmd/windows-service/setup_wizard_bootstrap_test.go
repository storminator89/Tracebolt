package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/enrollmentclient"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Only ephemeral memory certificates are generated. No listener, enrollment,
// native storage, service, trust store or persistent identity is created.
func setupPublicBootstrapFixture(t *testing.T, profile string) (enrollmentclient.Bootstrap, string) {
	t.Helper()
	now := time.Now().UTC()
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rk)
	ip, ik, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ik)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Setup inert root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("setup-root")}
	rd, err := x509.CreateCertificate(rand.Reader, rt, rt, rp, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rd)
	if err != nil {
		t.Fatal(err)
	}
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Setup inert issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("setup-issuer")}
	id, err := x509.CreateCertificate(rand.Reader, it, root, ip, rk)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := func(d []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})) }
	scheme := "https"
	ca := pemCert(rd)
	if profile == "http-test" {
		scheme = "http"
		ca = ""
	}
	b := enrollmentclient.Bootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: "manager_" + strings.Repeat("a", 32), Profile: profile, EnrollmentOrigin: scheme + "://127.0.0.1:8443", AgentOrigin: scheme + "://127.0.0.1:8444", CollectionProfile: "windows-inventory-v1", InvitationID: "invite_" + strings.Repeat("b", 32), ServerCAPEM: ca, IssuerRootPEM: pemCert(rd), IssuerPEM: pemCert(id)}
	sum := sha256.Sum256(id)
	return b, hex.EncodeToString(sum[:])
}
func TestSetupWizardPublicBootstrapPreviewAndExplicitTransportConsent(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		b, issuerDigest := setupPublicBootstrapFixture(t, profile)
		raw, _ := json.Marshal(b)
		preview, err := setupWizardPreview(raw)
		if err != nil || preview.ManagerID != b.ManagerInstanceID || preview.EnrollmentOrigin != b.EnrollmentOrigin || preview.AgentOrigin != b.AgentOrigin || preview.HTTPTest != (profile == "http-test") || preview.Fingerprints[len(preview.Fingerprints)-1] != issuerDigest {
			t.Fatal("valid public preview failed")
		}
		for _, ack := range []bool{false, true} {
			_, consent, err := setupWizardAcknowledgedBootstrap(raw, ack)
			allowed := ack == (profile == "http-test")
			if (err == nil) != allowed {
				t.Fatal("transport acknowledgement widened")
			}
			if allowed && (consent.InsecureHTTPAcknowledged != ack || validateReadSetupConsent(consent) != nil) {
				t.Fatal("coordinator consent changed")
			}
		}
		b.CollectionProfile = "basic-readonly-v1"
		other, _ := json.Marshal(b)
		if _, err := setupWizardPreview(other); err == nil {
			t.Fatal("wrong scope admitted")
		}
		injected := strings.TrimSuffix(string(raw), "}") + `,"invitationSecret":"inert-not-an-invitation"}`
		if _, err := setupWizardPreview([]byte(injected)); err == nil {
			t.Fatal("secret field admitted")
		}
	}
}
