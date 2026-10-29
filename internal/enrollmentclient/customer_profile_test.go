package enrollmentclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

func customerProfileFixture(t *testing.T, now time.Time) CustomerProfile {
	t.Helper()
	rpub, rkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ipub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("fixture-root")}
	rawRoot, err := x509.CreateCertificate(rand.Reader, root, root, rpub, rkey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("fixture-issuer")}
	rawIssuer, err := x509.CreateCertificate(rand.Reader, issuer, root, ipub, rkey)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := func(raw []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	return CustomerProfile{SchemaVersion: CustomerProfileVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Profile: "tls", EnrollmentOrigin: "https://manager.example.test:8443", AgentOrigin: "https://agent.example.test:8444", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, ServerCAPEM: pemCert(rawRoot), IssuerRootPEM: pemCert(rawRoot), IssuerPEM: pemCert(rawIssuer)}
}

func TestCustomerProfilePublicTrustValidation(t *testing.T) {
	now := time.Now().UTC()
	p := customerProfileFixture(t, now)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, display, err := ParseCustomerProfile(raw, now)
	if err != nil || got != p || display.ManagerInstanceID != p.ManagerInstanceID || display.InvitationID != "" || len(display.IssuerFingerprint) != 64 || len(display.ServerCAFingerprints) != 1 {
		t.Fatalf("profile or public trust display invalid: %v", err)
	}
	if _, _, err = ParseCustomerProfile(raw, now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired issuer accepted")
	}
	for name, mutate := range map[string]func(*CustomerProfile){
		"customer":          func(p *CustomerProfile) { p.CustomerID = "customer_bad" },
		"profile identity":  func(p *CustomerProfile) { p.InstallerProfileID = "" },
		"http":              func(p *CustomerProfile) { p.Profile = "http-test" },
		"collection":        func(p *CustomerProfile) { p.CollectionProfile = "basic-readonly-v1" },
		"invalid server ca": func(p *CustomerProfile) { p.ServerCAPEM = "" },
		"wrong root":        func(p *CustomerProfile) { p.IssuerRootPEM = p.IssuerPEM },
		"secret origin":     func(p *CustomerProfile) { p.EnrollmentOrigin = "https://manager.example.test/?secret=x" },
	} {
		t.Run(name, func(t *testing.T) {
			p := p
			mutate(&p)
			b, _ := json.Marshal(p)
			if _, _, err := ParseCustomerProfile(b, now); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	for name, input := range map[string][]byte{
		"unknown secret": append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"secret":"x"}`)...),
		"duplicate":      append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"customerId":"`+p.CustomerID+`"}`)...),
		"trailing":       append(append([]byte(nil), raw...), []byte(` {}`)...),
		"oversize":       make([]byte, maxJSON+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseCustomerProfile(input, now); err == nil {
				t.Fatal("malformed profile accepted")
			}
		})
	}
}
