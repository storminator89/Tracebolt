package main

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

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
)

func publicFixture(t *testing.T) []byte {
	t.Helper()
	now := time.Now().UTC()
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ip, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("rootfixture")}
	rd, err := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rd)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuerfixture")}
	id, err := x509.CreateCertificate(rand.Reader, issuer, root, ip, rk)
	if err != nil {
		t.Fatal(err)
	}
	cert := func(raw []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	b := enrollmentclient.Bootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), InvitationID: "invite_" + strings.Repeat("2", 32), Profile: "tls", EnrollmentOrigin: "https://127.0.0.1:8443", AgentOrigin: "https://127.0.0.1:8444", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, ServerCAPEM: cert(rd), IssuerRootPEM: cert(rd), IssuerPEM: cert(id)}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestActualParserAcceptsOnlyBoundedPublicWindowsBootstrap(t *testing.T) {
	raw := publicFixture(t)
	if !validPublicBootstrap(raw) {
		t.Fatal("valid public Windows configuration rejected")
	}
	secret := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"invitationSecret":"fixture-secret"}`)...)
	linux := strings.Replace(string(raw), enrollmentcrypto.CollectionProfileWindowsInventory, enrollmentcrypto.CollectionProfile, 1)
	wrongSchema := strings.Replace(string(raw), enrollmentclient.BootstrapVersion, "tracebolt.enrollment-bootstrap.v99", 1)
	mixedOrigin := strings.Replace(string(raw), "https://127.0.0.1:8444", "http://127.0.0.1:8444", 1)
	for _, bad := range [][]byte{nil, []byte("none"), secret, []byte(linux), []byte(wrongSchema), []byte(mixedOrigin), raw[:len(raw)-1], make([]byte, (64<<10)+1)} {
		if validPublicBootstrap(bad) {
			t.Fatal("invalid, secret-bearing or non-Windows configuration accepted")
		}
	}
}
