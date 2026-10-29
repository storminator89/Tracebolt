package enrollmentissuer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
)

// Reproducible public fixtures pin pre-refactor v2 DER bytes. All keys are
// published, deterministic test keys and must never be used outside tests.
func TestV2FixedIssuanceGolden(t *testing.T) {
	at := time.Unix(1791048000, 0).UTC()
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	deviceKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Tracebolt fixture root"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("fixture-root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Tracebolt fixture issuer"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("fixture-issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerT, root, issuerKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(deviceKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	id := func(prefix, digit string) string { return prefix + "_" + strings.Repeat(digit, 32) }
	intent := enrollmentcrypto.Intent{ManagerInstanceID: id("manager", "1"), Profile: "tls", Origin: "https://manager.example.test", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, InvitationID: id("invite", "2"), ClaimID: id("claim", "3"), RequestID: id("request", "4"), DeviceID: id("agent", "5"), IntentID: id("intent", "6"), KeyFingerprint: hash(spki), PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(spki), CSRHash: hash([]byte("fixture CSR")), ClaimHash: hash([]byte("fixture claim")), IssuerFingerprint: hash(issuerDER), SerialHex: strings.Repeat("7", 32), TemplateVersion: enrollmentcrypto.TemplateVersion, KeyGeneration: 1, NotBefore: at.Unix(), NotAfter: at.Add(time.Hour).Unix()}
	handle, err := enrollmentissuer.New(issuerDER, rootDER, issuerKey, intent.IssuerFingerprint, at)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := handle.Sign(context.Background(), intent, at)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "4ccbeee494ac50a3f13acfe4f0d089ed993050fc9d8ed7ff15e07632e2996814"
	if actual := hash(cert.DER()); actual != expected {
		t.Fatalf("V2_GOLDEN_SHA256=%s", actual)
	}
}
