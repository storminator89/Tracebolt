package customerissuance

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type issuedFixture struct {
	now                time.Time
	intent             Intent
	issuerDER, rootDER []byte
	issuer             *x509.Certificate
	issuerKey          ed25519.PrivateKey
	public             crypto.PublicKey
}

func makeIssuedFixture(t *testing.T) issuedFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("fixture-root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, rootPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(8 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("fixture-issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerT, root, issuerPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	a := approvalFixture(t, now, issuerDER)
	intent, err := Build(a, ids("intent", "8"), strings.Repeat("9", 32), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(intent.Approval.Candidate.Pending.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	return issuedFixture{now, intent, issuerDER, rootDER, issuer, issuerKey, pub}
}

func issueForTest(t *testing.T, f issuedFixture, edit func(*x509.Certificate), pub crypto.PublicKey, parent *x509.Certificate) []byte {
	t.Helper()
	serial, ok := new(big.Int).SetString(f.intent.SerialHex, 16)
	if !ok {
		t.Fatal("serial")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: f.intent.Approval.Candidate.DeviceID}, NotBefore: time.Unix(f.intent.NotBefore, 0), NotAfter: time.Unix(f.intent.NotAfter, 0), SignatureAlgorithm: x509.PureEd25519, BasicConstraintsValid: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, AuthorityKeyId: bytes.Clone(f.issuer.SubjectKeyId)}
	if edit != nil {
		edit(template)
	}
	if pub == nil {
		pub = f.public
	}
	if parent == nil {
		parent = f.issuer
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerifyIssuedFixedCustomerCertificate(t *testing.T) {
	f := makeIssuedFixture(t)
	der := issueForTest(t, f, nil, nil, nil)
	v, err := VerifyIssued(der, f.issuerDER, f.rootDER, f.intent, f.now)
	if err != nil || !v.Valid() {
		t.Fatal("valid fixed certificate rejected", err)
	}
	want, err := Digest(f.intent)
	if err != nil || v.IntentDigest() != want || len(v.CertificateHash()) != 64 {
		t.Fatal("intent or certificate digest incorrect")
	}
	copy := v.DER()
	copy[0] ^= 1
	if bytes.Equal(copy, v.DER()) {
		t.Fatal("returned DER aliases internal bytes")
	}
	der[0] ^= 1
	if bytes.Equal(der, v.DER()) {
		t.Fatal("caller DER aliases verified result")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, v), v.CertificateHash()) {
			t.Fatal("unexpected certificate data in formatting")
		}
	}
	b, _ := json.Marshal(v)
	if bytes.Contains(b, []byte(v.CertificateHash())) {
		t.Fatal("unexpected certificate data in serialization")
	}
	if (VerifiedCertificate{}).Valid() {
		t.Fatal("zero value accepted")
	}
}

func TestVerifyIssuedRejectsAlteredLeafAndExtensions(t *testing.T) {
	f := makeIssuedFixture(t)
	criticalKeyUsage := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: false, Value: []byte{3, 2, 7, 128}}
	for name, edit := range map[string]func(*x509.Certificate){
		"wrong device":        func(c *x509.Certificate) { c.Subject.CommonName = ids("agent", "a") },
		"extra subject":       func(c *x509.Certificate) { c.Subject.Organization = []string{"untrusted"} },
		"DNS SAN":             func(c *x509.Certificate) { c.DNSNames = []string{"untrusted.example"} },
		"IP SAN":              func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} },
		"serial":              func(c *x509.Certificate) { c.SerialNumber = big.NewInt(3) },
		"time":                func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(time.Second) },
		"CA":                  func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"missing key usage":   func(c *x509.Certificate) { c.KeyUsage = 0 },
		"extra key usage":     func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment },
		"missing EKU":         func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"server EKU":          func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"dual EKU":            func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		"missing constraints": func(c *x509.Certificate) { c.BasicConstraintsValid = false },
		"unexpected SKI":      func(c *x509.Certificate) { c.SubjectKeyId = []byte("extra") },
		"wrong criticality":   func(c *x509.Certificate) { c.ExtraExtensions = []pkix.Extension{criticalKeyUsage} },
		"unknown noncritical": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		},
		"unknown critical": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			der := issueForTest(t, f, edit, nil, nil)
			if _, err := VerifyIssued(der, f.issuerDER, f.rootDER, f.intent, f.now); err == nil {
				t.Fatal("changed leaf accepted")
			}
		})
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyIssued(issueForTest(t, f, nil, otherKey.Public(), nil), f.issuerDER, f.rootDER, f.intent, f.now); err == nil {
		t.Fatal("different SPKI accepted")
	}
	withoutSKI := *f.issuer
	withoutSKI.SubjectKeyId = nil
	missingAKI := issueForTest(t, f, func(c *x509.Certificate) { c.AuthorityKeyId = nil }, nil, &withoutSKI)
	if _, err = VerifyIssued(missingAKI, f.issuerDER, f.rootDER, f.intent, f.now); err == nil {
		t.Fatal("missing authority key identifier accepted")
	}
	der := issueForTest(t, f, nil, nil, nil)
	der[len(der)-1] ^= 1
	if _, err = VerifyIssued(der, f.issuerDER, f.rootDER, f.intent, f.now); err == nil {
		t.Fatal("bad signature accepted")
	}
}

func TestVerifyIssuedRejectsIssuerTimeAndUnboundContext(t *testing.T) {
	f := makeIssuedFixture(t)
	der := issueForTest(t, f, nil, nil, nil)
	other := makeIssuedFixture(t)
	for name, inputs := range map[string]struct {
		issuer, root []byte
		now          time.Time
	}{
		"other issuer": {other.issuerDER, other.rootDER, f.now}, "other root": {f.issuerDER, other.rootDER, f.now},
		"future start": {f.issuerDER, f.rootDER, f.now.Add(-time.Second)}, "expired": {f.issuerDER, f.rootDER, time.Unix(f.intent.NotAfter, 0)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyIssued(der, inputs.issuer, inputs.root, f.intent, inputs.now); err == nil {
				t.Fatal("invalid authority/time accepted")
			}
		})
	}
	for name, invalid := range map[string][]byte{"empty": nil, "oversize": bytes.Repeat([]byte{1}, 16384), "trailing": append(bytes.Clone(der), 1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyIssued(invalid, f.issuerDER, f.rootDER, f.intent, f.now); err == nil {
				t.Fatal("invalid DER accepted")
			}
		})
	}
	// Customer and manager data are NOT encoded in this leaf. A syntactically
	// valid substitution of a non-leaf approval field can verify against the
	// same DER, but its verified intent digest differs. Only a protected,
	// authoritative intent+certificate-hash commit can establish that binding.
	changed := f.intent
	changed.Approval.Candidate.CustomerRevision++
	first, err := VerifyIssued(der, f.issuerDER, f.rootDER, f.intent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifyIssued(der, f.issuerDER, f.rootDER, changed, f.now)
	if err != nil {
		t.Fatal("leaf-only limitation changed", err)
	}
	if first.IntentDigest() == second.IntentDigest() || first.CertificateHash() != second.CertificateHash() {
		t.Fatal("intent context or certificate hash lost")
	}
}
