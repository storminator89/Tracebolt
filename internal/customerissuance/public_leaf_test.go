package customerissuance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func publicLeafFixture(t *testing.T) (issuedFixture, PublicIntent, LocalPublicBinding, []byte) {
	t.Helper()
	f := makeIssuedFixture(t)
	p, err := ProjectPublic(f.intent)
	if err != nil {
		t.Fatal(err)
	}
	o := f.intent.Approval.Candidate.Pending
	b := LocalPublicBinding{ManagerID: o.ManagerID, CustomerID: o.CustomerID, InstallerProfileID: o.InstallerProfileID, ClaimID: o.ClaimID, IssuerFingerprint: o.IssuerFingerprint, Origin: o.Origin, AgentOrigin: o.AgentOrigin, DeadlineAt: o.DeadlineAt, PublicKeyDER: bytes.Clone(o.PublicKeyDER)}
	return f, p, b, issueForTest(t, f, nil, nil, nil)
}

func TestPublicLeafMatchesServerAndIsDefensive(t *testing.T) {
	f, p, b, der := publicLeafFixture(t)
	s, err := VerifyIssued(der, f.issuerDER, f.rootDER, f.intent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, b, f.now)
	if err != nil || !v.Valid() || v.IntentDigest() != p.IntentDigest || v.CertificateHash() != s.CertificateHash() || len(v.ProjectionDigest()) != 64 || !bytes.Equal(v.DER(), der) {
		t.Fatal("server/client mismatch", err)
	}
	copy := v.DER()
	copy[0] ^= 1
	if bytes.Equal(copy, v.DER()) {
		t.Fatal("DER aliases returned result")
	}
	der[0] ^= 1
	b.PublicKeyDER[0] ^= 1
	if !bytes.Equal(v.DER(), s.DER()) {
		t.Fatal("DER aliases input")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, v), v.CertificateHash()) {
			t.Fatal("certificate leaked in formatting")
		}
	}
	raw, _ := json.Marshal(v)
	if bytes.Contains(raw, []byte(v.CertificateHash())) {
		t.Fatal("certificate leaked in JSON")
	}
	if (VerifiedPublicLeaf{}).Valid() {
		t.Fatal("zero value accepted")
	}
}

func TestPublicLeafRejectsBindingTimeAndAuthority(t *testing.T) {
	f, p, b, der := publicLeafFixture(t)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(otherKey.Public())
	otherIssuer, otherRoot := certificateFixture(t, f.now)
	for name, fn := range map[string]func() error{
		"manager": func() error {
			bad := b
			bad.ManagerID = ids("manager", "a")
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, bad, f.now)
			return e
		},
		"customer": func() error {
			bad := b
			bad.CustomerID = ids("customer", "a")
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, bad, f.now)
			return e
		},
		"claim": func() error {
			bad := b
			bad.ClaimID = ids("claim", "a")
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, bad, f.now)
			return e
		},
		"local key": func() error {
			bad := b
			bad.PublicKeyDER = otherSPKI
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, bad, f.now)
			return e
		},
		"deadline substitution": func() error {
			bad := b
			bad.DeadlineAt++
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, bad, f.now)
			return e
		},
		"expired original deadline": func() error {
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, b, time.Unix(p.DeadlineAt, 0))
			return e
		},
		"expired leaf": func() error {
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, b, time.Unix(p.NotAfter, 0))
			return e
		},
		"before validity": func() error {
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, b, f.now.Add(-time.Second))
			return e
		},
		"untrusted issuer": func() error { _, e := VerifyPublicLeaf(der, otherIssuer, otherRoot, p, b, f.now); return e },
		"wrong root":       func() error { _, e := VerifyPublicLeaf(der, f.issuerDER, otherRoot, p, b, f.now); return e },
		"device substitution": func() error {
			bad := p
			bad.DeviceID = ids("agent", "a")
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, bad, b, f.now)
			return e
		},
		"serial substitution": func() error {
			bad := p
			bad.SerialHex = strings.Repeat("a", 32)
			_, e := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, bad, b, f.now)
			return e
		},
		"signature tamper": func() error {
			bad := bytes.Clone(der)
			bad[len(bad)-1] ^= 1
			_, e := VerifyPublicLeaf(bad, f.issuerDER, f.rootDER, p, b, f.now)
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			if fn() == nil {
				t.Fatal("invalid leaf accepted")
			}
		})
	}
}

func TestPublicLeafRejectsWrongKeyAndExtensions(t *testing.T) {
	f, p, b, _ := publicLeafFixture(t)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongKey := issueForTest(t, f, nil, otherKey.Public(), nil)
	extra := issueForTest(t, f, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
	}, nil, nil)
	for _, raw := range [][]byte{wrongKey, extra, {}, bytes.Repeat([]byte{0}, 9000)} {
		if _, err := VerifyPublicLeaf(raw, f.issuerDER, f.rootDER, p, b, f.now); err == nil {
			t.Fatal("invalid leaf accepted")
		}
	}
}

func TestPublicLeafDoesNotProveIntentOrCustomerBinding(t *testing.T) {
	f, p, b, der := publicLeafFixture(t)
	first, err := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, b, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// The same leaf does not contain the intent digest. A manager-authenticated
	// projection and durable v3 intent/certificate binding are separate gates.
	p.IntentDigest = strings.Repeat("a", 64)
	second, err := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, b, f.now)
	if err != nil || second.IntentDigest() != p.IntentDigest || second.ProjectionDigest() == first.ProjectionDigest() || second.CertificateHash() != first.CertificateHash() {
		t.Fatal("projection binding or stated limitation changed", err)
	}
	// The leaf likewise does not encode the public routing intent ID. The
	// manager must authenticate the whole projection and compare stored state.
	p.IntentID = ids("intent", "a")
	third, err := VerifyPublicLeaf(der, f.issuerDER, f.rootDER, p, b, f.now)
	if err != nil || third.CertificateHash() != second.CertificateHash() || third.ProjectionDigest() == second.ProjectionDigest() {
		t.Fatal("leaf incorrectly claimed to authenticate intent ID", err)
	}
}
