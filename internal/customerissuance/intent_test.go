package customerissuance

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
	"math/big"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerapprovalstore"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
)

func ids(prefix, digit string) string { return prefix + "_" + strings.Repeat(digit, 32) }
func certificateFixture(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	rootPub, rootKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	issuerPub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("fixture-root")}
	rawRoot, e := x509.CreateCertificate(rand.Reader, root, root, rootPub, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rawRoot)
	if e != nil {
		t.Fatal(e)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(8 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("fixture-issuer")}
	rawIssuer, e := x509.CreateCertificate(rand.Reader, issuer, root, issuerPub, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	return rawIssuer, rawRoot
}
func approvalFixture(t *testing.T, now time.Time, issuerDER []byte) customerapprovalstore.Record {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	// Deliberately untrusted CSR identity does not appear in the intent.
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-subject"}, DNSNames: []string{"untrusted.example"}}, key)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(issuerDER)
	c := customerclaim.Context{ManagerID: ids("manager", "1"), CustomerID: ids("customer", "2"), InstallerProfileID: ids("profile", "3"), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: hex.EncodeToString(h[:]), ClaimID: ids("claim", "4"), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ExpiresAt: now.Unix() + 60}
	req := ids("request", "5")
	msg, e := customerclaim.SigningMessage(c, req, csr, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := customerclaim.Encode(c, req, csr, ed25519.Sign(key, msg), now)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := customerclaim.Verify(raw, c, now)
	if e != nil {
		t.Fatal(e)
	}
	m := proof.Metadata()
	p := customerpending.Record{Version: "tracebolt.customer-pending.v1", ManagerID: m.ManagerID, CustomerID: m.CustomerID, InstallerProfileID: m.InstallerProfileID, Origin: m.Origin, AgentOrigin: m.AgentOrigin, IssuerFingerprint: m.IssuerFingerprint, ClaimID: m.ClaimID, RequestID: m.RequestID, KeyFingerprint: m.KeyFingerprint, CSRHash: m.CSRHash, ClaimHash: m.ClaimHash, ComparisonCode: m.ComparisonCode, PublicKeyDER: proof.PublicKeyDER(), CreatedAt: now.Unix() - 10, DeadlineAt: now.Unix() - 10 + int64(customerpending.PendingLifetime/time.Second)}
	expected := customerpending.ReviewExpectation{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, ClaimHash: p.ClaimHash, KeyFingerprint: p.KeyFingerprint, ManagerDigest: strings.Repeat("b", 64), CustomerRevision: 1, DeadlineAt: p.DeadlineAt}
	decision := customerapproval.Decision{OperationID: ids("request", "6"), DeviceID: ids("agent", "7"), Acknowledged: true, FingerprintCompared: true}
	a, e := customerapproval.Build(expected, p, decision, now)
	if e != nil {
		t.Fatal(e)
	}
	return customerapprovalstore.Record{Version: "tracebolt.customer-approval-record.v1", Actor: customerapprovalstore.Actor{Mode: "shared"}, Candidate: a}
}

func TestIntentBindsApprovalAndFixedWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer, root := certificateFixture(t, now)
	a := approvalFixture(t, now, issuer)
	i, err := Build(a, ids("intent", "8"), strings.Repeat("9", 32), now, time.Hour)
	if err != nil || !Valid(i) || !Current(i, now) {
		t.Fatal("build rejected", err)
	}
	if err = ValidateIssuer(i, issuer, root, now); err != nil {
		t.Fatal("valid public issuer rejected", err)
	}
	longer, err := Build(a, ids("intent", "8"), strings.Repeat("9", 32), now, 9*time.Hour)
	if err != nil || ValidateIssuer(longer, issuer, root, now) == nil {
		t.Fatal("intent outliving issuer accepted")
	}
	if i.Approval.Candidate.Pending.KeyFingerprint != a.Candidate.Pending.KeyFingerprint || i.Approval.Candidate.DeviceID != a.Candidate.DeviceID || i.Approval.Candidate.Pending.CustomerID != a.Candidate.Pending.CustomerID {
		t.Fatal("binding changed")
	}
	raw, err := Canonical(i)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("untrusted-subject")) || bytes.Contains(raw, []byte("untrusted.example")) {
		t.Fatal("untrusted CSR contents copied")
	}
	parsed, err := Parse(raw)
	if err != nil || !Valid(parsed) {
		t.Fatal("roundtrip rejected", err)
	}
	digest, err := Digest(i)
	if err != nil || len(digest) != 64 {
		t.Fatal("invalid digest", err)
	}
	a.Candidate.Pending.PublicKeyDER[0] ^= 1
	if !Valid(i) {
		t.Fatal("caller changed intent key bytes")
	}
	if Current(i, now.Add(time.Hour)) || Current(i, now.Add(-time.Second)) {
		t.Fatal("invalid intent time accepted")
	}
	if _, err = Build(i.Approval, ids("intent", "8"), strings.Repeat("9", 32), now, time.Hour+time.Nanosecond); err == nil {
		t.Fatal("fractional lifetime accepted")
	}
	if _, err = Build(i.Approval, ids("intent", "8"), strings.Repeat("9", 32), time.Unix(i.Approval.Candidate.Pending.DeadlineAt, 0), time.Hour); err == nil {
		t.Fatal("expired pending claim used")
	}
}

func TestIntentRejectsSubstitutionAndNoncanonicalEncoding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer, root := certificateFixture(t, now)
	a := approvalFixture(t, now, issuer)
	i, err := Build(a, ids("intent", "8"), strings.Repeat("9", 32), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Intent){
		"manager": func(v *Intent) { v.Approval.Candidate.Pending.ManagerID = ids("manager", "a") }, "customer": func(v *Intent) { v.Approval.Candidate.Pending.CustomerID = ids("customer", "a") }, "profile": func(v *Intent) { v.Approval.Candidate.Pending.InstallerProfileID = ids("profile", "a") }, "claim": func(v *Intent) { v.Approval.Candidate.Pending.ClaimID = ids("claim", "a") }, "issuer": func(v *Intent) { v.Approval.Candidate.Pending.IssuerFingerprint = strings.Repeat("a", 64) }, "origin": func(v *Intent) { v.Approval.Candidate.Pending.Origin = "https://other.example.test" }, "key": func(v *Intent) { v.Approval.Candidate.Pending.PublicKeyDER[0] ^= 1 }, "schema": func(v *Intent) { v.Version = "tracebolt.enrollment-intent.v2" }, "transport": func(v *Intent) { v.TransportProfile = "http-test" }, "scope": func(v *Intent) { v.CollectionProfile = "basic-readonly-v1" }, "serial": func(v *Intent) { v.SerialHex = strings.Repeat("0", 32) }, "expiry": func(v *Intent) { v.NotAfter = v.NotBefore + int64(MaxLifetime/time.Second) + 1 }, "actor": func(v *Intent) { v.Approval.Actor.Mode = "named" },
	} {
		t.Run(name, func(t *testing.T) {
			v := i
			v.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(i.Approval.Candidate.Pending.PublicKeyDER)
			edit(&v)
			if Valid(v) {
				t.Fatal("invalid substitution accepted")
			}
		})
	}
	// Fields chosen by trusted manager code still alter the full intent digest.
	for name, edit := range map[string]func(*Intent){"device": func(v *Intent) { v.Approval.Candidate.DeviceID = ids("agent", "a") }, "revision": func(v *Intent) { v.Approval.Candidate.CustomerRevision++ }, "manager digest": func(v *Intent) { v.Approval.Candidate.ManagerDigest = strings.Repeat("c", 64) }, "operation": func(v *Intent) { v.Approval.Candidate.OperationID = ids("request", "a") }, "actor": func(v *Intent) {
		v.Approval.Actor = customerapprovalstore.Actor{Mode: "named", ID: ids("operator", "a")}
	}, "serial": func(v *Intent) { v.SerialHex = strings.Repeat("a", 32) }, "not after": func(v *Intent) { v.NotAfter-- }} {
		t.Run(name, func(t *testing.T) {
			v := i
			edit(&v)
			first, _ := Digest(i)
			second, e := Digest(v)
			if e != nil || first == second {
				t.Fatal("field omitted from digest")
			}
		})
	}
	otherIssuer, otherRoot := certificateFixture(t, now)
	if ValidateIssuer(i, otherIssuer, otherRoot, now) == nil || ValidateIssuer(i, issuer, otherRoot, now) == nil || ValidateIssuer(i, issuer, root, now.Add(time.Hour)) == nil {
		t.Fatal("incorrect issuer or expired intent accepted")
	}
	raw, _ := Canonical(i)
	for name, b := range map[string][]byte{"trailing": append(bytes.Clone(raw), []byte(` {}`)...), "unknown": append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"extra":"x"}`)...), "duplicate": append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"intentId":"`+i.IntentID+`"}`)...), "oversize": bytes.Repeat([]byte(" "), maxIntentBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, e := Parse(b); e == nil {
				t.Fatal("bad encoding accepted")
			}
		})
	}
	// The v2 and v3 domains cannot collide by identical canonical public bytes.
	h := sha256.New()
	h.Write([]byte("Tracebolt enrollment issuance intent v2\x00"))
	h.Write(raw)
	d, _ := Digest(i)
	if hex.EncodeToString(h.Sum(nil)) == d {
		t.Fatal("domain separation missing")
	}
	if _, e := json.Marshal(i); e != nil {
		t.Fatal(e)
	}
}
