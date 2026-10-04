package enrollmentcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testID(prefix string, n byte) string {
	return prefix + hex.EncodeToString(bytes.Repeat([]byte{n}, 16))
}
func contextFixture(profile string, now time.Time) ChallengeContext {
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	}
	return ChallengeContext{ManagerInstanceID: testID("manager_", 1), Profile: profile, Origin: scheme + "://127.0.0.1:8443", CollectionProfile: CollectionProfile, InvitationID: testID("invite_", 2), ClaimID: testID("claim_", 3), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ExpiresAt: now.Unix() + 120}
}
func claimFixture(t testing.TB, c ChallengeContext, now time.Time) ([]byte, VerifiedClaim, ed25519.PrivateKey, []byte, string) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key")
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted requested identity"}, DNSNames: []string{"requested.invalid"}}, key)
	if e != nil {
		t.Fatal("fixture CSR")
	}
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	raw := signedClaim(t, c, testID("request_", 6), csr, secret, key, now)
	verified, e := VerifyClaim(raw, c, now)
	if e != nil {
		t.Fatal("valid proof rejected")
	}
	return raw, verified, key, csr, secret
}
func signedClaim(t testing.TB, c ChallengeContext, requestID string, csr []byte, secret string, key ed25519.PrivateKey, now time.Time) []byte {
	t.Helper()
	message, e := ClaimSigningMessage(c, requestID, csr, secret, now)
	if e != nil {
		t.Fatal("fixture signing message")
	}
	body := map[string]string{"schemaVersion": ClaimVersion, "managerInstanceId": c.ManagerInstanceID, "profile": c.Profile, "origin": c.Origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "requestId": requestID, "challenge": c.Challenge, "invitationSecret": secret, "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))}
	raw, _ := json.Marshal(body)
	return raw
}
func TestClaimProofBindingAndSemanticRetry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			c := contextFixture(profile, now)
			raw, proof, key, csr, secret := claimFixture(t, c, now)
			if !proof.Valid() || len(proof.ComparisonCode()) != 32 || len(proof.KeyFingerprint()) != 64 {
				t.Fatal("invalid proof metadata")
			}
			h, _ := InvitationHash(secret)
			if proof.InvitationHash() != h {
				t.Fatal("verifier mismatch")
			}
			code, e := ComparisonCode(c.ManagerInstanceID, c.InvitationID, c.ClaimID, proof.KeyFingerprint())
			if e != nil || code != proof.ComparisonCode() {
				t.Fatal("comparison mismatch")
			}
			copyKey := proof.PublicKeyDER()
			copyKey[0] ^= 1
			if bytes.Equal(copyKey, proof.PublicKeyDER()) {
				t.Fatal("mutable proof bytes")
			}
			next := c
			next.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
			next.ExpiresAt++
			retry, e := VerifyClaim(signedClaim(t, next, proof.RequestID(), csr, secret, key, now), next, now)
			if e != nil || retry.ClaimHash() != proof.ClaimHash() || retry.ComparisonCode() != proof.ComparisonCode() {
				t.Fatal("semantic retry changed")
			}
			if _, e = VerifyClaim(raw, next, now); e == nil {
				t.Fatal("old challenge replay accepted")
			}
			if _, e = VerifyClaim(raw, c, time.Unix(c.ExpiresAt, 0)); e == nil {
				t.Fatal("expiry boundary accepted")
			}
			for _, mutate := range []func(*ChallengeContext){func(c *ChallengeContext) { c.ManagerInstanceID = testID("manager_", 9) }, func(c *ChallengeContext) { c.ClaimID = testID("claim_", 9) }, func(c *ChallengeContext) { c.InvitationID = testID("invite_", 9) }, func(c *ChallengeContext) { c.Origin = strings.Replace(c.Origin, "8443", "9443", 1) }, func(c *ChallengeContext) { c.CollectionProfile = "unbounded" }} {
				wrong := c
				mutate(&wrong)
				if _, e := VerifyClaim(raw, wrong, now); e == nil {
					t.Fatal("context substitution accepted")
				}
			}
			for _, v := range []any{proof, &proof} {
				b, _ := json.Marshal(v)
				if bytes.Contains(b, []byte(secret)) {
					t.Fatal("JSON leaked secret")
				}
				for _, format := range []string{"%v", "%+v", "%#v"} {
					if strings.Contains(fmt.Sprintf(format, v), secret) {
						t.Fatal("format leaked secret")
					}
				}
			}
		})
	}
}
func TestClaimStrictJSONAndPossession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := contextFixture("tls", now)
	raw, _, _, _, _ := claimFixture(t, c, now)
	var original map[string]any
	json.Unmarshal(raw, &original)
	for _, name := range []string{"missing", "unknown", "case", "null", "number", "bad-proof", "bad-csr", "surrogate", "oversize", "duplicate", "trailing"} {
		t.Run(name, func(t *testing.T) {
			body := map[string]any{}
			for k, v := range original {
				body[k] = v
			}
			switch name {
			case "missing":
				delete(body, "proof")
			case "unknown":
				body["trusted"] = true
			case "case":
				body["Profile"] = body["profile"]
				delete(body, "profile")
			case "null":
				body["proof"] = nil
			case "number":
				body["requestId"] = 1
			case "bad-proof":
				body["proof"] = base64.RawStdEncoding.EncodeToString(make([]byte, 64))
			case "bad-csr":
				body["csr"] = base64.RawStdEncoding.EncodeToString([]byte("invalid"))
			case "oversize":
				body["csr"] = strings.Repeat("x", MaxClaimBytes)
			}
			bad, _ := json.Marshal(body)
			switch name {
			case "surrogate":
				bad = []byte(strings.Replace(string(raw), `"tls"`, `"\ud800"`, 1))
			case "duplicate":
				bad = append([]byte(`{"profile":"tls",`), raw[1:]...)
			case "trailing":
				bad = append(bytes.Clone(raw), []byte(` {}`)...)
			}
			if _, e := VerifyClaim(bad, c, now); e == nil {
				t.Fatal("invalid claim accepted")
			}
		})
	}
	if (VerifiedClaim{}).Valid() {
		t.Fatal("zero proof accepted")
	}
}

type certFixture struct {
	intent       Intent
	leaf, issuer []byte
	issuerCert   *x509.Certificate
	issuerKey    ed25519.PrivateKey
	endpointKey  ed25519.PrivateKey
	context      ChallengeContext
}

func certificateFixture(t testing.TB, profile string, now time.Time, collection ...string) certFixture {
	t.Helper()
	c := contextFixture(profile, now)
	if len(collection) == 1 {
		c.CollectionProfile = collection[0]
	}
	_, claim, key, _, _ := claimFixture(t, c, now)
	rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral offline test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, rootPub, rootKey)
	if e != nil {
		t.Fatal("fixture root")
	}
	root, _ = x509.ParseCertificate(rootDER)
	issuerPub, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ephemeral client only intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	issuerDER, e := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerPub, rootKey)
	if e != nil {
		t.Fatal("fixture intermediate")
	}
	issuer, _ := x509.ParseCertificate(issuerDER)
	i := Intent{ManagerInstanceID: c.ManagerInstanceID, Profile: profile, Origin: c.Origin, CollectionProfile: c.CollectionProfile, InvitationID: c.InvitationID, ClaimID: c.ClaimID, RequestID: claim.RequestID(), DeviceID: testID("agent_", 8), IntentID: testID("intent_", 9), KeyFingerprint: claim.KeyFingerprint(), PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(claim.PublicKeyDER()), CSRHash: claim.CSRHash(), ClaimHash: claim.ClaimHash(), IssuerFingerprint: hash(issuerDER), SerialHex: hex.EncodeToString(bytes.Repeat([]byte{10}, 16)), TemplateVersion: TemplateVersion, KeyGeneration: 1, NotBefore: now.Unix() - 30, NotAfter: now.Add(24 * time.Hour).Unix()}
	f := certFixture{intent: i, issuer: issuerDER, issuerCert: issuer, issuerKey: issuerKey, endpointKey: key, context: c}
	f.leaf = issueFixture(t, f, nil)
	return f
}
func issueFixture(t testing.TB, f certFixture, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	serial, _ := new(big.Int).SetString(f.intent.SerialHex, 16)
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: f.intent.DeviceID}, NotBefore: time.Unix(f.intent.NotBefore, 0), NotAfter: time.Unix(f.intent.NotAfter, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if mutate != nil {
		mutate(leaf)
	}
	raw, e := x509.CreateCertificate(rand.Reader, leaf, f.issuerCert, f.endpointKey.Public(), f.issuerKey)
	if e != nil {
		t.Fatal("fixture leaf creation")
	}
	return raw
}
func TestFixedIntentRejectsIssuedPrivilegeAndIdentityChanges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := certificateFixture(t, profile, now)
			verified, e := VerifyIssued(f.leaf, f.issuer, f.intent, now)
			if e != nil || !verified.Valid() || verified.Intent() != f.intent {
				t.Fatal("valid certificate rejected")
			}
			changed := verified.DER()
			changed[0] ^= 1
			if bytes.Equal(changed, verified.DER()) {
				t.Fatal("certificate alias")
			}
			variations := map[string]func(*x509.Certificate){"ca": func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }, "server-auth": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, "mixed-role": func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) }, "subject": func(c *x509.Certificate) { c.Subject.CommonName = testID("agent_", 11) }, "subject-extra": func(c *x509.Certificate) { c.Subject.Organization = []string{"untrusted requested organization"} }, "san": func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }, "serial": func(c *x509.Certificate) { c.SerialNumber = big.NewInt(1) }, "oversized-serial": func(c *x509.Certificate) { c.SerialNumber = new(big.Int).Lsh(big.NewInt(1), 152) }, "validity": func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(time.Second) }, "extra-extension": func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1}}}
			}}
			for name, mutate := range variations {
				t.Run(name, func(t *testing.T) {
					if _, e := VerifyIssued(issueFixture(t, f, mutate), f.issuer, f.intent, now); e == nil {
						t.Fatal("changed certificate policy accepted")
					}
				})
			}
			if _, e := VerifyIssued(f.leaf, f.issuer, f.intent, time.Unix(f.intent.NotAfter, 0)); e == nil {
				t.Fatal("expired certificate accepted")
			}
			wrong := f.intent
			wrong.KeyGeneration = 2
			if _, e := VerifyIssued(f.leaf, f.issuer, wrong, now); e == nil {
				t.Fatal("unimplemented key generation accepted")
			}
		})
	}
}
func TestActivationRequiresFreshPrivateKeyProof(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := certificateFixture(t, "tls", now)
	cert, e := VerifyIssued(f.leaf, f.issuer, f.intent, now)
	if e != nil {
		t.Fatal("fixture verification")
	}
	requestID := testID("request_", 12)
	message, e := ActivationSigningMessage(f.context, f.intent, requestID, cert.CertificateHash(), now)
	if e != nil {
		t.Fatal("activation message")
	}
	body := map[string]string{"schemaVersion": ActivationVersion, "managerInstanceId": f.intent.ManagerInstanceID, "profile": f.intent.Profile, "origin": f.intent.Origin, "deviceId": f.intent.DeviceID, "intentId": f.intent.IntentID, "certificateHash": cert.CertificateHash(), "requestId": requestID, "challenge": f.context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.endpointKey, message))}
	raw, _ := json.Marshal(body)
	proof, e := VerifyActivation(raw, cert, f.context, now)
	if e != nil || !proof.Valid() || proof.Intent() != f.intent || proof.RequestID() != requestID {
		t.Fatal("activation proof rejected")
	}
	body["proof"] = base64.RawStdEncoding.EncodeToString(make([]byte, 64))
	raw, _ = json.Marshal(body)
	if _, e := VerifyActivation(raw, cert, f.context, now); e == nil {
		t.Fatal("public certificate alone activated")
	}
	if _, e := VerifyActivation(raw, VerifiedCertificate{}, f.context, now); e == nil {
		t.Fatal("unvalidated certificate activated")
	}
}
func FuzzProofDecoders(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"proof":null}`))
	now := time.Unix(1800000000, 0)
	c := contextFixture("tls", now)
	fixture := certificateFixture(f, "tls", now)
	certificate, e := VerifyIssued(fixture.leaf, fixture.issuer, fixture.intent, now)
	if e != nil {
		f.Fatal("fuzz fixture verification")
	}
	rawClaim, _, _, _, _ := claimFixture(f, c, now)
	f.Add(rawClaim)
	f.Add(fixture.leaf)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxClaimBytes+1 {
			return
		}
		_, _ = VerifyClaim(raw, c, now)
		_, _ = VerifyActivation(raw, certificate, c, now)
		_, _ = VerifyIssued(raw, fixture.issuer, fixture.intent, now)
	})
}
func TestActivationBindsCompleteImmutableIntent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := certificateFixture(t, "tls", now)
	cert, e := VerifyIssued(f.leaf, f.issuer, f.intent, now)
	if e != nil {
		t.Fatal("fixture cert")
	}
	request := testID("request_", 21)
	message, e := ActivationSigningMessage(f.context, f.intent, request, cert.CertificateHash(), now)
	if e != nil {
		t.Fatal("fixture message")
	}
	body := map[string]string{"schemaVersion": ActivationVersion, "managerInstanceId": f.intent.ManagerInstanceID, "profile": f.intent.Profile, "origin": f.intent.Origin, "deviceId": f.intent.DeviceID, "intentId": f.intent.IntentID, "certificateHash": cert.CertificateHash(), "requestId": request, "challenge": f.context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.endpointKey, message))}
	raw, _ := json.Marshal(body)
	for _, change := range []func(*Intent){func(i *Intent) { i.CSRHash = strings.Repeat("a", 64) }, func(i *Intent) { i.ClaimHash = strings.Repeat("b", 64) }, func(i *Intent) { i.RequestID = testID("request_", 22) }} {
		intent := f.intent
		change(&intent)
		other, e := VerifyIssued(f.leaf, f.issuer, intent, now)
		if e != nil {
			t.Fatal("fixture metadata alteration")
		}
		if _, e = VerifyActivation(raw, other, f.context, now); e == nil {
			t.Fatal("activation signature was reusable for a changed intent")
		}
	}
}
