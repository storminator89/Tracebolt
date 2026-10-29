package customerclaim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixtureContext(now time.Time) Context {
	return Context{ManagerID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("8", 32), Origin: "https://manager.example.test:8443", AgentOrigin: "https://agent.example.test:8444", IssuerFingerprint: strings.Repeat("a", 64), ClaimID: "claim_" + strings.Repeat("3", 32), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ExpiresAt: now.Unix() + 60}
}
func fixtureRequest(t *testing.T, c Context, now time.Time) ([]byte, []byte, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored fixture"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	message, err := SigningMessage(c, "request_"+strings.Repeat("5", 32), csr, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(c, "request_"+strings.Repeat("5", 32), csr, ed25519.Sign(key, message), now)
	if err != nil {
		t.Fatal(err)
	}
	return raw, csr, key
}
func TestVerifiedRequestBindsCustomerAndOriginalKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixtureContext(now)
	raw, csr, key := fixtureRequest(t, c, now)
	verified, err := Verify(raw, c, now)
	if err != nil || !verified.Valid() {
		t.Fatalf("verification failed: %v", err)
	}
	m := verified.Metadata()
	if m.CustomerID != c.CustomerID || m.InstallerProfileID != c.InstallerProfileID || m.ManagerID != c.ManagerID || len(m.KeyFingerprint) != 64 || len(m.ComparisonCode) != 32 || len(m.ClaimHash) != 64 {
		t.Fatal("incorrect public metadata")
	}
	der := verified.PublicKeyDER()
	der[0] ^= 1
	if bytes.Equal(der, verified.PublicKeyDER()) {
		t.Fatal("key escaped mutable proof")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, verified), m.KeyFingerprint) {
			t.Fatal("proof formatted private details")
		}
	}
	encoded, _ := json.Marshal(verified)
	if bytes.Contains(encoded, []byte(m.KeyFingerprint)) {
		t.Fatal("proof serialized internal data")
	}
	// A fresh challenge may retry the exact same semantic request but the old
	// challenge signature never verifies against the fresh trusted context.
	next := c
	next.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	next.ExpiresAt--
	if _, err = Verify(raw, next, now); err == nil {
		t.Fatal("old proof accepted against a different challenge")
	}
	msg, err := SigningMessage(next, m.RequestID, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := Encode(next, m.RequestID, csr, ed25519.Sign(key, msg), now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Verify(retry, next, now)
	if err != nil || second.Metadata().ClaimHash != m.ClaimHash || second.Metadata().ComparisonCode != m.ComparisonCode {
		t.Fatal("semantic retry changed original binding")
	}
	if _, err = Verify(raw, c, time.Unix(c.ExpiresAt, 0)); err == nil {
		t.Fatal("expired challenge accepted")
	}
	// The verifier is intentionally stateless: the owning server must atomically
	// consume a challenge and check live profile/customer status before admission.
	if repeated, err := Verify(raw, c, now); err != nil || !repeated.Valid() {
		t.Fatal("stateless verification unexpectedly consumed challenge")
	}
}

func TestContextSubstitutionAndInvalidContextsFail(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixtureContext(now)
	raw, _, _ := fixtureRequest(t, c, now)
	tests := map[string]func(*Context){
		"manager":           func(v *Context) { v.ManagerID = "manager_" + strings.Repeat("7", 32) },
		"customer":          func(v *Context) { v.CustomerID = "customer_" + strings.Repeat("7", 32) },
		"profile":           func(v *Context) { v.InstallerProfileID = "profile_" + strings.Repeat("7", 32) },
		"manager-origin":    func(v *Context) { v.Origin = "https://other.example.test:8443" },
		"agent-origin":      func(v *Context) { v.AgentOrigin = "https://other.example.test:8444" },
		"issuer":            func(v *Context) { v.IssuerFingerprint = strings.Repeat("b", 64) },
		"claim":             func(v *Context) { v.ClaimID = "claim_" + strings.Repeat("7", 32) },
		"expiry":            func(v *Context) { v.ExpiresAt-- },
		"missing-profile":   func(v *Context) { v.InstallerProfileID = "" },
		"http":              func(v *Context) { v.Origin = "http://manager.example.test" },
		"url-secret":        func(v *Context) { v.AgentOrigin = "https://agent.example.test/?token=secret" },
		"too-long":          func(v *Context) { v.ExpiresAt = now.Unix() + 61 },
		"invalid-challenge": func(v *Context) { v.Challenge = "short" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			v := c
			mutate(&v)
			if _, err := Verify(raw, v, now); err == nil {
				t.Fatal("altered context accepted")
			}
		})
	}
}

func TestCustomerAndInstallerProfileAreDistinctBindings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixtureContext(now)
	raw, csr, key := fixtureRequest(t, c, now)
	first, err := Verify(raw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Context){
		func(v *Context) { v.CustomerID = "customer_" + strings.Repeat("7", 32) },
		func(v *Context) { v.InstallerProfileID = "profile_" + strings.Repeat("7", 32) },
	} {
		other := c
		mutate(&other)
		msg, err := SigningMessage(other, first.Metadata().RequestID, csr, now)
		if err != nil {
			t.Fatal(err)
		}
		newRaw, err := Encode(other, first.Metadata().RequestID, csr, ed25519.Sign(key, msg), now)
		if err != nil {
			t.Fatal(err)
		}
		second, err := Verify(newRaw, other, now)
		if err != nil || second.Metadata().ClaimHash == first.Metadata().ClaimHash || second.Metadata().ComparisonCode == first.Metadata().ComparisonCode {
			t.Fatal("customer or installer profile did not change the proof binding")
		}
	}
}

func TestStrictRequestParserAndSignatures(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixtureContext(now)
	raw, _, _ := fixtureRequest(t, c, now)
	var original map[string]any
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "unknown", "secret", "case", "null", "number", "wrong-profile", "wrong-customer", "bad-proof", "bad-csr", "noncanonical-base64", "surrogate", "oversize", "duplicate", "trailing"} {
		t.Run(name, func(t *testing.T) {
			b := map[string]any{}
			for k, v := range original {
				b[k] = v
			}
			switch name {
			case "missing":
				delete(b, "customerId")
			case "unknown":
				b["newField"] = "x"
			case "secret":
				b["invitationSecret"] = "never-accepted"
			case "case":
				b["CustomerId"] = b["customerId"]
				delete(b, "customerId")
			case "null":
				b["customerId"] = nil
			case "number":
				b["installerProfileId"] = 1
			case "wrong-profile":
				b["collectionProfile"] = "basic-readonly-v1"
			case "wrong-customer":
				b["customerId"] = "customer_" + strings.Repeat("9", 32)
			case "bad-proof":
				b["proof"] = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize))
			case "bad-csr":
				b["csr"] = base64.RawStdEncoding.EncodeToString([]byte("invalid"))
			case "noncanonical-base64":
				b["csr"] = original["csr"].(string) + "="
			}
			candidate, _ := json.Marshal(b)
			switch name {
			case "surrogate":
				candidate = bytes.Replace(candidate, []byte(`"customerId":"`+c.CustomerID+`"`), []byte(`"customerId":"\ud800"`), 1)
			case "oversize":
				candidate = bytes.Repeat([]byte(" "), MaxBytes+1)
			case "duplicate":
				candidate = append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"customerId":"`+c.CustomerID+`"}`)...)
			case "trailing":
				candidate = append(candidate, []byte(` {}`)...)
			}
			if _, err := Verify(candidate, c, now); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestMismatchedKeyCannotSignCSR(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixtureContext(now)
	_, csr, _ := fixtureRequest(t, c, now)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	msg, err := SigningMessage(c, "request_"+strings.Repeat("5", 32), csr, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Encode(c, "request_"+strings.Repeat("5", 32), csr, ed25519.Sign(other, msg), now); err == nil {
		t.Fatal("unrelated signing key accepted")
	}
	if (Verified{}).Valid() {
		t.Fatal("zero proof acquired authority")
	}
}
