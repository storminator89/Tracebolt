package customerclaim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStatusProofBindsRetainedIdentityAndFreshChallenge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixtureContext(now)
	raw, _, key := fixtureRequest(t, c, now)
	claim, err := Verify(raw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	m := claim.Metadata()
	der := claim.PublicKeyDER()
	c.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	request := "request_" + strings.Repeat("a", 32)
	message, err := StatusSigningMessage(c, m, der, request, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeStatus(c, m, der, request, ed25519.Sign(key, message), now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyStatus(encoded, c, m, der, now)
	if err != nil || !verified.Valid() || verified.RequestID() != request || verified.ExpiresAt() != c.ExpiresAt {
		t.Fatal("status proof rejected", err)
	}
	if _, err = VerifyStatus(encoded, c, m, der, time.Unix(c.ExpiresAt, 0)); err == nil {
		t.Fatal("expired status proof accepted")
	}
	badMetadata := m
	badMetadata.CustomerID = "customer_" + strings.Repeat("b", 32)
	if _, err = VerifyStatus(encoded, c, badMetadata, der, now); err == nil {
		t.Fatal("substituted stored metadata accepted")
	}
	badKey := bytes.Clone(der)
	badKey[len(badKey)-1] ^= 1
	if _, err = VerifyStatus(encoded, c, m, badKey, now); err == nil {
		t.Fatal("substituted stored key accepted")
	}
	for name, mutate := range map[string]func(*Context){"manager": func(v *Context) { v.ManagerID = "manager_" + strings.Repeat("a", 32) }, "customer": func(v *Context) { v.CustomerID = "customer_" + strings.Repeat("a", 32) }, "profile": func(v *Context) { v.InstallerProfileID = "profile_" + strings.Repeat("a", 32) }, "origin": func(v *Context) { v.Origin = "https://other.example.test" }, "agent": func(v *Context) { v.AgentOrigin = "https://other.example.test" }, "issuer": func(v *Context) { v.IssuerFingerprint = strings.Repeat("b", 64) }, "claim": func(v *Context) { v.ClaimID = "claim_" + strings.Repeat("a", 32) }, "nonce": func(v *Context) { v.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) }, "expiry": func(v *Context) { v.ExpiresAt-- }} {
		t.Run(name, func(t *testing.T) {
			v := c
			mutate(&v)
			if _, err := VerifyStatus(encoded, v, m, der, now); err == nil {
				t.Fatal("altered binding accepted")
			}
		})
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = EncodeStatus(c, m, der, request, ed25519.Sign(wrong, message), now); err == nil {
		t.Fatal("other key accepted")
	}
	// Verification alone is deliberately stateless: the manager must consume a
	// purpose-bound challenge before checking this proof.
	if _, err = VerifyStatus(encoded, c, m, der, now); err != nil {
		t.Fatal("stateless verify changed", err)
	}
}

func TestStatusProofStrictParsingAndDomainSeparation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixtureContext(now)
	claimRaw, csr, key := fixtureRequest(t, c, now)
	claim, err := Verify(claimRaw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	m, der := claim.Metadata(), claim.PublicKeyDER()
	request := "request_" + strings.Repeat("a", 32)
	msg, err := StatusSigningMessage(c, m, der, request, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeStatus(c, m, der, request, ed25519.Sign(key, msg), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyStatus(claimRaw, c, m, der, now); err == nil {
		t.Fatal("claim proof accepted as status")
	}
	claimMessage, err := SigningMessage(c, request, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	var cross statusBody
	if json.Unmarshal(raw, &cross) != nil {
		t.Fatal("bad fixture")
	}
	cross.Proof = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, claimMessage))
	crossRaw, _ := json.Marshal(cross)
	if _, err = VerifyStatus(crossRaw, c, m, der, now); err == nil {
		t.Fatal("claim-domain signature accepted as status")
	}
	var b map[string]any
	if json.Unmarshal(raw, &b) != nil {
		t.Fatal("bad fixture")
	}
	for _, name := range []string{"missing", "unknown", "null", "bad-signature", "wrong-hash", "duplicate", "trailing", "oversize", "case", "noncanonical-base64", "surrogate"} {
		t.Run(name, func(t *testing.T) {
			v := map[string]any{}
			for k, x := range b {
				v[k] = x
			}
			switch name {
			case "missing":
				delete(v, "proof")
			case "unknown":
				v["secret"] = "no"
			case "null":
				v["proof"] = nil
			case "bad-signature":
				v["proof"] = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
			case "wrong-hash":
				v["claimHash"] = strings.Repeat("a", 64)
			case "case":
				v["RequestId"] = v["requestId"]
				delete(v, "requestId")
			case "noncanonical-base64":
				v["proof"] = v["proof"].(string) + "="
			}
			data, _ := json.Marshal(v)
			switch name {
			case "duplicate":
				data = append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"requestId":"`+request+`"}`)...)
			case "trailing":
				data = append(data, []byte(` {}`)...)
			case "oversize":
				data = bytes.Repeat([]byte(" "), MaxBytes+1)
			case "surrogate":
				data = bytes.Replace(data, []byte(`"requestId":"`+request+`"`), []byte(`"requestId":"\ud800"`), 1)
			}
			if _, err := VerifyStatus(data, c, m, der, now); err == nil {
				t.Fatal("invalid status accepted")
			}
		})
	}
	if (VerifiedStatus{}).Valid() {
		t.Fatal("zero proof accepted")
	}
}
