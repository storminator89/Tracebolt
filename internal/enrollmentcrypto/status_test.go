package enrollmentcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func statusFixture(t *testing.T, c ChallengeContext, purpose string, now time.Time) ([]byte, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("key fixture")
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal("public fixture")
	}
	request := testID("request_", 12)
	msg, e := StatusSigningMessage(c, purpose, request, der, now)
	if e != nil {
		t.Fatal("message fixture")
	}
	body := map[string]string{"schemaVersion": StatusVersion, "managerInstanceId": c.ManagerInstanceID, "profile": c.Profile, "origin": c.Origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "keyFingerprint": hash(der), "requestId": request, "purpose": purpose, "challenge": c.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, msg))}
	raw, _ := json.Marshal(body)
	return raw, der
}
func TestStatusProofPurposeAndContext(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, profile := range []string{"tls", "http-test"} {
		for _, purpose := range []string{PurposeStatus, PurposeCredential} {
			c := contextFixture(profile, now)
			raw, der := statusFixture(t, c, purpose, now)
			v, e := VerifyStatus(raw, der, c, now)
			if e != nil || !v.Valid() || v.InstanceID() != c.ManagerInstanceID || v.ManagerInstanceID() != c.ManagerInstanceID || v.Profile() != profile || v.Origin() != c.Origin || v.CollectionProfile() != c.CollectionProfile || v.InvitationID() != c.InvitationID || v.ClaimID() != c.ClaimID || v.KeyFingerprint() != hash(der) || v.RequestID() != testID("request_", 12) || v.Purpose() != purpose || v.ExpiresAt() != c.ExpiresAt {
				t.Fatal("valid status proof failed")
			}
			var body map[string]string
			json.Unmarshal(raw, &body)
			for _, field := range []string{"purpose", "requestId", "origin", "profile", "claimId", "invitationId", "keyFingerprint", "challenge", "schemaVersion", "collectionProfile", "managerInstanceId"} {
				clone := map[string]string{}
				for k, value := range body {
					clone[k] = value
				}
				clone[field] += "x"
				altered, _ := json.Marshal(clone)
				if _, e := VerifyStatus(altered, der, c, now); e == nil {
					t.Fatal("altered field accepted", field)
				}
			}
			other := c
			other.ExpiresAt++
			if _, e := VerifyStatus(raw, der, other, now); e == nil {
				t.Fatal("changed expiry accepted")
			}
			if _, e := VerifyStatus(raw, der, c, time.Unix(c.ExpiresAt, 0)); e == nil {
				t.Fatal("expired proof accepted")
			}
			_, different := statusFixture(t, c, purpose, now)
			if _, e := VerifyStatus(raw, different, c, now); e == nil {
				t.Fatal("wrong stored key accepted")
			}
			for _, value := range []any{v, &v} {
				b, _ := json.Marshal(value)
				if bytes.Contains(b, []byte(v.RequestID())) {
					t.Fatal("JSON proof metadata exposed")
				}
				for _, format := range []string{"%v", "%+v", "%#v"} {
					if strings.Contains(fmt.Sprintf(format, value), v.RequestID()) {
						t.Fatal("proof metadata exposed")
					}
				}
			}
		}
	}
	if (VerifiedStatus{}).Valid() {
		t.Fatal("empty proof valid")
	}
}
func TestStatusStrictContract(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := contextFixture("tls", now)
	raw, der := statusFixture(t, c, PurposeStatus, now)
	for _, bad := range [][]byte{nil, []byte(`null`), append(bytes.Clone(raw), 'x'), bytes.Replace(raw, []byte(`"purpose":"status"`), []byte(`"purpose":"status","purpose":"credential"`), 1), bytes.Replace(raw, []byte(`"purpose":"status"`), []byte(`"purpose":null`), 1), bytes.Replace(raw, []byte(`"purpose":"status"`), []byte(`"purpose":"status","extra":"x"`), 1)} {
		if _, e := VerifyStatus(bad, der, c, now); e == nil {
			t.Fatal("ambiguous status contract accepted")
		}
	}
	for _, purpose := range []string{"", "activate", "STATUS"} {
		if _, e := StatusSigningMessage(c, purpose, testID("request_", 12), der, now); e == nil {
			t.Fatal("unknown purpose accepted")
		}
	}
	if _, e := VerifyStatus(raw, append(der, 0), c, now); e == nil {
		t.Fatal("noncanonical public material accepted")
	}
}
