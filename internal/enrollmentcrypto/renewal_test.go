package enrollmentcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"
)

func TestRenewalProofSeparatesIdentityGenerationPurposeAndShortChallenge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	base := contextFixture("tls", now)
	base.RenewalPolicy = RenewalPolicySameKey
	base.AgentOrigin = "https://agent.test"
	base.ExpiresAt = now.Unix() + 60
	c := RenewalContext{ChallengeContext: base, IdentityGeneration: testID("identity_", 8), CredentialGeneration: 2, CertificateHash: hash([]byte("cert")), DeviceID: testID("agent_", 9), KeyFingerprint: hash(der), Revision: 7, Purpose: PurposeRenewalIssue}
	request := testID("request_", 10)
	msg, e := RenewalSigningMessage(c, request, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := RenewalProofJSON(c, request, ed25519.Sign(key, msg))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyRenewal(raw, der, c, now); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"agentOrigin", "identityGeneration", "credentialGeneration", "certificateHash", "deviceId", "revision", "purpose", "requestId", "profile"} {
		t.Run(field, func(t *testing.T) {
			var body map[string]string
			json.Unmarshal(raw, &body)
			body[field] += "1"
			changed, _ := json.Marshal(body)
			if _, e := VerifyRenewal(changed, der, c, now); e == nil {
				t.Fatal("tampered proof accepted")
			}
		})
	}
	future := c
	future.ExpiresAt++
	if _, e = RenewalSigningMessage(future, request, now); e == nil {
		t.Fatal("challenge longer than 60 seconds")
	}
	if _, e = VerifyRenewal(raw, der, c, now.Add(60*time.Second)); e == nil {
		t.Fatal("expired challenge accepted")
	}
	http := c
	http.Profile = "http-test"
	http.Origin = "http://manager.test"
	if _, e = RenewalSigningMessage(http, request, now); e == nil {
		t.Fatal("HTTP renewal accepted")
	}
}
