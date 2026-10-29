package customerv3proof

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
)

func publicProofFixture(t *testing.T) (fixture, customerissuance.PublicIntent, customerissuance.LocalPublicBinding, string) {
	t.Helper()
	f := makeFixture(t)
	p, e := customerissuance.ProjectPublic(f.i)
	if e != nil {
		t.Fatal(e)
	}
	pending := f.i.Approval.Candidate.Pending
	b := customerissuance.LocalPublicBinding{ManagerID: pending.ManagerID, CustomerID: pending.CustomerID, InstallerProfileID: pending.InstallerProfileID, ClaimID: pending.ClaimID, IssuerFingerprint: pending.IssuerFingerprint, Origin: pending.Origin, AgentOrigin: pending.AgentOrigin, DeadlineAt: pending.DeadlineAt, PublicKeyDER: bytes.Clone(pending.PublicKeyDER)}
	return f, p, b, pending.ClaimHash
}

func TestPublicMessageMatchesServerTranscript(t *testing.T) {
	f, p, b, claimHash := publicProofFixture(t)
	req := id("request", "a")
	for _, test := range []struct {
		purpose Purpose
		hash    string
	}{{Credential, ""}, {Activation, f.cert.CertificateHash()}} {
		server, e := SigningMessage(f.i, test.purpose, f.c, req, test.hash, f.now)
		if e != nil {
			t.Fatal(e)
		}
		client, e := SigningMessagePublic(p, b, claimHash, test.purpose, f.c, req, test.hash, f.now)
		if e != nil || !bytes.Equal(server, client) {
			t.Fatal("different transcript", e)
		}
		if e = Verify(f.i, f.cert, test.purpose, f.c, req, ed25519.Sign(f.key, client), f.now); e != nil {
			t.Fatal("server rejected client proof", e)
		}
	}
}

func TestPublicMessageRejectsSubstitutionsAndExpiry(t *testing.T) {
	f, p, b, h := publicProofFixture(t)
	req := id("request", "a")
	for name, edit := range map[string]func(*customerclaim.Context){"manager": func(c *customerclaim.Context) { c.ManagerID = id("manager", "a") }, "customer": func(c *customerclaim.Context) { c.CustomerID = id("customer", "a") }, "profile": func(c *customerclaim.Context) { c.InstallerProfileID = id("profile", "a") }, "claim": func(c *customerclaim.Context) { c.ClaimID = id("claim", "a") }, "origin": func(c *customerclaim.Context) { c.Origin = "https://other.example.test" }, "issuer": func(c *customerclaim.Context) { c.IssuerFingerprint = strings.Repeat("a", 64) }, "bad nonce": func(c *customerclaim.Context) { c.Challenge = "bad" }} {
		t.Run(name, func(t *testing.T) {
			c := f.c
			edit(&c)
			if _, e := SigningMessagePublic(p, b, h, Credential, c, req, "", f.now); e == nil {
				t.Fatal("invalid challenge accepted")
			}
		})
	}
	changed := b
	changed.CustomerID = id("customer", "a")
	if _, e := SigningMessagePublic(p, changed, h, Credential, f.c, req, "", f.now); e == nil {
		t.Fatal("different local profile accepted")
	}
	changed = b
	changed.PublicKeyDER = bytes.Clone(b.PublicKeyDER)
	changed.PublicKeyDER[0] ^= 1
	if _, e := SigningMessagePublic(p, changed, h, Credential, f.c, req, "", f.now); e == nil {
		t.Fatal("different local key accepted")
	}
	for _, test := range []struct {
		purpose          Purpose
		hash, claim, req string
		now              time.Time
	}{{"other", "", h, req, f.now}, {Credential, f.cert.CertificateHash(), h, req, f.now}, {Activation, "", h, req, f.now}, {Credential, "", "bad", req, f.now}, {Credential, "", h, "bad", f.now}, {Credential, "", h, req, time.Unix(f.c.ExpiresAt, 0)}, {Credential, "", h, req, time.Unix(p.DeadlineAt, 0)}} {
		if _, e := SigningMessagePublic(p, b, test.claim, test.purpose, f.c, test.req, test.hash, test.now); e == nil {
			t.Fatal("invalid purpose, binding or time accepted")
		}
	}
	wrong := strings.Repeat("a", 64)
	if wrong == h {
		wrong = strings.Repeat("b", 64)
	}
	msg, e := SigningMessagePublic(p, b, wrong, Credential, f.c, req, "", f.now)
	if e != nil {
		t.Fatal(e)
	}
	if Verify(f.i, f.cert, Credential, f.c, req, ed25519.Sign(f.key, msg), f.now) == nil {
		t.Fatal("server accepted wrong protected claim hash")
	}
}
