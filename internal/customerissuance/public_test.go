package customerissuance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func publicFixture(t *testing.T) (Intent, PublicIntent, LocalPublicBinding, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	issuer, _ := certificateFixture(t, now)
	a := approvalFixture(t, now, issuer)
	i, err := Build(a, ids("intent", "8"), strings.Repeat("9", 32), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ProjectPublic(i)
	if err != nil {
		t.Fatal(err)
	}
	o := i.Approval.Candidate.Pending
	b := LocalPublicBinding{ManagerID: o.ManagerID, CustomerID: o.CustomerID, InstallerProfileID: o.InstallerProfileID, ClaimID: o.ClaimID, IssuerFingerprint: o.IssuerFingerprint, Origin: o.Origin, AgentOrigin: o.AgentOrigin, DeadlineAt: o.DeadlineAt, PublicKeyDER: bytes.Clone(o.PublicKeyDER)}
	return i, p, b, now
}

func TestPublicProjectionCanonicalAndPrivateFieldsExcluded(t *testing.T) {
	i, p, b, now := publicFixture(t)
	if err := MatchLocalPublic(p, b, now); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(i)
	if err != nil || digest != p.IntentDigest || p.IntentID != i.IntentID {
		t.Fatal("wrong original digest", err)
	}
	raw, err := CanonicalPublic(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"actor", "customerRevision", "operationId", "csr", "publicKeyDer", "requestId", "comparisonCode", "managerDigest"} {
		if bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(s))) {
			t.Fatalf("private field %s included", s)
		}
	}
	parsed, err := ParsePublic(raw)
	if err != nil || parsed != p {
		t.Fatal("canonical roundtrip", err)
	}
	for _, bad := range [][]byte{append([]byte(" "), raw...), append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"version":`), []byte(`"unknown":1,"version":`), 1), bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"duplicate","version":`), 1), bytes.Repeat([]byte{'x'}, maxPublicBytes+1)} {
		if _, err := ParsePublic(bad); err == nil {
			t.Fatal("noncanonical encoding accepted")
		}
	}
	// The old unexposed fixture shape is not silently adopted as the new one.
	old := bytes.Replace(raw, []byte(`"version":"`+PublicVersion+`","intentId":"`+p.IntentID+`",`), []byte(`"version":"tracebolt.customer-windows-public-intent.v1",`), 1)
	if bytes.Equal(old, raw) {
		t.Fatal("fixture failed to construct the old shape")
	}
	if _, err := ParsePublic(old); err == nil {
		t.Fatal("old projection accepted without intent ID")
	}
	field := []byte(`"intentId":"` + p.IntentID + `",`)
	for _, invalid := range [][]byte{bytes.Replace(raw, field, nil, 1), bytes.Replace(raw, field, append(bytes.Clone(field), field...), 1)} {
		if _, err := ParsePublic(invalid); err == nil {
			t.Fatal("missing or duplicate intent ID accepted")
		}
	}
}

func TestPublicProjectionRejectsInvalidValues(t *testing.T) {
	_, base, _, _ := publicFixture(t)
	for name, edit := range map[string]func(*PublicIntent){
		"transport": func(p *PublicIntent) { p.TransportProfile = "http" },
		"origin":    func(p *PublicIntent) { p.Origin = "http://manager.example.test" },
		"userinfo":  func(p *PublicIntent) { p.AgentOrigin = "https://u@agent.example.test" },
		"bad scope": func(p *PublicIntent) { p.CollectionProfile = "other" },
		"template":  func(p *PublicIntent) { p.TemplateVersion = "other" },
		"digest":    func(p *PublicIntent) { p.IntentDigest = "BAD" },
		"intent id": func(p *PublicIntent) { p.IntentID = "intent_bad" },
		"serial":    func(p *PublicIntent) { p.SerialHex = strings.Repeat("0", 32) },
		"deadline":  func(p *PublicIntent) { p.DeadlineAt = p.NotBefore },
		"duration":  func(p *PublicIntent) { p.NotAfter = p.NotBefore + int64(MaxLifetime/time.Second) + 1 },
		"device":    func(p *PublicIntent) { p.DeviceID = "agent_bad" },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			edit(&p)
			if _, err := CanonicalPublic(p); err == nil {
				t.Fatal("invalid projection accepted")
			}
			raw, _ := json.Marshal(p)
			if _, err := ParsePublic(raw); err == nil {
				t.Fatal("invalid input parsed")
			}
		})
	}
}

func TestMatchLocalPublicRejectsSubstitutionAndExpiry(t *testing.T) {
	_, base, b, now := publicFixture(t)
	for name, edit := range map[string]func(*PublicIntent){
		"manager": func(p *PublicIntent) { p.ManagerID = ids("manager", "a") }, "customer": func(p *PublicIntent) { p.CustomerID = ids("customer", "a") }, "profile": func(p *PublicIntent) { p.InstallerProfileID = ids("profile", "a") }, "claim": func(p *PublicIntent) { p.ClaimID = ids("claim", "a") }, "issuer": func(p *PublicIntent) { p.IssuerFingerprint = strings.Repeat("a", 64) }, "origin": func(p *PublicIntent) { p.Origin = "https://other.example.test" }, "agent origin": func(p *PublicIntent) { p.AgentOrigin = "https://other.example.test" }, "key": func(p *PublicIntent) { p.KeyFingerprint = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			edit(&p)
			if MatchLocalPublic(p, b, now) == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	bad := b
	for _, deadline := range []int64{0, b.DeadlineAt - 1, b.DeadlineAt + 1} {
		other := b
		other.DeadlineAt = deadline
		if MatchLocalPublic(base, other, now) == nil {
			t.Fatal("different original deadline accepted")
		}
	}
	bad.PublicKeyDER = bytes.Clone(b.PublicKeyDER)
	bad.PublicKeyDER[0] ^= 1
	if MatchLocalPublic(base, bad, now) == nil {
		t.Fatal("bad local key accepted")
	}
	for _, when := range []time.Time{time.Unix(base.NotBefore-1, 0), time.Unix(base.NotAfter, 0), time.Unix(base.DeadlineAt, 0), time.Time{}} {
		if MatchLocalPublic(base, b, when) == nil {
			t.Fatal("out-of-window accepted")
		}
	}
}
