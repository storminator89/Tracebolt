package journalrequest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalview"
)

func generationFixture(t *testing.T) Record {
	t.Helper()
	d := fixture(t).Description
	r, err := NewWithGeneration(d.DeviceID, d.CertificateHash, d.Identity.Sequence, d.Query, journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}, d.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestRequestGenerationPreservesLegacyCanonicalBytesAndComparableDescriptions(t *testing.T) {
	r := fixture(t)
	d := r.Description
	raw, err := json.Marshal(d)
	if err != nil || bytes.Contains(raw, []byte("policyGeneration")) {
		t.Fatal("legacy encoding gained generation")
	}
	// The old query digest's precise domain/field order/reader limits are fixed.
	legacyDigestBytes, _ := json.Marshal(struct {
		Domain  string            `json:"domain"`
		Query   journalview.Query `json:"query"`
		Budgets Budgets           `json:"budgets"`
	}{SchemaVersion, d.Query, FixedBudgets()})
	sum := sha256.Sum256(legacyDigestBytes)
	if d.Identity.QueryDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("legacy digest changed")
	}
	v2 := generationFixture(t)
	if Validate(v2) != nil {
		t.Fatal("v2 record invalid")
	}
	b, _ := json.Marshal(v2)
	var restored Record
	if json.Unmarshal(b, &restored) != nil || Validate(restored) != nil || restored.Description != v2.Description {
		t.Fatal("v2 comparable roundtrip failed")
	}
	if restored.Description.ExpiresAt.Sub(restored.Description.CreatedAt) != Lifetime || restored.Description.Budgets != d.Budgets || restored.Description.Identity.Sequence != d.Identity.Sequence {
		t.Fatal("v2 altered expiry, budgets or shared sequence")
	}
	g := v2.Description.PolicyGeneration
	if digest, _ := QueryDigestWithGeneration(d.Query, g, d.CreatedAt); digest == d.Identity.QueryDigest {
		t.Fatal("generation digest aliases legacy domain")
	}
	g.Revision++
	if restored.Description.PolicyGeneration == g {
		t.Fatal("description shares caller tuple")
	}
	if _, err := NewWithGeneration(d.DeviceID, d.CertificateHash, d.Identity.Sequence, d.Query, journalgeneration.Tuple{}, d.CreatedAt); err == nil {
		t.Fatal("v2 empty tuple accepted")
	}
}
func TestRequestDigestBindsEveryGenerationAndQueryDimension(t *testing.T) {
	r := generationFixture(t)
	d := r.Description
	for _, mutate := range []func(*journalgeneration.Tuple){func(g *journalgeneration.Tuple) { g.Revision++ }, func(g *journalgeneration.Tuple) { g.Generation = strings.Repeat("c", 64) }, func(g *journalgeneration.Tuple) { g.PolicyDigest = "sha256:" + strings.Repeat("d", 64) }} {
		g := d.PolicyGeneration
		mutate(&g)
		digest, err := QueryDigestWithGeneration(d.Query, g, d.CreatedAt)
		if err != nil || digest == d.Identity.QueryDigest {
			t.Fatal("generation dimension not bound")
		}
		bad := r
		bad.Description.PolicyGeneration = g
		if Validate(bad) == nil {
			t.Fatal("request rebound without digest change")
		}
	}
	for _, mutate := range []func(*journalview.Query){func(q *journalview.Query) { q.Unit = "other.service" }, func(q *journalview.Query) { q.Start = q.Start.Add(time.Microsecond) }, func(q *journalview.Query) { q.End = q.End.Add(-time.Microsecond) }, func(q *journalview.Query) { q.MaxPriority-- }} {
		q := d.Query
		mutate(&q)
		digest, err := QueryDigestWithGeneration(q, d.PolicyGeneration, d.CreatedAt)
		if err != nil || digest == d.Identity.QueryDigest {
			t.Fatal("query dimension not bound")
		}
	}
	for _, mutate := range []func(*Record){func(r *Record) { r.Description.SchemaVersion = SchemaVersion }, func(r *Record) { r.Description.PolicyGeneration = journalgeneration.Tuple{} }, func(r *Record) { r.Description.Identity.Sequence = 0 }, func(r *Record) { r.Description.Budgets.MaxRows++ }, func(r *Record) { r.Description.ExpiresAt = r.Description.ExpiresAt.Add(time.Second) }, func(r *Record) { r.Description.Query.Unit = "kernel" }} {
		bad := r
		mutate(&bad)
		if Validate(bad) == nil {
			t.Fatal("v2 downgrade or expanded contract accepted")
		}
	}
	legacy := fixture(t)
	legacy.Description.PolicyGeneration = d.PolicyGeneration
	if Validate(legacy) == nil {
		t.Fatal("generation smuggled into legacy request")
	}
}
func TestRequestGenerationClaimReceiptAndTerminalExpiryAreExact(t *testing.T) {
	r := generationFixture(t)
	d := r.Description
	claimAt := d.CreatedAt.Add(time.Second)
	r.State, r.PolicyDigest, r.ClaimedAt = Claimed, d.PolicyGeneration.PolicyDigest, &claimAt
	if Validate(r) != nil {
		t.Fatal("bound claim failed")
	}
	r.PolicyDigest = "sha256:" + strings.Repeat("e", 64)
	if Validate(r) == nil {
		t.Fatal("claim switched policies after creation")
	}
	r.PolicyDigest = d.PolicyGeneration.PolicyDigest
	acceptedAt := claimAt.Add(time.Second)
	r.State = Accepted
	r.Receipt = &Receipt{Identity: d.Identity, PolicyDigest: r.PolicyDigest, ResultDigest: "sha256:" + strings.Repeat("f", 64), AcceptedAt: acceptedAt, ExpiresAt: d.ExpiresAt}
	if Validate(r) != nil {
		t.Fatal("bound result failed")
	}
	r.Receipt.ExpiresAt = r.Receipt.ExpiresAt.Add(time.Second)
	if Validate(r) == nil {
		t.Fatal("receipt extended expiry")
	}
	r.Receipt.ExpiresAt = d.ExpiresAt
	expireAt := d.ExpiresAt
	r.State = Expired
	r.ExpiredAt = &expireAt
	if Validate(r) != nil || CheckTime(r, d.CreatedAt) != ErrExpired {
		t.Fatal("expired generation revived by clock rollback")
	}
	if r.Description.Identity.Sequence != d.Identity.Sequence || r.Description.PolicyGeneration != d.PolicyGeneration {
		t.Fatal("terminal metadata lost identity or generation")
	}
}
func TestNestedGenerationRejectsMalformedAndDuplicateJSON(t *testing.T) {
	r := generationFixture(t)
	raw, _ := json.Marshal(r)
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"policyGeneration":{`), []byte(`"policyGeneration":{"revision":"1",`), 1), bytes.Replace(raw, []byte(`"policyGeneration":{`), []byte(`"policyGeneration":{"scope":"system",`), 1), bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":1`), 1), bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":"01"`), 1), bytes.Replace(raw, []byte(`"revision":"1",`), nil, 1)} {
		var restored Record
		if json.Unmarshal(bad, &restored) == nil {
			t.Fatal("malformed nested tuple accepted")
		}
	}
}
