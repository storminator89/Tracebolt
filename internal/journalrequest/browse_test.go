package journalrequest

import (
	"localrmm/internal/journalview"
	"testing"
	"time"
)

func TestBrowseRequestVersionDigestAndLifetime(t *testing.T) {
	legacy := generationFixture(t)
	d := legacy.Description
	q := d.Query
	q.BrowseMode = journalview.BrowseMode
	q.Start = time.Unix(0, 0).UTC()
	r, e := NewWithGeneration(d.DeviceID, d.CertificateHash, d.Identity.Sequence, q, d.PolicyGeneration, d.CreatedAt)
	if e != nil || Validate(r) != nil || r.Description.SchemaVersion != SchemaVersionV3 {
		t.Fatal("browse creation", e)
	}
	if !r.Description.ExpiresAt.Equal(d.CreatedAt.Add(Lifetime)) {
		t.Fatal("original expiry changed")
	}
	for _, mutate := range []func(*journalview.Query){func(q *journalview.Query) { q.Search = "literal" }, func(q *journalview.Query) { q.Cursor = "s=fixture;i=3" }} {
		changed := q
		mutate(&changed)
		digest, e := QueryDigestWithGeneration(changed, d.PolicyGeneration, d.CreatedAt)
		if e != nil || digest == r.Description.Identity.QueryDigest {
			t.Fatal("cursor/search missing from exact request binding")
		}
	}
	if _, e := New(d.DeviceID, d.CertificateHash, d.Identity.Sequence, q, d.CreatedAt); e == nil {
		t.Fatal("legacy authority admitted browse")
	}
	r.Description.SchemaVersion = SchemaVersionV2
	if Validate(r) == nil {
		t.Fatal("request downgrade admitted")
	}
}
