package journalrequest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalview"
)

func fixture(t *testing.T) Record {
	t.Helper()
	now := time.Unix(1800000010, 0).UTC()
	r, err := New("agent_"+strings.Repeat("1", 32), strings.Repeat("2", 64), 1, journalview.Query{Unit: "fixture.service", Start: now.Add(-time.Minute), End: now, MaxPriority: 6}, now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestQueryDigestExactAndBoundedRecord(t *testing.T) {
	r := fixture(t)
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if len(raw) > MaxRecordBytes {
		t.Fatal("record exceeds cap")
	}
	var restored Record
	if json.Unmarshal(raw, &restored) != nil || Validate(restored) != nil {
		t.Fatal("canonical reopen failed")
	}
	d := r.Description
	for _, change := range []func(*journalview.Query){
		func(q *journalview.Query) { q.Unit = "different.service" },
		func(q *journalview.Query) { q.Start = q.Start.Add(time.Microsecond) },
		func(q *journalview.Query) { q.End = q.End.Add(-time.Microsecond) },
		func(q *journalview.Query) { q.MaxPriority-- },
	} {
		q := d.Query
		change(&q)
		got, err := QueryDigest(q, d.CreatedAt)
		if err != nil || got == d.Identity.QueryDigest {
			t.Fatal("unbound query dimension", err)
		}
	}
	second := fixture(t)
	if second.Description.Identity.ID == d.Identity.ID {
		t.Fatal("request ID reused")
	}
}
func TestRecordValidationRejectsRebindingAndImpossibleStates(t *testing.T) {
	for name, change := range map[string]func(*Record){
		"budget":                 func(r *Record) { r.Description.Budgets.MaxRows++ },
		"query":                  func(r *Record) { r.Description.Query.Unit = "other.service" },
		"digest":                 func(r *Record) { r.Description.Identity.QueryDigest = "sha256:" + strings.Repeat("f", 64) },
		"floor":                  func(r *Record) { r.Description.Identity.Sequence = 0 },
		"expiry":                 func(r *Record) { r.Description.ExpiresAt = r.Description.ExpiresAt.Add(time.Second) },
		"claimed-without-proof":  func(r *Record) { r.State = Claimed },
		"accepted-without-claim": func(r *Record) { r.State = Accepted },
		"cancel-without-time":    func(r *Record) { r.State = Canceled },
		"pending-with-policy":    func(r *Record) { r.PolicyDigest = "sha256:" + strings.Repeat("1", 64) },
		"noncanonical-unit":      func(r *Record) { r.Description.Query.Unit = "*.service" },
		"submicrosecond":         func(r *Record) { r.Description.Query.Start = r.Description.Query.Start.Add(time.Nanosecond) },
		"unknown-state":          func(r *Record) { r.State = "run" },
	} {
		t.Run(name, func(t *testing.T) {
			r := fixture(t)
			change(&r)
			if Validate(r) == nil {
				t.Fatal("accepted malformed record")
			}
		})
	}
}
func TestResultLifecycleValidation(t *testing.T) {
	r := fixture(t)
	d := r.Description
	claimAt := d.CreatedAt.Add(time.Second)
	r.State, r.PolicyDigest, r.ClaimedAt = Claimed, "sha256:"+strings.Repeat("3", 64), &claimAt
	if Validate(r) != nil {
		t.Fatal("valid claim rejected")
	}
	r.Receipt = &Receipt{d.Identity, r.PolicyDigest, "sha256:" + strings.Repeat("4", 64), claimAt.Add(time.Second), d.ExpiresAt}
	r.State = Accepted
	if Validate(r) != nil {
		t.Fatal("valid accepted result rejected")
	}
	r.Receipt.ExpiresAt = r.Receipt.ExpiresAt.Add(time.Second)
	if Validate(r) == nil {
		t.Fatal("sliding receipt expiry accepted")
	}
	r.Receipt.ExpiresAt = d.ExpiresAt
	r.Receipt.AcceptedAt = d.ExpiresAt
	if Validate(r) == nil {
		t.Fatal("expired result accepted")
	}
	if CheckTime(fixture(t), d.ExpiresAt) != ErrExpired {
		t.Fatal("boundary not expired")
	}
}

func TestExpiredRecordRequiresDurableTerminalTime(t *testing.T) {
	r := fixture(t)
	r.State = Expired
	if Validate(r) == nil {
		t.Fatal("unlatched expired state accepted")
	}
	expiredAt := r.Description.ExpiresAt
	r.ExpiredAt = &expiredAt
	if Validate(r) != nil {
		t.Fatal("valid terminal expiry rejected")
	}
	if CheckTime(r, r.Description.CreatedAt) != ErrExpired {
		t.Fatal("terminal expiry reversed with clock")
	}
	expiredAt = expiredAt.Add(-time.Nanosecond)
	if Validate(r) == nil {
		t.Fatal("premature expiry latch accepted")
	}
	expiredAt = r.Description.ExpiresAt
	r.State = Pending
	if Validate(r) == nil {
		t.Fatal("pending state with expiry latch accepted")
	}
}
