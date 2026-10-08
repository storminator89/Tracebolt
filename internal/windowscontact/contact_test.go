package windowscontact

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
var epochA = strings.Repeat("a", 32)
var epochB = strings.Repeat("b", 32)

func input(at time.Time) Input {
	return Input{DeviceID: "agent_" + strings.Repeat("1", 32), Authorized: true, AuthorityUntil: base.Add(365 * 24 * time.Hour), ReceivedAt: at, Sequence: 1, InvitationID: "invite_" + strings.Repeat("1", 32), CertificateHash: strings.Repeat("2", 64)}
}
func evaluate(t *testing.T, s *State, in Input, at time.Time) {
	t.Helper()
	if err := s.Evaluate(in, at, epochA); err != nil {
		t.Fatal(err, s)
	}
	if err := s.Validate(); err != nil {
		t.Fatal("invalid evaluation", err, s)
	}
}
func openState(t *testing.T) (State, Input, time.Time) {
	t.Helper()
	s, in := New(), input(base)
	at := base.Add(121 * time.Second)
	for i := 0; i <= 2; i++ {
		evaluate(t, &s, in, at.Add(time.Duration(i)*Interval))
	}
	if s.Status != "overdue" || len(s.Incidents) != 1 {
		t.Fatal(s)
	}
	return s, in, at.Add(2 * Interval)
}

func TestAgeAndConfirmationExactBoundaries(t *testing.T) {
	s, in := New(), input(base)
	evaluate(t, &s, in, base.Add(MaxAge))
	if s.Status != "recent" {
		t.Fatal("exact age must remain recent", s)
	}
	evaluate(t, &s, in, base.Add(MaxAge+time.Nanosecond))
	if s.Status != "pending" {
		t.Fatal("strict age boundary", s)
	}
	pending := *s.PendingSince
	evaluate(t, &s, in, pending.Add(Confirmation-time.Nanosecond))
	if len(s.Incidents) != 0 {
		t.Fatal("confirmed early")
	}
	evaluate(t, &s, in, pending.Add(Confirmation))
	if s.Status != "overdue" || len(s.Incidents) != 1 || !s.Incidents[0].LastAcceptedAt.Equal(base) || s.Incidents[0].Sequence != 1 || !s.Incidents[0].LastConfirmedAt.Equal(pending.Add(Confirmation)) {
		t.Fatal(s)
	}
	for i := 1; i < 30; i++ {
		evaluate(t, &s, in, pending.Add(Confirmation+time.Duration(i)*Interval))
	}
	if len(s.Incidents) != 1 || s.NextID != 1 || !s.LastAcceptedAt.Equal(base) {
		t.Fatal("duplicate created incident/refreshed receipt", s)
	}
}

func TestDuplicateReceiptAndRecoveryEvidence(t *testing.T) {
	s, in, at := openState(t)
	recovered := in
	recovered.Sequence++
	recovered.ReceivedAt = at.Add(Interval)
	evaluate(t, &s, recovered, recovered.ReceivedAt)
	if s.Status != "overdue" || s.RecoverySince == nil {
		t.Fatal(s)
	}
	// Re-evaluations confirm continuous fresh status, not an invented new receipt.
	evaluate(t, &s, recovered, recovered.ReceivedAt.Add(Confirmation-time.Nanosecond))
	if s.Incidents[0].ResolvedAt != nil {
		t.Fatal("early recovery")
	}
	evaluate(t, &s, recovered, recovered.ReceivedAt.Add(Confirmation))
	x := s.Incidents[0]
	if s.Status != "recent" || x.ResolvedAt == nil || x.ClosedReason != "reports-resumed" || !x.LastAcceptedAt.Equal(base) || !x.RecoveryAcceptedAt.Equal(recovered.ReceivedAt) || x.RecoverySequence != 2 || !s.LastAcceptedAt.Equal(recovered.ReceivedAt) {
		t.Fatal(s)
	}
	// Old retries do not refresh a receipt even if a caller incorrectly updates its time.
	retry := recovered
	retry.ReceivedAt = recovered.ReceivedAt.Add(time.Minute)
	evaluate(t, &s, retry, recovered.ReceivedAt.Add(90*time.Second))
	if s.Status != "unknown" || !s.LastAcceptedAt.Equal(recovered.ReceivedAt) {
		t.Fatal(s)
	}
	// Freshness must hold for the whole recovery duration.
	s, in, at = openState(t)
	in.Sequence++
	in.ReceivedAt = at
	evaluate(t, &s, in, at.Add(100*time.Second))
	evaluate(t, &s, in, at.Add(130*time.Second))
	if s.RecoverySince != nil || s.Incidents[0].ResolvedAt != nil {
		t.Fatal("stale recovery", s)
	}
}

func TestRecoveryCannotBridgeUnobservedStaleReceiptInterval(t *testing.T) {
	for _, tc := range []struct {
		name       string
		receiptGap time.Duration
		reset      bool
	}{
		{"exact-120-second-receipt-gap", MaxAge, false},
		{"120-seconds-plus-nanosecond", MaxAge + time.Nanosecond, true},
		{"reviewer-stale-gap", 159 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, in, opened := openState(t)
			in.Sequence++
			in.ReceivedAt = opened
			firstRecoveryEvaluation := opened.Add(100 * time.Second)
			evaluate(t, &s, in, firstRecoveryEvaluation)
			if s.RecoverySince == nil || !s.RecoverySince.Equal(firstRecoveryEvaluation) {
				t.Fatal(s)
			}
			in.Sequence++
			in.ReceivedAt = opened.Add(tc.receiptGap)
			secondEvaluation := firstRecoveryEvaluation.Add(Confirmation)
			evaluate(t, &s, in, secondEvaluation)
			if !tc.reset {
				if s.Status != "recent" || s.Incidents[0].ResolvedAt == nil {
					t.Fatal("exact freshness boundary reset continuous recovery", s)
				}
				return
			}
			if s.Status != "overdue" || s.Incidents[0].ResolvedAt != nil || s.RecoverySince == nil || !s.RecoverySince.Equal(secondEvaluation) {
				t.Fatal("recovery bridged unobserved stale period", s)
			}
			evaluate(t, &s, in, secondEvaluation.Add(Confirmation-time.Nanosecond))
			if s.Incidents[0].ResolvedAt != nil {
				t.Fatal("new recovery window resolved early")
			}
			evaluate(t, &s, in, secondEvaluation.Add(Confirmation))
			if s.Status != "recent" || s.Incidents[0].ResolvedAt == nil {
				t.Fatal("fresh 60-second replacement window did not recover", s)
			}
		})
	}
}

func TestGapRollbackRestartAndUnauthorizedReset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*State, Input, time.Time) error
	}{
		{"gap", func(s *State, in Input, at time.Time) error {
			return s.Evaluate(in, at.Add(MaxGap+time.Nanosecond), epochA)
		}},
		{"rollback", func(s *State, in Input, at time.Time) error { return s.Evaluate(in, at.Add(-time.Nanosecond), epochA) }},
		{"restart", func(s *State, in Input, at time.Time) error { return s.Evaluate(in, at.Add(Interval), epochB) }},
		{"unauthorized", func(s *State, in Input, at time.Time) error {
			in.Authorized = false
			return s.Evaluate(in, at.Add(Interval), epochA)
		}},
		{"expired", func(s *State, in Input, at time.Time) error {
			in.AuthorityUntil = at.Add(Interval)
			return s.Evaluate(in, at.Add(Interval), epochA)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, in := New(), input(base)
			at := base.Add(121 * time.Second)
			evaluate(t, &s, in, at)
			if err := tc.apply(&s, in, at); err != nil {
				t.Fatal(err)
			}
			if len(s.Incidents) != 0 || s.RecoverySince != nil || s.PendingSince != nil && !s.PendingSince.After(at) {
				t.Fatal("pending duration survived discontinuity", s)
			}
			s, in, at = openState(t)
			in.Sequence++
			in.ReceivedAt = at.Add(Interval)
			evaluate(t, &s, in, in.ReceivedAt)
			if err := tc.apply(&s, in, in.ReceivedAt); err != nil {
				t.Fatal(err)
			}
			if len(s.Incidents) != 1 || s.Incidents[0].ResolvedAt != nil {
				t.Fatal("history erased/resolved", s)
			}
			if err := s.Validate(); err != nil {
				t.Fatal(err, s)
			}
		})
	}
	// Exactly 90 seconds is a permitted evaluator gap.
	s, in := New(), input(base)
	evaluate(t, &s, in, base.Add(121*time.Second))
	evaluate(t, &s, in, base.Add(211*time.Second))
	if s.Status != "overdue" {
		t.Fatal("exact gap was reset", s)
	}
}

func TestViewReadOnlyRestartExpiryAndCurrentReceipt(t *testing.T) {
	s, in, at := openState(t)
	before, _ := Encode(s)
	if got := s.View(in, at, epochB); got.Status != "unknown" || len(got.Incidents) != 1 {
		t.Fatal(got)
	}
	if got := s.View(in, at.Add(MaxAge), epochA); got.Status != "overdue" {
		t.Fatal(got)
	}
	if got := s.View(in, at.Add(MaxAge+time.Nanosecond), epochA); got.Status != "unknown" {
		t.Fatal(got)
	}
	for _, change := range []func(*Input){func(i *Input) { i.Authorized = false }, func(i *Input) { i.AuthorityUntil = at }} {
		x := in
		change(&x)
		if got := s.View(x, at, epochA); got.Status != "unknown" || len(got.Incidents) != 1 {
			t.Fatal(got)
		}
	}
	in.Sequence++
	in.ReceivedAt = at.Add(time.Second)
	v := s.View(in, in.ReceivedAt, epochA)
	if v.Status != "unknown" || v.Sequence != in.Sequence || !v.LastAcceptedAt.Equal(in.ReceivedAt) || !v.CertificateExpiresAt.Equal(in.AuthorityUntil) {
		t.Fatal(v)
	}
	raw, _ := json.Marshal(v)
	for _, secret := range []string{in.CertificateHash, in.InvitationID, epochA, "pendingSince", "recoverySince"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("private state leaked: %s", secret)
		}
	}
	v.Incidents[0].ID = "changed"
	*v.LastAcceptedAt = base.Add(time.Hour)
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("GET/view mutated durable state")
	}
}

func TestIdentityMissingFutureAndRegressedReceipt(t *testing.T) {
	for _, change := range []func(*Input){func(i *Input) { i.InvitationID = ""; i.CertificateHash = "" }, func(i *Input) { i.CertificateHash = "bad" }, func(i *Input) { i.AuthorityUntil = time.Time{} }, func(i *Input) { i.DeviceID = "bad id" }, func(i *Input) { i.Sequence = MaxCounter + 1 }} {
		s, in := New(), input(base)
		change(&in)
		before := s
		if s.Evaluate(in, base, epochA) == nil || !reflect.DeepEqual(before, s) {
			t.Fatal("invalid input mutated state", s)
		}
	}
	for _, change := range []func(*Input){func(i *Input) { i.ReceivedAt = base.Add(time.Hour) }, func(i *Input) { i.ReceivedAt = time.Time{}; i.Sequence = 0 }, func(i *Input) { i.Sequence = 0 }, func(i *Input) { i.Sequence = 2; i.ReceivedAt = base.Add(-time.Second) }} {
		s, in := New(), input(base)
		evaluate(t, &s, in, base)
		change(&in)
		evaluate(t, &s, in, base.Add(Interval))
		if s.Status != "unknown" || !s.LastAcceptedAt.Equal(base) || s.Sequence != 1 {
			t.Fatal("receipt evidence lost", s)
		}
	}
	s, in, at := openState(t)
	in.InvitationID = "invite_" + strings.Repeat("4", 32)
	in.CertificateHash = strings.Repeat("5", 64)
	in.Sequence = 1
	in.ReceivedAt = at.Add(Interval)
	before, _ := Encode(s)
	if err := s.Evaluate(in, in.ReceivedAt, epochA); err != ErrInvalid {
		t.Fatal("identity change accepted", err)
	}
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("identity change mutated old authority history")
	}
	if got := s.View(in, in.ReceivedAt, epochA); got.Status != "unknown" || len(got.Incidents) != 0 || got.EvaluatedAt != nil {
		t.Fatal("old authority history transferred", got)
	}
}

func TestPruningKeepsOpenBoundedHistoryAndIndependentIDs(t *testing.T) {
	s, in, at := openState(t)
	for n := 0; n < 110; n++ {
		in.Sequence++
		in.ReceivedAt = at.Add(Interval)
		at = in.ReceivedAt
		evaluate(t, &s, in, at)
		evaluate(t, &s, in, at.Add(Interval))
		at = at.Add(Confirmation)
		evaluate(t, &s, in, at)
		at = in.ReceivedAt.Add(MaxAge + time.Second)
		evaluate(t, &s, in, at)
		evaluate(t, &s, in, at.Add(Interval))
		at = at.Add(Confirmation)
		evaluate(t, &s, in, at)
	}
	if len(s.Incidents) != MaxIncidents || s.NextID != 111 || s.Incidents[0].ResolvedAt != nil || !strings.HasPrefix(s.Incidents[0].ID, "wcontact_") {
		t.Fatal(s)
	}
	evaluate(t, &s, in, at.Add(Retention+time.Second))
	if len(s.Incidents) != 1 || s.Incidents[0].ResolvedAt != nil {
		t.Fatal("open retention", s)
	}
	if raw, err := Encode(s); err != nil || len(raw) > MaxStateBytes {
		t.Fatal(err)
	}
}

func TestStrictCanonicalSerializationAndCorruption(t *testing.T) {
	s, _, _ := openState(t)
	raw, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil || !reflect.DeepEqual(s, got) {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte(`{"version":1}`), append(append([]byte{}, raw...), ' '), append([]byte(" "), raw...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1), bytes.Replace(raw, []byte("wcontact_0000000000000001"), []byte("health_0000000000000001"), 1), bytes.Repeat([]byte("x"), MaxStateBytes+1), append(append([]byte{}, raw...), raw...)} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("accepted corruption: %.100s", bad)
		}
	}
	for _, change := range []func(*State){func(x *State) { x.Version = 2 }, func(x *State) { x.Incidents = append(x.Incidents, x.Incidents[0]) }, func(x *State) { x.Status = "offline" }, func(x *State) { x.Incidents[0].LastConfirmedAt = base }, func(x *State) { x.Sequence = 0 }, func(x *State) { x.Epoch = "" }, func(x *State) { x.InvitationID = ""; x.CertificateHash = "" }, func(x *State) { x.Incidents[0].ResolvedAt = stamp(base) }, func(x *State) { x.RecoverySince = stamp(base.Add(24 * time.Hour)) }} {
		x := s
		x.Incidents = append([]Incident{}, s.Incidents...)
		change(&x)
		if x.Validate() == nil {
			t.Fatal("accepted invalid state", x)
		}
	}
}

func TestIncidentLimitOverflowDoesNotPartiallyMutate(t *testing.T) {
	s, in := New(), input(base)
	evaluate(t, &s, in, base.Add(121*time.Second))
	s.NextID = MaxCounter
	before, _ := Encode(s)
	if s.Evaluate(in, base.Add(181*time.Second), epochA) == nil {
		t.Fatal("overflow accepted")
	}
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("failed evaluation mutated ledger")
	}
}
