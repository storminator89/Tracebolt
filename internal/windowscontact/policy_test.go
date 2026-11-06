package windowscontact

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func policyRequest(rev uint64, seconds int, id string) PolicyRequest {
	return PolicyRequest{ExpectedRevision: rev, GraceSeconds: seconds, RequestID: strings.Repeat(id, 32), Acknowledged: true}
}
func configure(t *testing.T, s *State, in Input, req PolicyRequest, at time.Time) {
	t.Helper()
	if err := s.Configure(in, req, at, epochA); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyLegacyBytesAndExplicitView(t *testing.T) {
	s := New()
	raw, _ := Encode(s)
	if string(raw) != `{"version":1,"deviceId":"","epoch":"","invitationId":"","certificateHash":"","status":"unknown","lastAcceptedAt":null,"sequence":0,"evaluatedAt":null,"pendingSince":null,"recoverySince":null,"incidents":[],"nextId":0}` {
		t.Fatal(string(raw))
	}
	in := input(base)
	evaluate(t, &s, in, base)
	v, _ := json.Marshal(s.View(in, base, epochA))
	if bytes.Contains(v, []byte("policy")) || !bytes.Contains(v, []byte("tracebolt.windows-contact-view.v1")) {
		t.Fatal(string(v))
	}
	configure(t, &s, in, policyRequest(0, 120, "a"), base)
	if s.Version != 2 || s.Status != "unknown" || s.PolicyRevision() != 1 || s.GraceSeconds() != 120 {
		t.Fatal(s)
	}
	v, _ = json.Marshal(s.View(in, base, epochA))
	for _, private := range []string{"lastRequest\"", "reportFloor", "acknowledged", "expectedRevision"} {
		if bytes.Contains(v, []byte(private)) {
			t.Fatal(string(v))
		}
	}
	if !bytes.Contains(v, []byte(`"awaitingFreshReport":true`)) || !bytes.Contains(v, []byte("tracebolt.windows-contact-view.v2")) {
		t.Fatal(string(v))
	}
	raw, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyGraceBoundariesAndPostChangeReport(t *testing.T) {
	for _, grace := range []int{120, 300, 900, 3600} {
		t.Run(time.Duration(grace).String(), func(t *testing.T) {
			s, in := New(), input(base)
			configure(t, &s, in, policyRequest(0, grace, "a"), base)
			for sec := 0; sec < grace+240; sec += 30 {
				evaluate(t, &s, in, base.Add(time.Duration(sec)*time.Second))
				if s.Status != "unknown" || len(s.Incidents) != 0 {
					t.Fatal("prechange receipt activated policy", s)
				}
			}
			at := base.Add(time.Duration(grace+300) * time.Second)
			in.Sequence++
			in.ReceivedAt = at
			evaluate(t, &s, in, at)
			if s.Status != "recent" || s.Policy.AwaitingFreshReport {
				t.Fatal(s)
			}
			for sec := 30; sec <= grace; sec += 30 {
				evaluate(t, &s, in, at.Add(time.Duration(sec)*time.Second))
				if sec <= 120 && s.Status != "recent" || sec > 120 && s.Status != "unknown" {
					t.Fatal("grace falsely fresh or early pending", sec, s)
				}
			}
			pending := at.Add(time.Duration(grace)*time.Second + time.Nanosecond)
			evaluate(t, &s, in, pending)
			if s.Status != "pending" {
				t.Fatal(s)
			}
			evaluate(t, &s, in, pending.Add(Confirmation-time.Nanosecond))
			if len(s.Incidents) != 0 {
				t.Fatal("early confirmation")
			}
			evaluate(t, &s, in, pending.Add(Confirmation))
			if len(s.Incidents) != 1 || s.Incidents[0].GraceSeconds != grace || s.Incidents[0].PolicyRevision != 1 {
				t.Fatal(s)
			}
		})
	}
}

func TestPolicyReplayConflictAndAuthorityAtomicity(t *testing.T) {
	s, in := New(), input(base)
	req := policyRequest(0, 300, "a")
	configure(t, &s, in, req, base)
	before, _ := Encode(s)
	configure(t, &s, in, req, base.Add(time.Second))
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("replay changed state")
	}
	for _, change := range []func(*PolicyRequest){func(r *PolicyRequest) { r.GraceSeconds = 900 }, func(r *PolicyRequest) { r.ExpectedRevision = 1 }, func(r *PolicyRequest) { r.Acknowledged = false }, func(r *PolicyRequest) { r.RequestID = strings.Repeat("0", 32) }, func(r *PolicyRequest) { r.GraceSeconds = 0 }} {
		bad := req
		change(&bad)
		if s.Configure(in, bad, base, epochA) == nil {
			t.Fatal("bad request accepted", bad)
		}
		after, _ = Encode(s)
		if !bytes.Equal(before, after) {
			t.Fatal("mutation on failure")
		}
	}
	for _, change := range []func(*Input){func(i *Input) { i.Authorized = false }, func(i *Input) { i.AuthorityUntil = base }, func(i *Input) { i.CertificateHash = strings.Repeat("9", 64) }, func(i *Input) { i.DeviceID = "agent_" + strings.Repeat("9", 32) }} {
		bad := in
		change(&bad)
		if s.Configure(bad, policyRequest(1, 900, "b"), base, epochA) == nil {
			t.Fatal("authority mismatch accepted")
		}
	}
	configure(t, &s, in, policyRequest(1, 900, "b"), base.Add(time.Second))
	if s.Configure(in, req, base.Add(time.Second), epochA) != ErrConflict {
		t.Fatal("old request reapplied")
	}
}

func TestPolicyChangePreservesOpenAndRecoveryConstraints(t *testing.T) {
	s, in, at := openState(t)
	original := s.Incidents[0]
	configure(t, &s, in, policyRequest(0, 3600, "a"), at)
	if s.Status != "unknown" || s.Incidents[0] != original || s.PendingSince != nil || s.RecoverySince != nil {
		t.Fatal("configuration changed incident", s)
	}
	evaluate(t, &s, in, at.Add(30*time.Second))
	if s.Incidents[0].ResolvedAt != nil {
		t.Fatal("grace recovered incident")
	}
	in.Sequence++
	in.ReceivedAt = at.Add(60 * time.Second)
	evaluate(t, &s, in, in.ReceivedAt)
	evaluate(t, &s, in, in.ReceivedAt.Add(60*time.Second))
	if s.Incidents[0].ResolvedAt == nil {
		t.Fatal("fresh recovery failed")
	}
	// A second edit cannot make the now-stale receipt actionable again.
	configure(t, &s, in, policyRequest(1, 120, "b"), in.ReceivedAt.Add(60*time.Second))
	for n := 1; n < 20; n++ {
		evaluate(t, &s, in, in.ReceivedAt.Add(time.Duration(60+n*30)*time.Second))
		if s.Status != "unknown" || len(s.Incidents) != 1 {
			t.Fatal("reconfiguration resumed silence", s)
		}
	}
}

func TestPolicyReceiptFloorsRestartAndCopyIsolation(t *testing.T) {
	s, in := New(), input(base)
	evaluate(t, &s, in, base)
	configure(t, &s, in, policyRequest(0, 300, "a"), base)
	// A report with a new time but an old sequence cannot arm the policy.
	in.ReceivedAt = base.Add(time.Second)
	evaluate(t, &s, in, in.ReceivedAt)
	if !s.Policy.AwaitingFreshReport {
		t.Fatal("retry armed policy")
	}
	in.Sequence++
	in.ReceivedAt = base.Add(2 * time.Second)
	evaluate(t, &s, in, in.ReceivedAt)
	before, _ := Encode(s)
	v := s.View(in, in.ReceivedAt, epochA)
	v.Policy.GraceSeconds = 900
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("view mutated policy")
	}
	if err := s.Evaluate(in, in.ReceivedAt.Add(time.Second), epochB); err != nil {
		t.Fatal(err)
	}
	if s.Policy.AwaitingFreshReport || s.Policy.GraceSeconds != 300 {
		t.Fatal("restart lost policy", s)
	}
	bad := s
	bad.Policy = s.Policy.clone()
	bad.Policy.ReportFloor = s.Sequence
	if bad.Validate() == nil {
		t.Fatal("invalid activation accepted")
	}
	bad = s
	bad.Policy = s.Policy.clone()
	bad.Policy.LastRequest.GraceSeconds = 900
	if bad.Validate() == nil {
		t.Fatal("inconsistent request accepted")
	}
}

func TestPolicyAtomicCopyAndFreshRecoveryAfterEdit(t *testing.T) {
	s, in, at := openState(t)
	in.Sequence++
	in.ReceivedAt = at.Add(time.Second)
	evaluate(t, &s, in, in.ReceivedAt)
	configure(t, &s, in, policyRequest(0, 300, "a"), in.ReceivedAt)
	// A still-fresh report already accepted before the edit cannot recover it.
	evaluate(t, &s, in, in.ReceivedAt.Add(60*time.Second))
	if s.Incidents[0].ResolvedAt != nil || s.RecoverySince != nil {
		t.Fatal("prechange evidence recovered incident")
	}
	before, _ := Encode(s)
	copy := s
	configure(t, &copy, in, policyRequest(1, 900, "b"), in.ReceivedAt.Add(60*time.Second))
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("configure changed shared policy")
	}
	copy = s
	fresh := in
	fresh.Sequence++
	fresh.ReceivedAt = in.ReceivedAt.Add(61 * time.Second)
	evaluate(t, &copy, fresh, fresh.ReceivedAt)
	after, _ = Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("evaluate changed shared policy")
	}
	if copy.Policy.AwaitingFreshReport || !s.Policy.AwaitingFreshReport {
		t.Fatal("gate alias")
	}
	// Invalid input on a state sharing the original policy must be atomic.
	broken := s
	broken.NextID = MaxCounter
	before, _ = Encode(broken)
	// Invalid input fails without sharing any changes.
	fresh.DeviceID = "invalid"
	if broken.Evaluate(fresh, fresh.ReceivedAt, epochA) == nil {
		t.Fatal("invalid input accepted")
	}
	after, _ = Encode(broken)
	if !bytes.Equal(before, after) {
		t.Fatal("failed evaluation mutated state")
	}
}
