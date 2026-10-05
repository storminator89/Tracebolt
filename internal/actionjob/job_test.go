package actionjob

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var at = time.Date(2026, 10, 5, 18, 0, 0, 0, time.UTC)

func fixture(t *testing.T) (Record, func(actionpermit.Permit) ([]byte, error)) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32)))
	r, e := New("manager_"+strings.Repeat("1", 32), "agent_"+strings.Repeat("2", 32), actionpermit.Digest([]byte("incarnation")), key.Public().(ed25519.PublicKey), at)
	if e != nil {
		t.Fatal(e)
	}
	c := actionhelper.Capabilities{Version: "tracebolt.action-capabilities.v1", Enabled: true, ManagerID: r.ManagerID, KeyID: actionpermit.Digest(r.PublicKey), EndpointID: r.DeviceID, IncarnationDigest: r.IncarnationDigest, RootPolicyDigest: actionpermit.Digest([]byte("policy")), TransportProfile: actionhelper.ProductionTLS, CapturedAt: at.Unix(), MaxLifetimeSeconds: 45, Services: []actionhelper.CapabilityService{{Unit: "fixture.service", UnitPolicyDigest: actionpermit.Digest([]byte("unit"))}}}
	if e = r.Report(c, at); e != nil {
		t.Fatal(e)
	}
	return r, func(p actionpermit.Permit) ([]byte, error) {
		b, e := actionpermit.SigningMessage(p)
		if e != nil {
			return nil, e
		}
		return actionpermit.Encode(p, ed25519.Sign(key, b))
	}
}
func preview(t *testing.T, r *Record) Preview {
	t.Helper()
	p, e := r.MakePreview("action_"+strings.Repeat("3", 32), "operator_"+strings.Repeat("4", 32), "fixture.service", actionhelper.ProductionTLS, at)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func approved(t *testing.T) (Record, Job) {
	t.Helper()
	r, sign := fixture(t)
	p := preview(t, &r)
	j, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(time.Second), sign)
	if e != nil {
		t.Fatal(e)
	}
	return r, j
}
func copyRecord(r Record) Record {
	b, _ := json.Marshal(r)
	var v Record
	json.Unmarshal(b, &v)
	return v
}
func TestApprovalIsBoundAndSignsOnce(t *testing.T) {
	r, sign := fixture(t)
	p := preview(t, &r)
	var count atomic.Int32
	wrapped := func(p actionpermit.Permit) ([]byte, error) { count.Add(1); return sign(p) }
	for _, bad := range []struct{ id, digest, actor, profile string }{{p.ID, p.Digest, "operator_" + strings.Repeat("5", 32), p.TransportProfile}, {p.ID, actionpermit.Digest(nil), p.ActorID, p.TransportProfile}, {p.ID, p.Digest, p.ActorID, actionhelper.DisposableHTTPTest}} {
		c := copyRecord(r)
		if _, e := c.Approve(bad.id, bad.digest, bad.actor, bad.profile, at.Add(time.Second), wrapped); e == nil {
			t.Fatal("unbound approval")
		}
	}
	if count.Load() != 0 {
		t.Fatal("signed denied action")
	}
	j, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(time.Second), wrapped)
	if e != nil {
		t.Fatal(e)
	}
	old, _ := json.Marshal(r)
	retry, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(30*time.Second), wrapped)
	fresh, _ := json.Marshal(r)
	if e != nil || count.Load() != 1 || !j.Deadline().Equal(at.Add(46*time.Second)) || retry.Identity() != j.Identity() || string(old) != string(fresh) {
		t.Fatal("approval retry changed authority", e)
	}
}
func TestClaimIsConsumeOnceAndNeverReconstructsGrant(t *testing.T) {
	r, j := approved(t)
	g, e := r.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(2*time.Second))
	if e != nil || len(g.Envelope) == 0 {
		t.Fatal(e)
	}
	restored := copyRecord(r)
	g, e = restored.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(3*time.Second))
	if !errors.Is(e, ErrConsumed) || len(g.Envelope) != 0 {
		t.Fatal("regranted", e)
	}
	if restored.Ready(actionhelper.ProductionTLS, at.Add(3*time.Second)) != "action_in_progress" {
		t.Fatal("lost claim became retryable")
	}
	if _, e = restored.MakePreview("action_"+strings.Repeat("9", 32), j.Preview.ActorID, "fixture.service", actionhelper.ProductionTLS, at.Add(3*time.Second)); e == nil {
		t.Fatal("new job while unknown")
	}
}
func TestReportReplayNeverRefreshesOriginalAge(t *testing.T) {
	r, _ := fixture(t)
	before := *r.CapabilitiesReceivedAt
	if e := r.Report(*r.Capabilities, at.Add(30*time.Second)); e != nil {
		t.Fatal(e)
	}
	if !r.CapabilitiesReceivedAt.Equal(before) || r.Ready(actionhelper.ProductionTLS, at.Add(60*time.Second)) != "helper_stale" {
		t.Fatal("replay refreshed readiness")
	}
	bad := *r.Capabilities
	bad.Enabled = false
	if e := r.Report(bad, at.Add(time.Second)); !errors.Is(e, ErrConflict) {
		t.Fatal("same time replaced policy", e)
	}
}
func TestChangedPolicyExpiryAndBadSignerFailClosed(t *testing.T) {
	for _, kind := range []string{"changed", "expired", "signer", "disabled", "clock"} {
		t.Run(kind, func(t *testing.T) {
			r, sign := fixture(t)
			p := preview(t, &r)
			now := at.Add(time.Second)
			switch kind {
			case "changed":
				r.Capabilities.RootPolicyDigest = actionpermit.Digest(nil)
			case "expired":
				now = at.Add(60 * time.Second)
			case "signer":
				sign = func(actionpermit.Permit) ([]byte, error) { return []byte("unsigned"), nil }
			case "disabled":
				r.Capabilities.Enabled = false
			case "clock":
				now = at.Add(-time.Second)
			}
			if _, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, now, sign); e == nil || len(r.Jobs) != 0 {
				t.Fatal("approval accepted", e)
			}
		})
	}
}
func TestResultTransitionsIdempotencyAndUnknownBlock(t *testing.T) {
	r, j := approved(t)
	r.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(2*time.Second))
	x := actionhelper.Result{JobID: j.Preview.ID, Sequence: j.Preview.Sequence, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.Admitted, ConsumedAt: at.Add(2 * time.Second).UnixMicro(), TransitionAt: at.Add(2 * time.Second).UnixMicro()}
	if e := r.Accept(x, at.Add(3*time.Second)); e != nil {
		t.Fatal(e)
	}
	old, _ := json.Marshal(r)
	if e := r.Accept(x, at.Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	same, _ := json.Marshal(r)
	if string(old) != string(same) {
		t.Fatal("repeat mutated receipt")
	}
	x.Phase = actionstate.Dispatching
	x.DispatchAt = at.Add(4 * time.Second).UnixMicro()
	x.TransitionAt = x.DispatchAt
	if e := r.Accept(x, at.Add(5*time.Second)); e != nil {
		t.Fatal(e)
	}
	x.Phase = actionstate.NeedsIntervention
	x.Outcome = actionstate.OutcomeUnknown
	x.ObservedState = actionstate.ObservedUnknown
	x.TransitionAt = at.Add(40 * time.Second).UnixMicro()
	if e := r.Accept(x, at.Add(41*time.Second)); e != nil {
		t.Fatal(e)
	}
	if r.Ready(actionhelper.ProductionTLS, at.Add(42*time.Second)) != "needs_intervention" {
		t.Fatal("unknown retryable")
	}
	x.Phase = actionstate.OperationCompleted
	x.Outcome = actionstate.OutcomeCompleted
	if e := r.Accept(x, at.Add(43*time.Second)); e == nil {
		t.Fatal("terminal outcome overwritten")
	}
	if Validate(copyRecord(r)) != nil {
		t.Fatal("round trip invalid")
	}
}
func TestInvalidResultBindingAndFutureClock(t *testing.T) {
	r, j := approved(t)
	r.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(2*time.Second))
	base := actionhelper.Result{JobID: j.Preview.ID, Sequence: j.Preview.Sequence, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.NotStarted, Reason: actionstate.ReasonInactive, ConsumedAt: at.Add(2 * time.Second).UnixMicro(), TransitionAt: at.Add(3 * time.Second).UnixMicro()}
	for _, change := range []func(*actionhelper.Result){func(x *actionhelper.Result) { x.JobID = "action_" + strings.Repeat("8", 32) }, func(x *actionhelper.Result) { x.Sequence++ }, func(x *actionhelper.Result) { x.EnvelopeDigest = actionpermit.Digest(nil) }, func(x *actionhelper.Result) { x.TransitionAt = at.Add(time.Hour).UnixMicro() }, func(x *actionhelper.Result) { x.ConsumedAt = at.Add(-time.Minute).UnixMicro() }} {
		c := copyRecord(r)
		x := base
		change(&x)
		if e := c.Accept(x, at.Add(4*time.Second)); e == nil {
			t.Fatal("invalid result accepted")
		}
	}
	if e := r.Accept(base, at.Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	if r.Ready(actionhelper.ProductionTLS, at.Add(5*time.Second)) != "ready" {
		t.Fatal("definitely not started did not allow explicit next action")
	}
}
func TestClaimBeforeDeadlineHelperExpiredAfterward(t *testing.T) {
	r, j := approved(t)
	if _, e := r.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	x := actionhelper.Result{JobID: j.Preview.ID, Sequence: j.Preview.Sequence, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.Expired, ConsumedAt: j.Deadline().Add(time.Second).UnixMicro(), TransitionAt: j.Deadline().Add(time.Second).UnixMicro()}
	if e := r.Accept(x, j.Deadline().Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	if !CanFollow(r.Jobs[0], j.Deadline().Add(3*time.Second)) {
		t.Fatal("expired not terminal")
	}
	if Validate(copyRecord(r)) != nil {
		t.Fatal("expired result invalid on reload")
	}
}
func TestImpossibleEarlyHelperExpiryDoesNotFreeJob(t *testing.T) {
	r, j := approved(t)
	r.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(2*time.Second))
	x := actionhelper.Result{JobID: j.Preview.ID, Sequence: j.Preview.Sequence, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.Expired, ConsumedAt: at.Add(3 * time.Second).UnixMicro(), TransitionAt: at.Add(3 * time.Second).UnixMicro()}
	if e := r.Accept(x, at.Add(4*time.Second)); e == nil {
		t.Fatal("early expiry accepted")
	}
	if r.Ready(actionhelper.ProductionTLS, at.Add(4*time.Second)) != "action_in_progress" {
		t.Fatal("early expiry freed action")
	}
}
func TestSignerCannotExtendRequestedLocalDeadline(t *testing.T) {
	r, sign := fixture(t)
	p := preview(t, &r)
	if _, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(time.Second), func(p actionpermit.Permit) ([]byte, error) { p.StartDeadline++; return sign(p) }); e == nil || len(r.Jobs) > 0 {
		t.Fatal("signer changed immutable requested permit")
	}
}
func TestPolicyProfileChangeKeepsHistoryAndSequence(t *testing.T) {
	r, j := approved(t)
	r.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(2*time.Second))
	x := actionhelper.Result{JobID: j.Preview.ID, Sequence: 1, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.NotStarted, Reason: actionstate.ReasonInactive, ConsumedAt: at.Add(2 * time.Second).UnixMicro(), TransitionAt: at.Add(3 * time.Second).UnixMicro()}
	if e := r.Accept(x, at.Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	original := append([]byte{}, r.Jobs[0].Envelope...)
	c := *r.Capabilities
	c.CapturedAt = at.Add(5 * time.Second).Unix()
	c.TransportProfile = actionhelper.DisposableHTTPTest
	c.HTTPTestAcknowledged = true
	c.RootPolicyDigest = actionpermit.Digest([]byte("new local policy"))
	if e := r.Report(c, at.Add(5*time.Second)); e != nil {
		t.Fatal(e)
	}
	p, e := r.MakePreview("action_"+strings.Repeat("9", 32), j.Preview.ActorID, "fixture.service", c.TransportProfile, at.Add(5*time.Second))
	if e != nil || p.Sequence != 2 || string(r.Jobs[0].Envelope) != string(original) || Validate(r) != nil {
		t.Fatal("profile switch reset history", e)
	}
}
