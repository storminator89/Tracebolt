package actionwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
)

func capabilityFixture() actionhelper.Capabilities {
	d := actionpermit.Digest([]byte("inert"))
	return actionhelper.Capabilities{Version: actionhelper.CapabilitiesVersion, Enabled: true, ManagerID: "manager_" + strings.Repeat("1", 32), KeyID: d, EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: d, RootPolicyDigest: d, TransportProfile: actionhelper.ProductionTLS, CapturedAt: time.Now().UTC().Unix(), MaxLifetimeSeconds: 60, Services: []actionhelper.CapabilityService{{Unit: "fixture.service", UnitPolicyDigest: d}}}
}
func TestActionCanonicalClaimsDeliveryCapabilitiesResults(t *testing.T) {
	id := actionjob.Identity{JobID: "action_" + strings.Repeat("3", 32), Sequence: 1, EnvelopeDigest: actionpermit.Digest(nil)}
	raw, e := EncodeClaim(id)
	if e != nil {
		t.Fatal(e)
	}
	same, e := DecodeClaim(raw)
	if e != nil || same != id {
		t.Fatal(same, e)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), bytes.Replace(raw, []byte(`"jobId"`), []byte(`"JobId"`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), append(bytes.Clone(raw), []byte("{}")...)} {
		if _, e = DecodeClaim(bad); e == nil {
			t.Fatal("ambiguous claim")
		}
	}
	c := capabilityFixture()
	raw, e = EncodeCapabilities(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeCapabilities(raw); e != nil {
		t.Fatal(e)
	}
	now := time.Unix(c.CapturedAt, 0).UTC()
	if CheckCapabilityTime(c, now) != nil || CheckCapabilityTime(c, now.Add(60*time.Second)) == nil || CheckCapabilityTime(c, now.Add(-6*time.Second)) == nil {
		t.Fatal("original capture age not enforced")
	}
	d := actionjob.Delivery{Identity: id, State: actionjob.Claimed, StartDeadline: now.Add(time.Minute)}
	raw, e = EncodeDelivery(d)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeDelivery(raw); e != nil {
		t.Fatal(e)
	}
	d.State = actionstate.OperationCompleted
	if _, e = EncodeDelivery(d); e == nil {
		t.Fatal("terminal work delivered")
	}
	result := actionhelper.Result{JobID: id.JobID, Sequence: id.Sequence, EnvelopeDigest: id.EnvelopeDigest, Phase: actionstate.NotStarted, ConsumedAt: now.UnixMicro(), TransitionAt: now.UnixMicro(), Reason: actionstate.ReasonInactive}
	raw, e = EncodeResult(result)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeResult(raw); e != nil {
		t.Fatal(e)
	}
	result.Outcome = actionstate.OutcomeCompleted
	if _, e = EncodeResult(result); e == nil {
		t.Fatal("contradictory result accepted")
	}
}
func TestActionGrantMatchesSignedDescriptionIdentity(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, 32))
	c := capabilityFixture()
	now := c.CapturedAt
	plan := actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: c.Services[0].Unit, UnitPolicyDigest: c.Services[0].UnitPolicyDigest}
	pd, _ := actionpermit.PlanDigest(plan)
	p := actionpermit.Permit{Version: actionpermit.Version, ManagerID: c.ManagerID, KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey)), EndpointID: c.EndpointID, IncarnationDigest: c.IncarnationDigest, JobID: "action_" + strings.Repeat("3", 32), Sequence: 1, Plan: plan, PlanDigest: pd, OperatorID: "operator_" + strings.Repeat("4", 32), ApprovalDigest: c.RootPolicyDigest, RootPolicyDigest: c.RootPolicyDigest, IssuedAt: now, NotBefore: now, StartDeadline: now + 60}
	msg, e := actionpermit.SigningMessage(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := actionpermit.Encode(p, ed25519.Sign(key, msg))
	if e != nil {
		t.Fatal(e)
	}
	g := actionjob.Grant{Identity: actionjob.Identity{JobID: p.JobID, Sequence: p.Sequence, EnvelopeDigest: actionpermit.Digest(raw)}, Envelope: raw}
	encoded, e := EncodeGrant(g)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeGrant(encoded); e != nil {
		t.Fatal(e)
	}
	g.Identity.Sequence++
	if _, e = EncodeGrant(g); e == nil {
		t.Fatal("mismatched grant")
	}
}
func TestActionWireBodiesRejectUnknownFieldsAndBounds(t *testing.T) {
	c := capabilityFixture()
	raw, _ := EncodeCapabilities(c)
	bad := append(raw[:len(raw)-1], []byte(`,"command":"shell"}`)...)
	if _, e := DecodeCapabilities(bad); e == nil {
		t.Fatal("extension allowed")
	}
	if _, e := DecodeCapabilities([]byte(strings.Repeat("x", MaxBodyBytes+1))); e == nil {
		t.Fatal("oversized accepted")
	}
	c.Services = nil
	raw, _ = json.Marshal(c)
	if _, e := DecodeCapabilities(raw); e == nil {
		t.Fatal("null service list")
	}
}
func FuzzActionClaim(f *testing.F) {
	f.Add([]byte(`{"jobId":"action_33333333333333333333333333333333","sequence":"1","envelopeDigest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		id, e := DecodeClaim(raw)
		if e == nil {
			out, e := EncodeClaim(id)
			if e != nil || !bytes.Equal(out, raw) {
				t.Fatal("canonical drift", e)
			}
		}
	})
}
