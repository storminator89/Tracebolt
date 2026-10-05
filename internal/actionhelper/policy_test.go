//go:build linux

package actionhelper

import (
	"encoding/json"
	"localrmm/internal/actionpermit"
	"testing"
)

func TestCanonicalPolicyAndTransportBinding(t *testing.T) {
	a, _ := fixtureAuthority()
	raw, _ := json.Marshal(a.Policy)
	p, e := decodePolicy(raw, a.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodePolicy(append(raw, '\n'), a.PublicKey); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(raw, ' '), append([]byte(" "), raw...), append(raw[:len(raw)-1], []byte(",\"unexpected\":true}")...)} {
		if _, e = decodePolicy(bad, a.PublicKey); e == nil {
			t.Fatal("accepted noncanonical")
		}
	}
	v1, _ := policyVerifier(p, a.PublicKey)
	binding1, _ := v1.BindingDigest()
	p.TransportProfile = DisposableHTTPTest
	p.HTTPTestAcknowledged = true
	v2, e := policyVerifier(p, a.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	binding2, _ := v2.BindingDigest()
	if binding1 != binding2 {
		t.Fatal("profile reset ledger binding")
	}
	changed, _ := json.Marshal(p)
	if actionpermit.Digest(raw) == actionpermit.Digest(changed) {
		t.Fatal("profile not bound")
	}
	p.Enabled = false
	v3, e := policyVerifier(p, a.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	binding3, _ := v3.BindingDigest()
	if binding1 != binding3 {
		t.Fatal("disable reset ledger")
	}
}
func TestPolicyExplicitGrantAndReviewRequirements(t *testing.T) {
	for _, kind := range []string{"version", "profile", "http_unacknowledged", "production_acknowledged", "root_peer", "key", "review", "duplicate_target", "duplicate_unit", "unreviewed_target", "unsafe_input", "duplicate_input", "protected_target", "protected_dependency"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := fixtureAuthority()
			p := a.Policy
			switch kind {
			case "version":
				p.Version = "v0"
			case "profile":
				p.TransportProfile = "http"
			case "http_unacknowledged":
				p.TransportProfile = DisposableHTTPTest
			case "production_acknowledged":
				p.HTTPTestAcknowledged = true
			case "root_peer":
				p.AgentUID = 0
			case "key":
				p.KeyID = actionpermit.Digest(nil)
			case "review":
				p.Targets[0].ReviewDigest = ""
			case "duplicate_target":
				p.Targets = append(p.Targets, p.Targets[0])
			case "duplicate_unit":
				p.Targets[0].Units = append(p.Targets[0].Units, p.Targets[0].Units[0])
			case "unreviewed_target":
				p.Targets[0].Units[0].Unit = "other.service"
			case "unsafe_input":
				p.Targets[0].Inputs[0].Path = "/tmp/owned"
			case "duplicate_input":
				p.Targets[0].Inputs = append(p.Targets[0].Inputs, p.Targets[0].Inputs[0])
			case "protected_target":
				p.Targets[0].Unit = "tracebolt-agent.service"
			case "protected_dependency":
				p.Targets[0].Units[0].Unit = "ssh.service"
			}
			if _, e := policyVerifier(p, a.PublicKey); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestDefaultOffPolicyCannotVerifySubmission(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	f.a.Policy.Enabled = false
	v, e := f.a.verifier()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.Verify(r.Envelope); e != actionpermit.ErrDisabled {
		t.Fatal(e)
	}
}
