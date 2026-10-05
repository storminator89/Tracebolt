package journalhelper

import (
	"encoding/json"
	"strings"
	"testing"

	"localrmm/internal/journalpolicy"
)

func fixtureState() State {
	return State{Deployment: Deployment{SchemaVersion: DeploymentVersion, HelperUID: 1201, HelperGID: 1201, JournalGID: 190, AgentUID: 1200, AgentGID: 1200}, Policy: journalpolicy.Policy{SchemaVersion: journalpolicy.Version, Scope: journalpolicy.Scope, CollectionProfile: journalpolicy.CollectionProfile, SenderBinding: strings.Repeat("a", 64), ManagerOrigin: "https://manager.example.test:8443", TransportProfile: "tls", AgentUID: 1200, HelperUID: 1201, AllowedUnits: []string{"demo.service"}, MaxWindowSeconds: 3600, MaxLookbackSeconds: 86400, MaxPriority: 4, Enabled: true, ContentAcknowledged: true}, Revision: "sha256:" + strings.Repeat("f", 64)}
}
func fixtureIdentity() Identity {
	return Identity{1201, 1201, 1201, 1201, 1201, 1201, []uint32{190}, true}
}
func fixturePeer() Peer { return Peer{1200, 1200, 123} }
func TestDeploymentAndIdentityFailClosed(t *testing.T) {
	state := fixtureState()
	raw, _ := json.Marshal(state.Deployment)
	for _, b := range [][]byte{raw, append(append([]byte{}, raw...), '\n')} {
		got, e := decodeDeployment(b)
		if e != nil || got != state.Deployment {
			t.Fatal("canonical metadata rejected")
		}
	}
	for _, b := range [][]byte{nil, []byte(`{}`), append(raw, []byte(`{}`)...), []byte(strings.Replace(string(raw), `"agentGid":1200`, `"agentGid":null`, 1)), []byte(strings.Replace(string(raw), `"agentGid":1200`, `"agentGid":1200,"helperUid":1201`, 1)), []byte(strings.Replace(string(raw), `"helperUid":1201`, `"helperUid":0`, 1)), []byte(strings.Replace(string(raw), `"helperUid":1201`, `"helperUid":1200`, 1)), []byte(strings.Replace(string(raw), `"helperGid":1201`, `"helperGid":190`, 1)), []byte(strings.Repeat("x", MaxDeploymentBytes+1))} {
		if _, e := decodeDeployment(b); e == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
	i := fixtureIdentity()
	if validateState(state, i) != nil {
		t.Fatal("valid fixture rejected")
	}
	i.Groups = []uint32{1201, 190}
	if validateState(state, i) != nil {
		t.Fatal("primary supplementary group rejected")
	}
	for _, mutate := range []func(*Identity){func(i *Identity) { i.RealUID = 0 }, func(i *Identity) { i.EffectiveUID = 0 }, func(i *Identity) { i.SavedUID = 0 }, func(i *Identity) { i.RealUID = 1200 }, func(i *Identity) { i.RealGID = 190 }, func(i *Identity) { i.EffectiveGID = 0 }, func(i *Identity) { i.SavedGID = 0 }, func(i *Identity) { i.Groups = nil }, func(i *Identity) { i.Groups = []uint32{190, 4} }, func(i *Identity) { i.Groups = []uint32{190, 10} }, func(i *Identity) { i.Groups = []uint32{190, 1200} }, func(i *Identity) { i.NoCapabilities = false }} {
		i := fixtureIdentity()
		mutate(&i)
		if validateState(state, i) == nil {
			t.Fatal("unsafe identity accepted")
		}
	}
	for _, p := range []Peer{{0, 1200, 123}, {1201, 1200, 123}, {1200, 1201, 123}, {1200, 1200, 0}} {
		if _, e := authorityContext(state, fixtureIdentity(), p, state.Policy.SenderBinding); e == nil {
			t.Fatal("unsafe peer accepted")
		}
	}
	if _, e := authorityContext(state, fixtureIdentity(), fixturePeer(), strings.Repeat("b", 64)); e == nil {
		t.Fatal("different sender accepted")
	}
}
