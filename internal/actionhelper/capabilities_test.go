//go:build linux

package actionhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
)

func TestCapabilitiesProjectionAndDefaultOff(t *testing.T) {
	f := newFixture(t)
	f.a.Policy.Enabled = false
	reopenCapabilitiesFixture(t, f)
	c, err := f.s.Capabilities(context.Background(), f.peer)
	if err != nil || c.Enabled || ValidateCapabilities(c) != nil {
		t.Fatal(c, err)
	}
	raw, _ := json.Marshal(f.a.Policy)
	digest, _ := targetDigest(f.a.Policy.Targets[0])
	if c.RootPolicyDigest != actionpermit.Digest(raw) || c.Services[0].UnitPolicyDigest != digest || c.CapturedAt != time.UnixMicro(f.clock.Load()).Unix() {
		t.Fatal("incorrect projection", c)
	}
	body, _ := json.Marshal(c)
	for _, secret := range []string{"/usr/", "publicKey", "reviewDigest", "configurationDigest", "agentUid", "agentGid", "UnitPolicyDigest"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("private or noncanonical field escaped", secret)
		}
	}
	if !bytes.Contains(body, []byte(`"unitPolicyDigest"`)) {
		t.Fatal("service fields not lowerCamel")
	}
	if a, b, c := f.backend.counts(); a != 0 || b != 0 || c != 0 {
		t.Fatal("capabilities used backend")
	}
}

func TestCapabilitiesRechecksIdentityBindingRevisionAndOriginalClock(t *testing.T) {
	for _, kind := range []string{"revision", "binding", "identity", "peer", "backward", "out_of_range", "advancing"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			original := time.UnixMicro(f.clock.Load()).Unix()
			calls := 0
			f.loadHook = func() {
				calls++
				if calls != 2 {
					return
				}
				switch kind {
				case "revision":
					f.a.Revision = actionpermit.Digest([]byte("replaced"))
				case "binding":
					f.a.Policy.EndpointID = "agent_" + strings.Repeat("a", 32)
				case "peer":
					f.a.Policy.AgentGID++
				case "backward":
					f.clock.Add(-1000000)
				case "out_of_range":
					f.clock.Store(time.Unix(maxCapabilitiesUnix+1, 0).UnixMicro())
				case "advancing":
					f.clock.Add(3000000)
				}
			}
			if kind == "identity" {
				identityCalls := 0
				f.s.inner.deps.Identity = func() error {
					identityCalls++
					if identityCalls == 2 {
						return ErrRejected
					}
					return nil
				}
			}
			c, err := f.s.Capabilities(context.Background(), f.peer)
			if kind == "advancing" {
				if err != nil || c.CapturedAt != original {
					t.Fatal("original capture time refreshed", c, err)
				}
			} else if err == nil {
				t.Fatal("changed authority/clock accepted", c)
			}
		})
	}
}

func TestCapabilitiesStrictShapeAndProfiles(t *testing.T) {
	f := newFixture(t)
	base, _ := f.s.Capabilities(context.Background(), f.peer)
	for _, kind := range []string{"zero", "version", "manager", "endpoint", "key", "incarnation", "policy", "clock", "future", "lifetime", "long_lifetime", "empty", "too_many", "duplicate", "unsorted", "protected", "noncanonical", "digest", "profile", "tls_ack", "http_no_ack"} {
		t.Run(kind, func(t *testing.T) {
			c := base
			c.Services = append([]CapabilityService(nil), base.Services...)
			switch kind {
			case "zero":
				c = Capabilities{}
			case "version":
				c.Version = "next"
			case "manager":
				c.ManagerID = "other"
			case "endpoint":
				c.EndpointID = "other"
			case "key":
				c.KeyID = "bad"
			case "incarnation":
				c.IncarnationDigest = "bad"
			case "policy":
				c.RootPolicyDigest = "bad"
			case "clock":
				c.CapturedAt = 0
			case "future":
				c.CapturedAt = 253402300800
			case "lifetime":
				c.MaxLifetimeSeconds = 0
			case "long_lifetime":
				c.MaxLifetimeSeconds = 121
			case "empty":
				c.Services = nil
			case "too_many":
				c.Services = make([]CapabilityService, 17)
			case "duplicate":
				c.Services = append(c.Services, c.Services[0])
			case "unsorted":
				c.Services = append(c.Services, CapabilityService{Unit: "aaa.service", UnitPolicyDigest: base.Services[0].UnitPolicyDigest})
			case "protected":
				c.Services[0].Unit = "sshd.service"
			case "noncanonical":
				c.Services[0].Unit = "foo@bar.service"
			case "digest":
				c.Services[0].UnitPolicyDigest = "bad"
			case "profile":
				c.TransportProfile = "automatic"
			case "tls_ack":
				c.HTTPTestAcknowledged = true
			case "http_no_ack":
				c.TransportProfile = DisposableHTTPTest
			}
			if ValidateCapabilities(c) == nil {
				t.Fatal("invalid capabilities accepted")
			}
		})
	}
	base.TransportProfile = DisposableHTTPTest
	base.HTTPTestAcknowledged = true
	if ValidateCapabilities(base) != nil {
		t.Fatal("explicit HTTP-test scope rejected")
	}
}

func TestCapabilitiesIPCMaximumFrameAndMalformedBodies(t *testing.T) {
	f := newFixture(t)
	target := f.a.Policy.Targets[0]
	f.a.Policy.Targets = nil
	for i := 0; i < 16; i++ {
		target.Unit = fmt.Sprintf("%02d%s.service", i, strings.Repeat("a", 118))
		target.Units = []UnitPin{{Unit: target.Unit, ConfigurationDigest: actionpermit.Digest(nil)}}
		f.a.Policy.Targets = append(f.a.Policy.Targets, target)
	}
	reopenCapabilitiesFixture(t, f)
	c, err := f.s.Capabilities(context.Background(), f.peer)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if writeCapabilities(&encoded, c, nil) != nil {
		t.Fatal("max legal capabilities exceeded bound")
	}
	if encoded.Len() <= 4<<10 || encoded.Len() > MaxResponseBytes+8 {
		t.Fatal("maximum bound test ineffective", encoded.Len())
	}
	r, err := ReadResponse(bytes.NewReader(encoded.Bytes()))
	if err != nil || len(r.Capabilities.Services) != 16 {
		t.Fatal(r, err)
	}
	raw := encoded.Bytes()[8:]
	bad := [][]byte{append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"unit":`), []byte(`"Unit":`), 1), bytes.Replace(raw, []byte(`"enabled":true,`), nil, 1), bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":true`), 1), bytes.Replace(raw, []byte(`"unit":`), []byte(`"arbitrary":0,"unit":`), 1)}
	for _, b := range bad {
		if _, err := ReadResponse(bytes.NewReader(frame(b))); err == nil {
			t.Fatal("noncanonical capability accepted")
		}
	}
	r.Error = "denied"
	b, _ := json.Marshal(r)
	if _, err := ReadResponse(bytes.NewReader(frame(b))); err == nil {
		t.Fatal("capabilities plus error accepted")
	}
	request := Request{Version: RequestVersion, Operation: CapabilitiesOperation}
	wire, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{`,"envelope":""}`, `,"jobId":""}`, `,"completion":true}`, `,"capabilities":{}}`} {
		payload := append(bytes.Clone(wire[8:len(wire)-1]), []byte(suffix)...)
		if _, err := readRequest(bytes.NewReader(frame(payload))); err == nil {
			t.Fatal("caller-authored body accepted", suffix)
		}
	}
	request.Envelope = []byte("anything")
	if _, err := EncodeRequest(request); err == nil {
		t.Fatal("capability body accepted")
	}
	request.Envelope = nil
	request.JobID = "action_" + strings.Repeat("1", 32)
	if _, err := EncodeRequest(request); err == nil {
		t.Fatal("capability job accepted")
	}
}

func TestCapabilitiesAuthenticatedIPCAndConcurrentProjection(t *testing.T) {
	f := newFixture(t)
	wire, _ := EncodeRequest(Request{Version: RequestVersion, Operation: CapabilitiesOperation})
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { f.s.ServeConn(context.Background(), a); close(done) }()
	if _, err := b.Write(wire); err != nil {
		t.Fatal(err)
	}
	r, err := ReadResponse(b)
	b.Close()
	<-done
	if err != nil || r.Capabilities == nil || r.Result != nil {
		t.Fatal(r, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			if _, err := f.s.Capabilities(context.Background(), f.peer); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if _, err := f.s.Capabilities(context.Background(), Peer{UID: 999, GID: 999, PID: 1}); err == nil {
		t.Fatal("unbound peer accepted")
	}
	if _, err := f.s.Capabilities(nil, f.peer); err == nil {
		t.Fatal("nil context accepted")
	}
	if a, b, c := f.backend.counts(); a != 0 || b != 0 || c != 0 {
		t.Fatal("projection had side effects")
	}
}

func FuzzCapabilitiesResponseFrame(f *testing.F) {
	a, _ := fixtureAuthority()
	c, _ := projectCapabilities(a, time.Unix(1700000000, 0).UTC())
	var b bytes.Buffer
	_ = writeCapabilities(&b, c, nil)
	f.Add(b.Bytes())
	f.Add(frame([]byte(`{"version":"tracebolt.action-helper-response.v1","capabilities":null}`)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := ReadResponse(bytes.NewReader(raw))
		if err != nil {
			return
		}
		if r.Capabilities != nil && ValidateCapabilities(*r.Capabilities) != nil {
			t.Fatal("invalid accepted projection")
		}
		if r.Result != nil && ValidateResult(*r.Result) != nil {
			t.Fatal("invalid accepted result")
		}
		var encoded bytes.Buffer
		if err := writeResponseValue(&encoded, r); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadResponse(&encoded); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCapabilitiesChangedPolicyNeedsReopenAndPreservesHistory(t *testing.T) {
	f := newFixture(t)
	request := f.request(t, 1)
	original, err := f.s.Handle(context.Background(), f.peer, request)
	if err != nil {
		t.Fatal(err)
	}
	f.a.Policy.MaxLifetimeSeconds = 59
	f.a.Revision = actionpermit.Digest([]byte("changed policy requiring reopen"))
	if _, err = f.s.Capabilities(context.Background(), f.peer); err == nil {
		t.Fatal("advertised unmatched state policy")
	}
	recovered, err := f.s.Handle(context.Background(), f.peer, request)
	if err != nil || recovered != original {
		t.Fatal("historical result unavailable", recovered, err)
	}
	deps := f.s.inner.deps
	if _, err = New(deps); err == nil {
		t.Fatal("constructed with a mismatched opened snapshot")
	}
	f.state.Close()
	v, err := f.a.verifier()
	if err != nil {
		t.Fatal(err)
	}
	f.state, err = actionstate.Open(context.Background(), f.dir, v)
	if err != nil {
		t.Fatal(err)
	}
	deps.State = f.state
	f.s, err = New(deps)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := f.s.Capabilities(context.Background(), f.peer)
	if err != nil || caps.MaxLifetimeSeconds != 59 {
		t.Fatal(caps, err)
	}
	recovered, err = f.s.Handle(context.Background(), f.peer, request)
	if err != nil || recovered != original {
		t.Fatal("reopen reset history", err)
	}
}

func reopenCapabilitiesFixture(t *testing.T, f *runtimeFixture) {
	t.Helper()
	deps := f.s.inner.deps
	f.state.Close()
	v, e := f.a.verifier()
	if e != nil {
		t.Fatal(e)
	}
	f.state, e = actionstate.Open(context.Background(), f.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	deps.State = f.state
	f.s, e = New(deps)
	if e != nil {
		t.Fatal(e)
	}
}
func TestCapabilitiesEnableAndExpansionRequireRestart(t *testing.T) {
	for _, kind := range []string{"enable", "expand"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			if kind == "enable" {
				f.a.Policy.Enabled = false
				reopenCapabilitiesFixture(t, f)
				f.a.Policy.Enabled = true
			} else {
				f.a.Policy.MaxLifetimeSeconds = 61
			}
			if _, e := f.s.Capabilities(context.Background(), f.peer); e == nil {
				t.Fatal("advertised changed policy without reopening state")
			}
			reopenCapabilitiesFixture(t, f)
			c, e := f.s.Capabilities(context.Background(), f.peer)
			if e != nil || !c.Enabled {
				t.Fatal(c, e)
			}
		})
	}
}
