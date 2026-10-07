package actionpermit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Deterministic inert fixture keys only. No production key generation or storage.
func fixture(t testing.TB) (Permit, LocalPins, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, ed25519.SeedSize))
	plan := Plan{Version: PlanVersion, Action: TryRestartService, Unit: "fixture.service", UnitPolicyDigest: Digest([]byte("reviewed fixture unit inputs"))}
	digest, err := PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	p := Permit{Version, "manager_" + strings.Repeat("1", 32), Digest(key.Public().(ed25519.PublicKey)), "agent_" + strings.Repeat("2", 32), Digest([]byte("fixture incarnation")), "action_" + strings.Repeat("3", 32), 11, plan, digest, "operator_" + strings.Repeat("4", 32), Digest([]byte("fixture approval")), Digest([]byte("fixture root policy")), 1791205200, 1791205200, 1791205260}
	pins := LocalPins{Enabled: true, ManagerID: p.ManagerID, PublicKey: key.Public().(ed25519.PublicKey), EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: p.RootPolicyDigest, MaxLifetimeSeconds: 90, MaxFutureSkewSeconds: 2, Services: []ServiceRule{{plan.Unit, plan.UnitPolicyDigest}}}
	return p, pins, key
}

func signed(t testing.TB, p Permit, key ed25519.PrivateKey) []byte {
	t.Helper()
	message, err := SigningMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(p, ed25519.Sign(key, message))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedRoundTripAndDomain(t *testing.T) {
	p, pins, key := fixture(t)
	v, err := NewVerifier(pins)
	if err != nil {
		t.Fatal(err)
	}
	raw := signed(t, p, key)
	// Fixed conformance vector: changing native field order or signed framing
	// without an explicit version decision must not silently pass a round trip.
	if Digest(raw) != "sha256:3c57846c2fddf672f33f8ff5c571367a2f3c4abb4e9a0c67d054fed63c6cd2b8" {
		t.Fatal("v1 envelope conformance vector changed")
	}
	message, _ := SigningMessage(p)
	if Digest(message) != "sha256:88860e53fb02154ee8f8c6d73fd57bb7a1e4ac596505d65948b4fe231318fbc8" {
		t.Fatal("v1 signing conformance vector changed")
	}
	got, err := v.Verify(raw)
	if err != nil || got != p {
		t.Fatal("round trip", err)
	}
	if err = v.CheckTime(got, time.Unix(p.IssuedAt, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(p)
	raw, err = Encode(p, ed25519.Sign(key, plain))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(raw); !errors.Is(err, ErrSignature) {
		t.Fatal("non-domain signature accepted", err)
	}
	if _, err = (Verifier{}).Verify(raw); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestAllSignedFieldsBound(t *testing.T) {
	p, pins, key := fixture(t)
	v, _ := NewVerifier(pins)
	raw := signed(t, p, key)
	_, sig, _ := decode(raw)
	mutations := map[string]func(*Permit){
		"manager":     func(p *Permit) { p.ManagerID = "manager_" + strings.Repeat("a", 32) },
		"key":         func(p *Permit) { p.KeyID = Digest([]byte("another key")) },
		"endpoint":    func(p *Permit) { p.EndpointID = "agent_" + strings.Repeat("a", 32) },
		"incarnation": func(p *Permit) { p.IncarnationDigest = Digest([]byte("another incarnation")) },
		"job":         func(p *Permit) { p.JobID = "action_" + strings.Repeat("a", 32) },
		"sequence":    func(p *Permit) { p.Sequence++ },
		"plan":        func(p *Permit) { p.Plan.Unit = "other.service"; p.PlanDigest, _ = PlanDigest(p.Plan) },
		"operator":    func(p *Permit) { p.OperatorID = "operator_" + strings.Repeat("a", 32) },
		"approval":    func(p *Permit) { p.ApprovalDigest = Digest([]byte("another approval")) },
		"policy":      func(p *Permit) { p.RootPolicyDigest = Digest([]byte("another policy")) },
		"issued":      func(p *Permit) { p.IssuedAt-- },
		"not-before":  func(p *Permit) { p.NotBefore++ },
		"deadline":    func(p *Permit) { p.StartDeadline++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			b, err := Encode(changed, sig)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.Verify(b); err == nil {
				t.Fatal("changed signed field accepted")
			}
		})
	}
	for i := range sig {
		changed := bytes.Clone(sig)
		changed[i] ^= 1
		b, _ := Encode(p, changed)
		if _, err := v.Verify(b); !errors.Is(err, ErrSignature) {
			t.Fatalf("signature byte %d: %v", i, err)
		}
	}
}

func TestStrictCanonicalParser(t *testing.T) {
	p, _, key := fixture(t)
	raw := signed(t, p, key)
	cases := [][]byte{
		nil, bytes.Repeat([]byte("x"), MaxPermitBytes+1), append(bytes.Clone(raw), ' '), append(bytes.Clone(raw), raw...),
		bytes.Replace(raw, []byte(`"permit":`), []byte(`"extra":1,"permit":`), 1),
		bytes.Replace(raw, []byte(`"sequence":"11"`), []byte(`"sequence":"11","sequence":"11"`), 1),
		bytes.Replace(raw, []byte(`"sequence":"11"`), []byte(`"sequence":"011"`), 1),
		bytes.Replace(raw, []byte(`"sequence":"11"`), []byte(`"sequence":11`), 1),
		bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1),
		bytes.Replace(raw, []byte(`"issuedAt":1791205200`), []byte(`"issuedAt":1.7912052e9`), 1),
		bytes.Replace(raw, []byte(`"issuedAt":1791205200`), []byte(`"issuedAt":null`), 1),
		bytes.Replace(raw, []byte(`"unit":"fixture.service"`), []byte(`"unit":"\u0066ixture.service"`), 1),
		bytes.Replace(raw, []byte(Version), []byte("tracebolt.execution-permit.v2"), 1),
		bytes.Replace(raw, []byte(`"signature":`), []byte(`"SIGNATURE":`), 1),
	}
	for i, b := range cases {
		if bytes.Equal(b, raw) {
			t.Fatalf("bad fixture %d", i)
		}
		if _, err := Decode(b); !errors.Is(err, ErrInvalid) {
			t.Fatalf("encoding %d accepted: %v", i, err)
		}
	}
	for i := 0; i < len(raw); i++ {
		if _, err := Decode(raw[:i]); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
}

func TestContractAndPlanLimits(t *testing.T) {
	p, _, _ := fixture(t)
	for _, unit := range []string{"", "../fixture.service", "--fixture.service", "fixture@instance.service", "fixture\\x2d.service", "fixture.socket", "fixture.service --all", "a;id.service", strings.Repeat("a", 129) + ".service"} {
		plan := p.Plan
		plan.Unit = unit
		if _, err := PlanDigest(plan); err == nil {
			t.Fatalf("unit accepted: %q", unit)
		}
	}
	for name, mutate := range map[string]func(*Permit){
		"version": func(p *Permit) { p.Version = "unknown" }, "action": func(p *Permit) { p.Plan.Action = "shell" },
		"plan-digest": func(p *Permit) { p.PlanDigest = Digest([]byte("wrong")) }, "zero-sequence": func(p *Permit) { p.Sequence = 0 },
		"anonymous": func(p *Permit) { p.OperatorID = "" }, "display-actor": func(p *Permit) { p.OperatorID = "Administrator" },
		"inverted": func(p *Permit) { p.NotBefore = p.IssuedAt - 1 }, "empty-window": func(p *Permit) { p.StartDeadline = p.NotBefore },
		"long-window": func(p *Permit) { p.StartDeadline = p.IssuedAt + MaxLifetimeSeconds + 1 }, "negative-time": func(p *Permit) { p.IssuedAt = -1 },
		"far-time": func(p *Permit) { p.StartDeadline = maxUnix + 1 }, "zero-digest": func(p *Permit) { p.IncarnationDigest = "sha256:" + strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			if _, err := SigningMessage(changed); !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
		})
	}
}

func TestPinnedPolicyAndDefaultOff(t *testing.T) {
	p, pins, key := fixture(t)
	raw := signed(t, p, key)
	pins.Enabled = false
	v, err := NewVerifier(pins)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(raw); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if _, err = v.CheckSignature(raw); err != nil {
		t.Fatal("historical signature check", err)
	}
	pins.Enabled = true
	for name, mutate := range map[string]func(*LocalPins){
		"manager": func(p *LocalPins) { p.ManagerID = "manager_" + strings.Repeat("a", 32) },
		"key": func(p *LocalPins) {
			p.PublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{38}, 32)).Public().(ed25519.PublicKey)
		},
		"endpoint":         func(p *LocalPins) { p.EndpointID = "agent_" + strings.Repeat("a", 32) },
		"incarnation":      func(p *LocalPins) { p.IncarnationDigest = Digest([]byte("different")) },
		"policy":           func(p *LocalPins) { p.RootPolicyDigest = Digest([]byte("different")) },
		"shorter-lifetime": func(p *LocalPins) { p.MaxLifetimeSeconds = 30 },
		"service":          func(p *LocalPins) { p.Services = []ServiceRule{{"other.service", p.Services[0].UnitPolicyDigest}} },
		"unit-inputs":      func(p *LocalPins) { p.Services = []ServiceRule{{"fixture.service", Digest([]byte("changed input"))}} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := pins
			mutate(&changed)
			v, err := NewVerifier(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.Verify(raw); !errors.Is(err, ErrBinding) {
				t.Fatal(err)
			}
		})
	}
	v, _ = NewVerifier(pins)
	pins.PublicKey[0] ^= 1
	pins.Services[0].Unit = "mutated.service"
	if _, err = v.Verify(raw); err != nil {
		t.Fatal("caller mutated verifier pins", err)
	}
}

func TestInvalidPinsAndClockBounds(t *testing.T) {
	p, pins, _ := fixture(t)
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 32), append([]byte{1}, make([]byte, 31)...)} {
		bad := pins
		bad.PublicKey = key
		if _, err := NewVerifier(bad); err == nil {
			t.Fatal("invalid key")
		}
	}
	for _, lifetime := range []int64{-1, 0, 121} {
		bad := pins
		bad.MaxLifetimeSeconds = lifetime
		if _, err := NewVerifier(bad); err == nil {
			t.Fatal("invalid lifetime")
		}
	}
	bad := pins
	bad.Services = append(bad.Services, bad.Services[0])
	if _, err := NewVerifier(bad); err == nil {
		t.Fatal("duplicate service")
	}
	v, _ := NewVerifier(pins)
	for _, test := range []struct {
		when time.Time
		want error
	}{
		{time.Unix(p.IssuedAt-3, 0).UTC(), ErrClock}, {time.Unix(p.IssuedAt-1, 0).UTC(), ErrNotReady},
		{time.Unix(p.IssuedAt, 0).UTC(), nil}, {time.Unix(p.StartDeadline-1, 999999999).UTC(), nil},
		{time.Unix(p.StartDeadline, 0).UTC(), ErrExpired}, {time.Time{}, ErrClock},
		{time.Unix(p.IssuedAt, 0).In(time.FixedZone("local", 3600)), ErrClock},
	} {
		if err := v.CheckTime(p, test.when); !errors.Is(err, test.want) {
			t.Fatalf("clock %v: %v, want %v", test.when, err, test.want)
		}
	}
}

func FuzzDecode(f *testing.F) {
	p, _, key := fixture(f)
	f.Add(signed(f, p, key))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, sig, err := decode(raw)
		if err == nil {
			encoded, err := Encode(p, sig)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatal("noncanonical accepted")
			}
		}
	})
}
