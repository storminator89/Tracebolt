package journalpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalview"
)

func fixture() (Policy, Context, journalview.Query, time.Time) {
	now := time.Date(2026, 10, 4, 15, 0, 0, 0, time.UTC)
	p := Policy{SchemaVersion: Version, Scope: Scope, CollectionProfile: CollectionProfile, SenderBinding: strings.Repeat("a", 64), ManagerOrigin: "https://manager.example:8787", TransportProfile: "tls", AgentUID: 1100, HelperUID: 1101, AllowedUnits: []string{"example.service", "worker@one.service"}, MaxWindowSeconds: 900, MaxLookbackSeconds: 3600, MaxPriority: 4, Enabled: true, ContentAcknowledged: true}
	c := Context{SenderBinding: p.SenderBinding, ManagerOrigin: p.ManagerOrigin, TransportProfile: p.TransportProfile, CollectionProfile: p.CollectionProfile, AgentUID: p.AgentUID, HelperUID: p.HelperUID, PeerUID: p.AgentUID}
	q := journalview.Query{Unit: "example.service", Start: now.Add(-10 * time.Minute), End: now.Add(-time.Minute), MaxPriority: 3}
	return p, c, q, now
}

func TestStrictPolicyRoundTripAndExactScope(t *testing.T) {
	p, c, q, now := fixture()
	raw, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Encode(got)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("noncanonical round trip")
	}
	permit, err := Authorize(got, c, q, now)
	if err != nil {
		t.Fatal(err)
	}
	if permit.Query() != q || len(permit.PolicyDigest()) != 71 || !strings.HasPrefix(permit.PolicyDigest(), "sha256:") || permit.Recheck(p, c, now.Add(time.Second)) != nil {
		t.Fatal("wrong exact permit")
	}
	// The permit retains no caller-owned unit slice or mutable policy pointer.
	got.AllowedUnits[0] = "changed.service"
	if permit.Query() != q || permit.Recheck(p, c, now) != nil {
		t.Fatal("caller mutation changed detached permit")
	}
}

func TestPolicyRequiresSeparateIdentityExactAllowlistAndConsent(t *testing.T) {
	tests := map[string]func(*Policy){
		"root agent": func(p *Policy) { p.AgentUID = 0 }, "root helper": func(p *Policy) { p.HelperUID = 0 },
		"same uid": func(p *Policy) { p.HelperUID = p.AgentUID }, "reserved uid": func(p *Policy) { p.HelperUID = ^uint32(0) },
		"no content acknowledgement": func(p *Policy) { p.ContentAcknowledged = false },
		"unknown profile":            func(p *Policy) { p.CollectionProfile = "managed-operations-v2" },
		"empty allowlist":            func(p *Policy) { p.AllowedUnits = nil }, "duplicate": func(p *Policy) { p.AllowedUnits = []string{"example.service", "example.service"} },
		"descending": func(p *Policy) { p.AllowedUnits = []string{"z.service", "a.service"} },
		"wildcard":   func(p *Policy) { p.AllowedUnits = []string{"*.service"} }, "match injection": func(p *Policy) { p.AllowedUnits = []string{"example.service PRIORITY=7"} },
		"path":        func(p *Policy) { p.AllowedUnits = []string{"/etc/example.service"} },
		"zero window": func(p *Policy) { p.MaxWindowSeconds = 0 }, "wide window": func(p *Policy) { p.MaxWindowSeconds = 3601 },
		"old lookback": func(p *Policy) { p.MaxLookbackSeconds = 86401 }, "invalid severity": func(p *Policy) { p.MaxPriority = 8 },
		"wrong destination":          func(p *Policy) { p.ManagerOrigin = "https://u:p@manager.example" },
		"plaintext requires new ack": func(p *Policy) { p.TransportProfile = "http-test"; p.ManagerOrigin = "http://manager.example:8787" },
		"inapplicable plaintext ack": func(p *Policy) { p.PlaintextAcknowledged = true },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, _, _, _ := fixture()
			change(&p)
			if Validate(p) == nil {
				t.Fatal("accepted policy")
			}
			if _, err := Encode(p); !errors.Is(err, ErrPolicy) {
				t.Fatal(err)
			}
		})
	}
	p, c, q, now := fixture()
	p.TransportProfile = "http-test"
	p.ManagerOrigin = "http://manager.example:8787"
	p.PlaintextAcknowledged = true
	c.TransportProfile = p.TransportProfile
	c.ManagerOrigin = p.ManagerOrigin
	if _, err := Authorize(p, c, q, now); err != nil {
		t.Fatal("explicit plaintext content acknowledgement rejected", err)
	}
}

func TestPolicyStrictJSONRejectsAmbiguity(t *testing.T) {
	p, _, _, _ := fixture()
	raw, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{nil, []byte("null"), append(bytes.Clone(raw), []byte("{}")...), bytes.Replace(raw, []byte(`"maxPriority":4`), []byte(`"maxPriority":null`), 1), bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":null`), 1), bytes.Replace(raw, []byte(`"maxPriority":4`), []byte(`"maxPriority":4e0`), 1), bytes.Replace(raw, []byte(`"agentUid":1100`), []byte(`"agentUid":4294967296`), 1), bytes.Replace(raw, []byte(`"agentUid":1100`), []byte(`"agentUid":-1`), 1), bytes.Replace(raw, []byte(`"enabled":true,`), nil, 1), append([]byte(`{"unknown":0,`), raw[1:]...), append([]byte(`{"enabled":true,`), raw[1:]...), append(bytes.Clone(raw), bytes.Repeat([]byte(" "), MaxPolicyBytes)...)}
	for i, v := range cases {
		if _, err := Decode(v); !errors.Is(err, ErrPolicy) {
			t.Fatalf("case %d accepted", i)
		}
	}
	// A valid explicit disabled policy can be stored but never authorizes reads.
	p.Enabled = false
	raw, _ = Encode(p)
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
}

func TestPeerBindingFiltersAndBudgetsAreIndependent(t *testing.T) {
	p, c, q, now := fixture()
	contexts := map[string]func(*Context){"root peer": func(c *Context) { c.PeerUID = 0 }, "helper peer": func(c *Context) { c.PeerUID = c.HelperUID }, "wrong peer": func(c *Context) { c.PeerUID++ }, "wrong binding": func(c *Context) { c.SenderBinding = strings.Repeat("b", 64) }, "wrong origin": func(c *Context) { c.ManagerOrigin = "https://other.example" }, "old profile": func(c *Context) { c.CollectionProfile = "basic-readonly-v1" }, "wrong helper": func(c *Context) { c.HelperUID++ }, "wrong agent": func(c *Context) { c.AgentUID++ }, "wrong transport": func(c *Context) { c.TransportProfile = "http-test" }}
	for name, f := range contexts {
		t.Run(name, func(t *testing.T) {
			bad := c
			f(&bad)
			if _, err := Authorize(p, bad, q, now); !errors.Is(err, ErrDenied) {
				t.Fatal(err)
			}
		})
	}
	queries := map[string]func(*journalview.Query){"foreign unit": func(q *journalview.Query) { q.Unit = "foreign.service" }, "higher priority": func(q *journalview.Query) { q.MaxPriority = 5 }, "wider window": func(q *journalview.Query) { q.Start = now.Add(-16 * time.Minute); q.End = now }, "older window": func(q *journalview.Query) { q.Start = now.Add(-61 * time.Minute); q.End = q.Start.Add(time.Minute) }, "future": func(q *journalview.Query) { q.End = now.Add(time.Second) }}
	for name, f := range queries {
		t.Run(name, func(t *testing.T) {
			bad := q
			f(&bad)
			if _, err := Authorize(p, c, bad, now); !errors.Is(err, ErrDenied) {
				t.Fatal(err)
			}
		})
	}
	p.Enabled = false
	if _, err := Authorize(p, c, q, now); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}

func TestDisableOrPolicyRevisionInvalidatesUnsentContent(t *testing.T) {
	p, c, q, now := fixture()
	permit, err := Authorize(p, c, q, now)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Policy){"disabled": func(p *Policy) { p.Enabled = false }, "changed allowlist": func(p *Policy) { p.AllowedUnits = []string{"example.service"} }, "expanded severity": func(p *Policy) { p.MaxPriority = 5 }, "changed destination": func(p *Policy) { p.ManagerOrigin = "https://elsewhere.example" }, "changed helper": func(p *Policy) { p.HelperUID++ }}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			next := p
			next.AllowedUnits = append([]string(nil), p.AllowedUnits...)
			change(&next)
			if !errors.Is(permit.Recheck(next, c, now), ErrChanged) {
				t.Fatal("released under changed policy")
			}
		})
	}
	if !errors.Is(permit.Recheck(p, c, now.Add(2*time.Hour)), ErrChanged) {
		t.Fatal("expired query authorized")
	}
	var zero Permit
	if !errors.Is(zero.Recheck(p, c, now), ErrChanged) {
		t.Fatal("zero permit accepted")
	}
}

func TestPolicyDecodingDetachesInput(t *testing.T) {
	p, c, q, now := fixture()
	raw, _ := Encode(p)
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	clear(raw)
	permit, err := Authorize(got, c, q, now)
	if err != nil || permit.Query() != q {
		t.Fatal(err)
	}
	// This is deliberately a pure JSON/authorization test, not a root-file,
	// SO_PEERCRED, enrollment, service or real journal-read claim.
	if _, err := json.Marshal(got); err != nil {
		t.Fatal(err)
	}
}
