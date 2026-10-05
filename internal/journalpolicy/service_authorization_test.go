package journalpolicy

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalview"
)

func servicePolicy(mode ServiceAuthorization) Policy {
	p := generationPolicy()
	p.SchemaVersion, p.Scope, p.ServiceAuthorization = VersionV3, ScopeV3, mode
	if mode == AllSystemServices {
		p.AllowedUnits = []string{}
	}
	return p
}

func TestV3ServiceAuthorizationIsExplicitAndLegacyBytesStayExact(t *testing.T) {
	for _, mode := range []ServiceAuthorization{ExactUnits, AllSystemServices} {
		p := servicePolicy(mode)
		raw, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(raw)
		if err != nil || got.ServiceAuthorization != mode || got.AllowedUnits == nil {
			t.Fatal("v3 scope roundtrip", err)
		}
		again, err := Encode(got)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("v3 canonical policy changed")
		}
	}
	for _, version := range []string{Version, VersionV2} {
		p := generationPolicy()
		p.SchemaVersion = version
		prefix := `{"schemaVersion":"` + version + `",`
		if version == Version {
			p.Revision, p.Generation = 0, ""
		} else {
			prefix += `"revision":"1","generation":"` + strings.Repeat("c", 64) + `",`
		}
		want := prefix + `"scope":"on-demand-allowlisted-system-service-log-content","collectionProfile":"managed-operations-v3","senderBinding":"` + strings.Repeat("a", 64) + `","managerOrigin":"https://manager.example:8787","transportProfile":"tls","agentUid":1100,"helperUid":1101,"allowedUnits":["example.service","worker@one.service"],"maxWindowSeconds":900,"maxLookbackSeconds":3600,"maxPriority":4,"enabled":true,"contentAcknowledged":true,"plaintextAcknowledged":false}`
		raw, err := Encode(p)
		if err != nil || string(raw) != want {
			t.Fatal("legacy canonical bytes changed", version)
		}
		for _, value := range []string{`""`, `"exact-units"`, `"all-system-services"`, `null`} {
			if _, err := Decode(append([]byte(`{"serviceAuthorization":`+value+`,`), raw[1:]...)); err != ErrPolicy {
				t.Fatal("legacy scope field accepted", version, value)
			}
		}
		p.AllowedUnits = []string{}
		if Validate(p) != ErrPolicy {
			t.Fatal("legacy empty allowlist became broad")
		}
	}
}

func TestV3ScopeRejectsAmbiguousOrDowngradedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*Policy){
		"missing mode":       func(p *Policy) { p.ServiceAuthorization = "" },
		"unknown mode":       func(p *Policy) { p.ServiceAuthorization = "all" },
		"legacy scope":       func(p *Policy) { p.Scope = Scope },
		"nil list":           func(p *Policy) { p.AllowedUnits = nil },
		"broad named list":   func(p *Policy) { p.AllowedUnits = []string{"example.service"} },
		"wildcard":           func(p *Policy) { p.AllowedUnits = []string{"*.service"} },
		"empty exact":        func(p *Policy) { p.ServiceAuthorization = ExactUnits },
		"legacy version":     func(p *Policy) { p.SchemaVersion = VersionV2 },
		"future version":     func(p *Policy) { p.SchemaVersion = "tracebolt.journal-content-policy.v4" },
		"missing revision":   func(p *Policy) { p.Revision = 0 },
		"missing generation": func(p *Policy) { p.Generation = "" },
		"no content consent": func(p *Policy) { p.ContentAcknowledged = false },
		"no HTTP consent":    func(p *Policy) { p.TransportProfile = "http-test"; p.ManagerOrigin = "http://manager.example:8787" },
	} {
		t.Run(name, func(t *testing.T) {
			p := servicePolicy(AllSystemServices)
			mutate(&p)
			if Validate(p) != ErrPolicy {
				t.Fatal("invalid broad authority accepted")
			}
		})
	}
	raw, _ := Encode(servicePolicy(AllSystemServices))
	for _, candidate := range [][]byte{
		bytes.Replace(raw, []byte(`"serviceAuthorization":"all-system-services",`), nil, 1),
		bytes.Replace(raw, []byte(`"allowedUnits":[],`), nil, 1),
		bytes.Replace(raw, []byte(`"allowedUnits":[]`), []byte(`"allowedUnits":null`), 1),
		bytes.Replace(raw, []byte(`"serviceAuthorization":"all-system-services"`), []byte(`"serviceAuthorization":true`), 1),
		append([]byte(`{"serviceAuthorization":"all-system-services",`), raw[1:]...),
		bytes.Replace(raw, []byte(`"revision":"1",`), nil, 1),
		bytes.Replace(raw, []byte(`"generation":"`+strings.Repeat("c", 64)+`",`), nil, 1),
	} {
		if _, err := Decode(candidate); err != ErrPolicy {
			t.Fatal("ambiguous v3 JSON accepted")
		}
	}
}

func TestAllSystemServicesStillRequiresOneExactBoundedServiceQuery(t *testing.T) {
	p := servicePolicy(AllSystemServices)
	_, c, q, now := fixture()
	g, err := PolicyGeneration(p)
	if err != nil || g == (journalgeneration.Tuple{}) {
		t.Fatal("v3 generation missing")
	}
	for _, unit := range []string{"example.service", "newly-installed.service", "future@instance.service"} {
		q.Unit = unit
		permit, err := AuthorizeBound(p, c, q, g, now)
		if err != nil || permit.Query() != q || permit.Recheck(p, c, now) != nil {
			t.Fatal("valid exact service denied", unit, err)
		}
	}
	for _, unit := range []string{"", "*", "*.service", "kernel", "system", "authentication", "demo.socket", "demo.service other.service", "demo.service\n", "_TRANSPORT=kernel", "/var/log/auth.log", "/etc/demo.service"} {
		q.Unit = unit
		if _, err := AuthorizeBound(p, c, q, g, now); err != ErrDenied {
			t.Fatal("broad source or noncanonical service accepted", unit)
		}
	}
	q.Unit = "example.service"
	for _, mutate := range []func(*journalview.Query){
		func(q *journalview.Query) { q.MaxPriority = 5 },
		func(q *journalview.Query) { q.Start = now.Add(-16 * time.Minute); q.End = now },
		func(q *journalview.Query) { q.Start = now.Add(-61 * time.Minute); q.End = q.Start.Add(time.Minute) },
		func(q *journalview.Query) { q.End = now.Add(time.Second) },
	} {
		bad := q
		mutate(&bad)
		if _, err := AuthorizeBound(p, c, bad, g, now); err != ErrDenied {
			t.Fatal("broad grant expanded query bounds")
		}
	}
	if _, err := Authorize(p, c, q, now); err != ErrDenied {
		t.Fatal("broad policy accepted an unbound legacy request")
	}
	exact := servicePolicy(ExactUnits)
	exactGeneration, _ := PolicyGeneration(exact)
	if exactGeneration.PolicyDigest == g.PolicyDigest {
		t.Fatal("policy digest did not bind service authorization")
	}
	q.Unit = "future.service"
	if _, err := AuthorizeBound(exact, c, q, exactGeneration, now); err != ErrDenied {
		t.Fatal("v3 exact grant became broad")
	}
	q.Unit = "example.service"
	permit, _ := AuthorizeBound(p, c, q, g, now)
	if permit.Recheck(exact, c, now) != ErrChanged {
		t.Fatal("permit survived scope change")
	}
	p.Enabled = false
	if permit.Recheck(p, c, now) != ErrChanged {
		t.Fatal("disabled broad policy released content")
	}
}
