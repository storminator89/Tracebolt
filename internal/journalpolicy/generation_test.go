package journalpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalview"
)

func generationPolicy() Policy {
	p, _, _, _ := fixture()
	p.SchemaVersion = VersionV2
	p.Revision = 1
	p.Generation = strings.Repeat("c", 64)
	return p
}
func TestGenerationPolicyCanonicalAndLegacyCompatibility(t *testing.T) {
	legacy, c, q, now := fixture()
	raw, err := Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"revision"`)) || bytes.Contains(raw, []byte(`"generation"`)) {
		t.Fatal("legacy encoding changed")
	}
	legacyGeneration, err := PolicyGeneration(legacy)
	if err != nil || legacyGeneration != (journalgeneration.Tuple{}) {
		t.Fatal("legacy tuple not empty")
	}
	if _, err := AuthorizeBound(legacy, c, q, journalgeneration.Tuple{}, now); err != nil {
		t.Fatal(err)
	}
	for _, revision := range []uint64{1, 1<<53 + 1, ^uint64(0)} {
		p := generationPolicy()
		p.Revision = revision
		raw, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Encode(restored)
		if err != nil || !bytes.Equal(raw, b) {
			t.Fatal("v2 policy roundtrip")
		}
		g, err := PolicyGeneration(p)
		if err != nil || g.Revision != revision || g.Generation != p.Generation {
			t.Fatal("tuple mismatch")
		}
		hash := sha256.Sum256(raw)
		if g.PolicyDigest != "sha256:"+hex.EncodeToString(hash[:]) {
			t.Fatal("digest does not commit full policy")
		}
		permit, err := AuthorizeBound(p, c, q, g, now)
		if err != nil || permit.Generation() != g || permit.PolicyDigest() != g.PolicyDigest || permit.Recheck(p, c, now) != nil {
			t.Fatal("bound permit failed", err)
		}
		copied := permit.Generation()
		copied.Revision++
		if permit.Generation() != g {
			t.Fatal("mutable permit")
		}
		if _, err := Authorize(p, c, q, now); err != ErrDenied {
			t.Fatal("legacy authorizer silently upgraded")
		}
		if _, err := AuthorizeBound(legacy, c, q, g, now); err != ErrDenied {
			t.Fatal("v2 request authorized by v1 policy")
		}
	}
}
func TestGenerationPolicyRejectsMissingWrongStaleAndConflictBindings(t *testing.T) {
	p := generationPolicy()
	_, c, q, now := fixture()
	g, _ := PolicyGeneration(p)
	permit, err := AuthorizeBound(p, c, q, g, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*journalgeneration.Tuple){"missing": func(g *journalgeneration.Tuple) { *g = journalgeneration.Tuple{} }, "old-revision": func(g *journalgeneration.Tuple) { g.Revision = 0 }, "new-revision": func(g *journalgeneration.Tuple) { g.Revision++ }, "same-revision-new-generation": func(g *journalgeneration.Tuple) { g.Generation = strings.Repeat("d", 64) }, "same-revision-other-policy": func(g *journalgeneration.Tuple) { g.PolicyDigest = "sha256:" + strings.Repeat("e", 64) }} {
		t.Run(name, func(t *testing.T) {
			bad := g
			mutate(&bad)
			if _, err := AuthorizeBound(p, c, q, bad, now); err != ErrDenied {
				t.Fatal("mismatched tuple authorized")
			}
		})
	}
	for name, mutate := range map[string]func(*Policy){"downgrade": func(p *Policy) { p.SchemaVersion = Version; p.Revision = 0; p.Generation = "" }, "next-revision": func(p *Policy) { p.Revision++ }, "same-revision-conflict": func(p *Policy) { p.Generation = strings.Repeat("d", 64) }, "same-generation-policy-change": func(p *Policy) { p.AllowedUnits = []string{"added.service", "example.service", "worker@one.service"} }, "disabled": func(p *Policy) { p.Enabled = false }} {
		t.Run(name, func(t *testing.T) {
			next := p
			mutate(&next)
			if permit.Recheck(next, c, now) != ErrChanged {
				t.Fatal("permit bridged changed policy")
			}
			if _, err := AuthorizeBound(next, c, q, g, now); err != ErrDenied {
				t.Fatal("old tuple under new policy")
			}
		})
	}
	if permit.Recheck(p, c, now.Add(2*time.Hour)) != ErrChanged {
		t.Fatal("generation extended query age")
	}
	for _, unit := range []string{"", "kernel", "system", "authentication", "*", "*.service", "other.service", "_TRANSPORT=kernel", "/var/log/auth.log"} {
		q.Unit = unit
		if _, err := AuthorizeBound(p, c, q, g, now); err != ErrDenied {
			t.Fatalf("new source %q permitted", unit)
		}
	}
}
func TestGenerationPolicyStrictJSONVersionsAndBounds(t *testing.T) {
	p := generationPolicy()
	raw, _ := Encode(p)
	cases := [][]byte{bytes.Replace(raw, []byte(VersionV2), []byte(Version), 1), bytes.Replace(raw, []byte(`"revision":"1",`), nil, 1), bytes.Replace(raw, []byte(`"generation":"`+p.Generation+`",`), nil, 1), append([]byte(`{"revision":"1",`), raw[1:]...), append([]byte(`{"scope":"kernel",`), raw[1:]...)}
	for _, revision := range []string{`1`, `"0"`, `"01"`, `"+1"`, `"-1"`, `"1e0"`, `"1.0"`, `"18446744073709551616"`, `"\u0031"`, `null`} {
		cases = append(cases, bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":`+revision), 1))
	}
	for _, generation := range []string{"", strings.Repeat("0", 64), strings.Repeat("C", 64), strings.Repeat("c", 63)} {
		cases = append(cases, bytes.Replace(raw, []byte(p.Generation), []byte(generation), 1))
	}
	legacy, _, _, _ := fixture()
	legacyRaw, _ := Encode(legacy)
	cases = append(cases, append([]byte(`{"revision":"0",`), legacyRaw[1:]...), append([]byte(`{"generation":"",`), legacyRaw[1:]...))
	for i, raw := range cases {
		if _, err := Decode(raw); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.Scope = "kernel" }, func(p *Policy) { p.MaxWindowSeconds = 3601 }, func(p *Policy) { p.MaxLookbackSeconds = 86401 }, func(p *Policy) { p.MaxPriority = 8 }, func(p *Policy) { p.ContentAcknowledged = false }, func(p *Policy) { p.AllowedUnits = make([]string, MaxUnits+1) }, func(p *Policy) { p.Generation = "" }, func(p *Policy) { p.Revision = 0 }} {
		bad := p
		mutate(&bad)
		if Validate(bad) == nil {
			t.Fatal("v2 expanded original bounds")
		}
	}
	_, c, q, now := fixture()
	for _, mutate := range []func(*journalview.Query){func(q *journalview.Query) { q.MaxPriority = 7 }, func(q *journalview.Query) { q.End = now.Add(time.Second) }, func(q *journalview.Query) { q.Start = now.Add(-2 * time.Hour) }, func(q *journalview.Query) { q.Start = q.Start.Add(time.Nanosecond) }} {
		bad := q
		mutate(&bad)
		g, _ := PolicyGeneration(p)
		if _, err := AuthorizeBound(p, c, bad, g, now); err == nil {
			t.Fatal("v2 relaxed query budgets")
		}
	}
}
