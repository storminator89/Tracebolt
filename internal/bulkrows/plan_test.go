package bulkrows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func config() Config[string] {
	return Config[string]{MaxRows: 100000, MaxChunkRows: 3, MaxPayloadBytes: 32, MaxChunks: 100000, MaxCanonicalBytes: 64 << 20, Domain: "fixture.rows.v1\x00", Validate: func(s string) error {
		if s == "" {
			return ErrInvalid
		}
		return nil
	}, Less: func(a, b string) bool { return a < b }, Canonical: func(s string) []byte { return []byte(s + "\n") }}
}
func TestPlanIsDeterministicDetachedAndDomainSeparated(t *testing.T) {
	c := config()
	input := []string{"d", "b", "a", "c"}
	before := append([]string{}, input...)
	p, e := Plan(context.Background(), input, c)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(input, before) || !reflect.DeepEqual(p.Rows, []string{"a", "b", "c", "d"}) || !reflect.DeepEqual(p.Boundaries, []int{0, 3, 4}) || p.CanonicalBytes != 8 {
		t.Fatal(p, input)
	}
	expected := sha256.Sum256([]byte(c.Domain + "a\nb\nc\nd\n"))
	if p.RowsSHA256 != hex.EncodeToString(expected[:]) {
		t.Fatal("hash changed")
	}
	input[0] = "mutated"
	if p.Rows[3] != "d" {
		t.Fatal("aliased input descriptors")
	}
	c.Domain = "other.rows.v1\x00"
	q, e := Plan(context.Background(), p.Rows, c)
	if e != nil || p.RowsSHA256 == q.RowsSHA256 {
		t.Fatal("domains collide")
	}
}
func TestIndependentRowAndByteBoundaries(t *testing.T) {
	c := config()
	c.MaxChunkRows = 10
	c.MaxPayloadBytes = 4
	p, e := Plan(context.Background(), []string{"a", "b", "c", "d", "e"}, c)
	if e != nil || !reflect.DeepEqual(p.Boundaries, []int{0, 2, 4, 5}) {
		t.Fatal(p, e)
	}
}
func TestSuccessfulEmptyAndUnavailableAreDifferent(t *testing.T) {
	c := config()
	p, e := Plan(context.Background(), []string{}, c)
	if e != nil || p.Rows == nil || !reflect.DeepEqual(p.Boundaries, []int{0}) || p.CanonicalBytes != 0 || p.RowsSHA256 != Digest(c.Domain, nil) {
		t.Fatal(p, e)
	}
	p, e = Plan(context.Background(), []string(nil), c)
	if !errors.Is(e, ErrInvalid) || p.Rows != nil || p.Boundaries != nil {
		t.Fatal("nil source became success")
	}
}
func TestFailureNeverReturnsUsablePrefix(t *testing.T) {
	cases := map[string]func(*Config[string]) []string{
		"duplicate":       func(c *Config[string]) []string { return []string{"a", "a"} },
		"invalid row":     func(c *Config[string]) []string { return []string{"a", ""} },
		"rows":            func(c *Config[string]) []string { c.MaxRows = 3; return []string{"a", "b", "c", "d"} },
		"single payload":  func(c *Config[string]) []string { c.MaxPayloadBytes = 2; return []string{"a", "long"} },
		"aggregate bytes": func(c *Config[string]) []string { c.MaxCanonicalBytes = 2; return []string{"a", "b"} },
		"chunks":          func(c *Config[string]) []string { c.MaxChunkRows = 1; c.MaxChunks = 1; return []string{"a", "b"} },
		"empty encoding": func(c *Config[string]) []string {
			c.Canonical = func(string) []byte { return nil }
			return []string{"a"}
		},
		"missing codec":    func(c *Config[string]) []string { c.Validate = nil; return []string{"a"} },
		"unbounded config": func(c *Config[string]) []string { c.MaxCanonicalBytes = ^uint64(0); return []string{"a"} },
		"missing domain":   func(c *Config[string]) []string { c.Domain = ""; return []string{"a"} },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			c := config()
			rows := modify(&c)
			p, e := Plan(context.Background(), rows, c)
			if e == nil || p.Rows != nil || p.Boundaries != nil || p.CanonicalBytes != 0 || p.RowsSHA256 != "" {
				t.Fatal("returned invalid prefix", p, e)
			}
		})
	}
}
func TestCancellationAndAdapterErrorsArePreserved(t *testing.T) {
	c := config()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, e := Plan(ctx, []string{"a"}, c); !errors.Is(e, ErrCanceled) {
			t.Fatal(e)
		}
	}
	expected := errors.New("adapter invalid")
	c.Validate = func(string) error { return expected }
	if _, e := Plan(context.Background(), []string{"a"}, c); !errors.Is(e, expected) {
		t.Fatal("lost adapter error", e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	c.Validate = func(string) error { cancel(); return nil }
	if _, e := Plan(ctx, []string{"a"}, c); !errors.Is(e, ErrCanceled) {
		t.Fatal(e)
	}
}
func TestMaximumPlanningScopeAndExactCeiling(t *testing.T) {
	c := config()
	c.MaxChunkRows = 128
	c.MaxPayloadBytes = 64 << 10
	c.MaxChunks = 1024
	rows := make([]string, 100000)
	for i := range rows {
		rows[i] = string([]byte{byte('a' + i/26/26/26), byte('a' + i/26/26%26), byte('a' + i/26%26), byte('a' + i%26)})
	}
	p, e := Plan(context.Background(), rows, c)
	if e != nil || len(p.Rows) != 100000 || len(p.Boundaries) != 783 || p.Boundaries[len(p.Boundaries)-1] != 100000 {
		t.Fatal(len(p.Rows), len(p.Boundaries), e)
	}
	if !strings.HasSuffix(c.Domain, "\x00") {
		t.Fatal("fixture domain")
	}
}
