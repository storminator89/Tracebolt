package cachedupdates

import (
	"bytes"
	"strings"
	"testing"
)

func TestLocalConsentExactBindingAndScope(t *testing.T) {
	binding := strings.Repeat("a", 64)
	consent := LocalConsent{ConsentVersion, SchemaVersion, Scope, binding, true}
	raw, e := EncodeLocalConsent(consent, binding)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeLocalConsent(raw, binding)
	if e != nil || got != consent {
		t.Fatal("explicit opt-in rejected")
	}
	for name, b := range map[string][]byte{
		"absent":         nil,
		"false":          bytes.Replace(raw, []byte(`"acknowledged":true`), []byte(`"acknowledged":false`), 1),
		"missing":        bytes.Replace(raw, []byte(`,"acknowledged":true`), nil, 1),
		"duplicate":      bytes.Replace(raw, []byte(`"acknowledged":true`), []byte(`"acknowledged":true,"acknowledged":true`), 1),
		"alias":          bytes.Replace(raw, []byte(`"acknowledged"`), []byte(`"Acknowledged"`), 1),
		"nested-array":   bytes.Replace(raw, []byte(`"acknowledged":true`), []byte(`"acknowledged":[]`), 1),
		"nested-object":  bytes.Replace(raw, []byte(`"scope":`), []byte(`"scope":{},"ignored":`), 1),
		"null":           bytes.Replace(raw, []byte(`"acknowledged":true`), []byte(`"acknowledged":null`), 1),
		"unknown":        bytes.Replace(raw, []byte(`"scope":`), []byte(`"extra":true,"scope":`), 1),
		"future-scope":   bytes.Replace(raw, []byte(Scope), []byte(Scope+"-and-mac"), 1),
		"future-version": bytes.Replace(raw, []byte(SchemaVersion), []byte("tracebolt.cached-apt-updates.v2"), 1),
		"trailing":       append(bytes.Clone(raw), []byte(` {}`)...),
		"oversized":      append(bytes.Repeat([]byte(" "), MaxConsentBytes), raw...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeLocalConsent(b, binding); e == nil {
				t.Fatal("invalid consent accepted")
			}
		})
	}
	for _, other := range []string{strings.Repeat("b", 64), strings.Repeat("A", 64), ""} {
		if _, e := DecodeLocalConsent(raw, other); e == nil {
			t.Fatal("consent accepted another identity/cert/manager/profile binding")
		}
	}
	consent.Acknowledged = false
	if _, e := EncodeLocalConsent(consent, binding); e == nil {
		t.Fatal("encoder fabricated acknowledgement")
	}
}

func FuzzLocalConsent(f *testing.F) {
	binding := strings.Repeat("a", 64)
	raw, _ := EncodeLocalConsent(LocalConsent{ConsentVersion, SchemaVersion, Scope, binding, true}, binding)
	f.Add(raw)
	f.Add([]byte(`{"schemaVersion":[],"extensionVersion":{},"scope":null,"senderBinding":true,"acknowledged":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		consent, e := DecodeLocalConsent(raw, binding)
		if e != nil {
			return
		}
		encoded, e := EncodeLocalConsent(consent, binding)
		if e != nil {
			t.Fatal(e)
		}
		again, e := DecodeLocalConsent(encoded, binding)
		if e != nil || again != consent {
			t.Fatal("consent failed roundtrip")
		}
	})
}
