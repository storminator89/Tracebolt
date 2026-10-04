package offlinecatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStrictRootTypesNullsAndUnknownFields(t *testing.T) {
	replace := func(from, to string) []byte { return []byte(strings.Replace(syntheticFile, from, to, 1)) }
	cases := map[string][]byte{
		"null root":             []byte(`null`),
		"array root":            []byte(`[]`),
		"scalar root":           []byte(`true`),
		"empty":                 nil,
		"empty object":          []byte(`{}`),
		"missing schema":        replace(`"schema":"debian-tracker-normalized-1",`, ""),
		"missing synthetic":     replace(`"synthetic":true,`, ""),
		"null synthetic":        replace(`"synthetic":true`, `"synthetic":null`),
		"string synthetic":      replace(`"synthetic":true`, `"synthetic":"true"`),
		"integer synthetic":     replace(`"synthetic":true`, `"synthetic":1`),
		"null schema":           replace(`"schema":"debian-tracker-normalized-1"`, `"schema":null`),
		"wrong schema":          replace(`debian-tracker-normalized-1`, `debian-tracker-normalized-2`),
		"null covered sources":  replace(`"coveredSources":["tracebolt-private-fixture-source"]`, `"coveredSources":null`),
		"covered object":        replace(`"coveredSources":["tracebolt-private-fixture-source"]`, `"coveredSources":{}`),
		"null source name":      replace(`"coveredSources":["tracebolt-private-fixture-source"]`, `"coveredSources":[null]`),
		"empty coverage":        replace(`"coveredSources":["tracebolt-private-fixture-source"]`, `"coveredSources":[]`),
		"null rules":            []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture-source"],"rules":null}`),
		"missing rules":         []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture-source"]}`),
		"null rule":             []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture-source"],"rules":[null]}`),
		"null source":           replace(`"sourcePackage":"tracebolt-private-fixture-source"`, `"sourcePackage":null`),
		"null advisory":         replace(`"advisoryId":"CVE-2099-99990001"`, `"advisoryId":null`),
		"null release":          replace(`"release":"trixie"`, `"release":null`),
		"null status":           replace(`"status":"resolved"`, `"status":null`),
		"null fixed version":    replace(`"fixedVersion":"1:2.0-1+deb13u2"`, `"fixedVersion":null`),
		"null qualifications":   replace(`"qualifications":[]`, `"qualifications":null`),
		"null qualification":    replace(`"qualifications":[]`, `"qualifications":[null]`),
		"qualifications object": replace(`"qualifications":[]`, `"qualifications":{}`),
		"null archives":         replace(`"archiveVersions":[{"repository":"trixie-security","version":"1:2.0-1+deb13u2"}]`, `"archiveVersions":null`),
		"null archive":          replace(`{"repository":"trixie-security","version":"1:2.0-1+deb13u2"}`, `null`),
		"null repository":       replace(`"repository":"trixie-security"`, `"repository":null`),
		"null archive version":  replace(`"version":"1:2.0-1+deb13u2"`, `"version":null`),
		"root duplicate":        replace(`"synthetic":true`, `"synthetic":false,"synthetic":true`),
		"escaped duplicate":     replace(`"synthetic":true`, `"\u0073ynthetic":false,"synthetic":true`),
		"nested duplicate":      replace(`"status":"resolved"`, `"status":"open","status":"resolved"`),
		"case root":             replace(`"synthetic":true`, `"Synthetic":true`),
		"case nested":           replace(`"status":"resolved"`, `"Status":"resolved"`),
		"misplaced known field": replace(`"status":"resolved"`, `"status":"resolved","synthetic":true`),
		"invalid UTF8":          append([]byte(syntheticFile), 0xff),
		"trailing object":       append([]byte(syntheticFile), []byte(`{}`)...),
		"trailing scalar":       append([]byte(syntheticFile), []byte(`null`)...),
		"XML":                   []byte(`<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///private/example">]><x>&secret;</x>`),
		"bad version":           replace(`1:2.0-1+deb13u2`, "not a version"),
		"uncovered source":      replace(`"sourcePackage":"tracebolt-private-fixture-source"`, `"sourcePackage":"fixture-other-source"`),
	}
	for _, field := range []string{"trust", "originAssurance", "publicUrl", "provider", "profile", "verified", "signatureVerified", "publishedAt", "importedAt", "sha256", "revision", "id", "filename", "release", "declaredRelease"} {
		cases["untrusted root "+field] = replace(`"synthetic":true`, `"synthetic":true,"`+field+`":"private-untrusted-marker"`)
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			candidate, err := Parse(context.Background(), raw, testTime())
			requireError(t, err, ErrInvalid)
			if candidate.data != nil {
				t.Fatal("malformed input returned candidate")
			}
			if strings.Contains(fmt.Sprintf("%+v", err), "private-") {
				t.Fatal("raw input in error diagnostics")
			}
		})
	}
}

func TestOnlyTrixieAcceptedAndNoRealAuthority(t *testing.T) {
	for _, release := range []string{"bookworm", "sid", "bullseye", "13", "Trixie", "trixie-security", "noble"} {
		raw := strings.Replace(syntheticFile, `"release":"trixie"`, `"release":"`+release+`"`, 1)
		_, err := Parse(context.Background(), []byte(raw), testTime())
		requireError(t, err, ErrUnsupportedRelease)
	}
	// A false synthetic declaration is accepted only as unverified input. This
	// fixture alteration is not evidence of an actual non-synthetic feed.
	raw := strings.Replace(syntheticFile, `"synthetic":true`, `"synthetic":false`, 1)
	candidate, err := Parse(context.Background(), []byte(raw), testTime())
	if err != nil {
		t.Fatal(err)
	}
	if candidate.data.metadata.Synthetic || candidate.data.metadata.OriginAssurance != "unverified" || candidate.data.metadata.Freshness != "unknown" {
		t.Fatal("declaration granted authority")
	}
	_, err = Parse(context.Background(), []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture-source"],"rules":[]}`), testTime())
	if err != nil {
		t.Fatal("explicit empty rules with nonempty coverage must remain supported")
	}
}

func TestDuplicateRecordsAndBoundedNestedArrays(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal([]byte(syntheticFile), &root); err != nil {
		t.Fatal(err)
	}
	rules := root["rules"].([]any)
	rule := rules[0].(map[string]any)
	cases := map[string]func(){
		"rules": func() { root["rules"] = append(rules, rules[0]) },
		"sources": func() {
			root["coveredSources"] = []string{"tracebolt-private-fixture-source", "tracebolt-private-fixture-source"}
		},
		"archives": func() {
			archives := rule["archiveVersions"].([]any)
			rule["archiveVersions"] = append(archives, archives[0])
		},
		"qualifications bound": func() { rule["qualifications"] = strings.Split(strings.Repeat("fixture,", 16)+"fixture", ",") },
		"archive bound": func() {
			values := make([]map[string]string, 33)
			for i := range values {
				values[i] = map[string]string{"repository": fmt.Sprintf("fixture-%d", i), "version": "1.0"}
			}
			rule["archiveVersions"] = values
		},
		"long string": func() { rule["advisoryId"] = strings.Repeat("x", 1025) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(syntheticFile), &root); err != nil {
				t.Fatal(err)
			}
			rules = root["rules"].([]any)
			rule = rules[0].(map[string]any)
			mutate()
			raw, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(context.Background(), raw, testTime())
			requireError(t, err, ErrInvalid)
		})
	}
}

func TestExactByteAndRuleAndSourceLimits(t *testing.T) {
	exact := append([]byte(syntheticFile), bytes.Repeat([]byte(" "), MaxBytes-len(syntheticFile))...)
	candidate, err := Parse(context.Background(), exact, testTime())
	if err != nil || candidate.data.metadata.ByteCount != MaxBytes {
		t.Fatal("exact byte limit rejected")
	}
	_, err = Parse(context.Background(), append(exact, ' '), testTime())
	requireError(t, err, ErrTooLarge)
	for _, over := range []bool{false, true} {
		n := MaxRules
		if over {
			n++
		}
		for _, kind := range []string{"rules", "sources"} {
			t.Run(fmt.Sprintf("%s-%d", kind, n), func(t *testing.T) {
				sources := []string{"fixture-source-00000"}
				rules := []map[string]string{}
				for i := range n {
					if kind == "sources" {
						if i > 0 {
							sources = append(sources, fmt.Sprintf("fixture-source-%05d", i))
						}
					} else {
						rules = append(rules, map[string]string{"sourcePackage": sources[0], "advisoryId": fmt.Sprintf("SYNTHETIC-2099-%05d", i), "release": "trixie", "status": "undetermined"})
					}
				}
				raw, err := json.Marshal(map[string]any{"schema": "debian-tracker-normalized-1", "synthetic": true, "coveredSources": sources, "rules": rules})
				if err != nil || len(raw) > MaxBytes {
					t.Fatal("invalid bounded fixture")
				}
				candidate, err := Parse(context.Background(), raw, testTime())
				if over {
					requireError(t, err, ErrTooLarge)
				} else if err != nil {
					t.Fatalf("exact collection limit rejected: %v", err)
				} else if candidate.data.metadata.RuleCount != len(rules) || candidate.data.metadata.CoveredSourceCount != len(sources) {
					t.Fatal("wrong limit metadata")
				}
			})
		}
	}
	depth := []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture-source"],"rules":` + strings.Repeat("[", 18) + "null" + strings.Repeat("]", 18) + "}")
	_, err = Parse(context.Background(), depth, testTime())
	requireError(t, err, ErrTooLarge)
}

func FuzzParseRejectsWithoutDisclosure(f *testing.F) {
	f.Add([]byte(syntheticFile))
	f.Add([]byte(`{"schema":"wrong"}`))
	f.Add([]byte(`{"synthetic":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		candidate, err := Parse(context.Background(), raw, testTime())
		if err != nil {
			if candidate.data != nil {
				t.Fatal("failed parse returned data")
			}
			if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrUnsupportedRelease) && !errors.Is(err, ErrTooLarge) {
				t.Fatal("unbounded error")
			}
		} else if candidate.data.metadata.OriginAssurance != "unverified" || candidate.data.metadata.Freshness != "unknown" || candidate.data.metadata.PublishedAt != nil {
			t.Fatal("parse manufactured authority")
		}
	})
}
