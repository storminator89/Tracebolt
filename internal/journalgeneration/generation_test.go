package journalgeneration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixtureTuple() Tuple {
	return Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}
}
func TestTupleExactUint64CanonicalDetachedRoundTrip(t *testing.T) {
	for _, revision := range []uint64{1, 1<<53 + 1, ^uint64(0)} {
		value := fixtureTuple()
		value.Revision = revision
		raw, err := Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(raw)
		if err != nil || got != value {
			t.Fatalf("uint64 round trip: %v %v", got, err)
		}
		clear(raw)
		if got != value {
			t.Fatal("tuple aliases input")
		}
		detached := got
		detached.Generation = strings.Repeat("c", 64)
		if got != value || detached == got {
			t.Fatal("tuple not detached comparable value")
		}
	}
}
func TestTupleRejectsMalformedJSONAndInvalidValues(t *testing.T) {
	good := fixtureTuple()
	raw, _ := Encode(good)
	variants := [][]byte{nil, []byte("null"), []byte("{}"), append(bytes.Clone(raw), ' '), append(bytes.Clone(raw), []byte("{}")...), bytes.Repeat([]byte(" "), MaxTupleBytes+1)}
	for _, replacement := range []string{`0`, `1`, `"0"`, `"01"`, `"+1"`, `"-1"`, `"1.0"`, `"1e0"`, `"18446744073709551616"`, `"\u0031"`, `null`} {
		variants = append(variants, bytes.Replace(raw, []byte(`"1"`), []byte(replacement), 1))
	}
	for _, prefix := range []string{`"unknown":1,`, `"revision":"1",`, `"generation":"` + good.Generation + `",`} {
		variants = append(variants, append([]byte("{"+prefix), raw[1:]...))
	}
	for _, member := range []string{`"revision":"1",`, `"generation":"` + good.Generation + `",`, `,"policyDigest":"` + good.PolicyDigest + `"`} {
		variants = append(variants, bytes.Replace(raw, []byte(member), nil, 1))
	}
	for i, b := range variants {
		if _, err := Decode(b); err == nil {
			t.Fatalf("malformed tuple %d accepted: %s", i, b)
		}
		var nested struct {
			Tuple Tuple `json:"tuple"`
		}
		if bytes.Equal(b, bytes.TrimSpace(b)) && json.Unmarshal(append(append([]byte(`{"tuple":`), b...), '}'), &nested) == nil {
			t.Fatalf("nested malformed tuple %d accepted", i)
		}
	}
	for _, mutate := range []func(*Tuple){func(t *Tuple) { t.Revision = 0 }, func(t *Tuple) { t.Generation = "" }, func(t *Tuple) { t.Generation = strings.Repeat("0", 64) }, func(t *Tuple) { t.Generation = strings.Repeat("A", 64) }, func(t *Tuple) { t.Generation = strings.Repeat("a", 63) }, func(t *Tuple) { t.PolicyDigest = strings.Repeat("b", 64) }, func(t *Tuple) { t.PolicyDigest = "sha256:" + strings.Repeat("0", 64) }, func(t *Tuple) { t.PolicyDigest = "sha256:" + strings.Repeat("B", 64) }} {
		bad := good
		mutate(&bad)
		if Validate(bad) == nil {
			t.Fatal("invalid tuple validated")
		}
		if _, err := Encode(bad); err == nil {
			t.Fatal("invalid tuple encoded")
		}
	}
}
func TestReportCanonicalFreshnessMetadataOnly(t *testing.T) {
	r := Report{SchemaVersion: ReportVersion, Tuple: fixtureTuple(), Sequence: ^uint64(0), ObservedAt: time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)}
	raw, err := EncodeReport(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeReport(raw)
	if err != nil || got != r {
		t.Fatalf("report roundtrip %v", err)
	}
	if len(raw) > MaxReportBytes || bytes.Contains(raw, []byte("allowedUnits")) || bytes.Contains(raw, []byte("message")) {
		t.Fatal("report not metadata-only")
	}
	for _, mutate := range []func(*Report){func(r *Report) { r.SchemaVersion = "tracebolt.journal-generation-report.v2" }, func(r *Report) { r.Sequence = 0 }, func(r *Report) { r.ObservedAt = time.Time{} }, func(r *Report) { r.ObservedAt = r.ObservedAt.In(time.FixedZone("offset", 3600)) }, func(r *Report) { r.ObservedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, func(r *Report) { r.Tuple.Revision = 0 }} {
		bad := r
		mutate(&bad)
		if ValidateReport(bad) == nil {
			t.Fatal("invalid report validated")
		}
		if _, err := EncodeReport(bad); err == nil {
			t.Fatal("invalid report encoded")
		}
	}
	for _, bad := range [][]byte{[]byte("null"), append([]byte(`{"sequence":"1",`), raw[1:]...), append([]byte(`{"scope":"system",`), raw[1:]...), bytes.Replace(raw, []byte(`"sequence":"18446744073709551615"`), []byte(`"sequence":"01"`), 1), bytes.Replace(raw, []byte(`"observedAt":"2026-10-05T13:00:00Z"`), []byte(`"observedAt":"2026-10-05T13:00:00+00:00"`), 1), bytes.Replace(raw, []byte(`"policyGeneration":{`), []byte(`"policyGeneration":{"revision":"1",`), 1), bytes.Repeat([]byte(" "), MaxReportBytes+1)} {
		if _, err := DecodeReport(bad); err == nil {
			t.Fatalf("malformed report accepted: %s", bad)
		}
	}
}
func FuzzGenerationMetadata(f *testing.F) {
	tuple, _ := Encode(fixtureTuple())
	f.Add(tuple)
	report, _ := EncodeReport(Report{SchemaVersion: ReportVersion, Tuple: fixtureTuple(), Sequence: 1, ObservedAt: time.Unix(1800000000, 0).UTC()})
	f.Add(report)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxReportBytes+1 {
			return
		}
		if got, err := Decode(raw); err == nil {
			b, err := Encode(got)
			if err != nil || !bytes.Equal(b, raw) {
				t.Fatal("noncanonical accepted tuple")
			}
		}
		if got, err := DecodeReport(raw); err == nil {
			b, err := EncodeReport(got)
			if err != nil || !bytes.Equal(b, raw) {
				t.Fatal("noncanonical accepted report")
			}
		}
	})
}
