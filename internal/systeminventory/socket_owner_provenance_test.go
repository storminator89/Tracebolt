package systeminventory

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func provenanceFixture() (SocketOwnerProvenance, time.Time, int64) {
	at := time.Date(2026, 10, 6, 8, 0, 0, 123456789, time.UTC)
	return SocketOwnerProvenance{SchemaVersion: SocketOwnerSourceVersion, Scope: SocketOwnerSourceScope, GrantEpoch: strings.Repeat("1", 64), PolicyDigest: strings.Repeat("2", 64), AuthorityRevision: strings.Repeat("3", 64), ContextID: strings.Repeat("4", 64), StartedAt: at.Add(time.Second), FinishedAt: at.Add(2 * time.Second)}, at, 2000
}

func TestSocketOwnerProvenanceStrictContract(t *testing.T) {
	p, at, duration := provenanceFixture()
	raw, _ := json.Marshal(p)
	got, err := DecodeSocketOwnerProvenance(raw, at, duration)
	if err != nil || got != p {
		t.Fatal("valid source marker", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*SocketOwnerProvenance)
	}{
		{"version", func(p *SocketOwnerProvenance) { p.SchemaVersion += ".future" }},
		{"scope", func(p *SocketOwnerProvenance) { p.Scope = "host-admin" }},
		{"zero epoch", func(p *SocketOwnerProvenance) { p.GrantEpoch = strings.Repeat("0", 64) }},
		{"uppercase digest", func(p *SocketOwnerProvenance) { p.PolicyDigest = strings.Repeat("A", 64) }},
		{"short revision", func(p *SocketOwnerProvenance) { p.AuthorityRevision = "1" }},
		{"nonhex context", func(p *SocketOwnerProvenance) { p.ContextID = strings.Repeat("x", 64) }},
		{"zero time", func(p *SocketOwnerProvenance) { p.StartedAt = time.Time{} }},
		{"nonUTC", func(p *SocketOwnerProvenance) { p.StartedAt = p.StartedAt.In(time.FixedZone("same offset", 0)) }},
		{"before batch", func(p *SocketOwnerProvenance) { p.StartedAt = at.Add(-time.Nanosecond) }},
		{"reversed", func(p *SocketOwnerProvenance) { p.FinishedAt = p.StartedAt.Add(-time.Nanosecond) }},
		{"past batch", func(p *SocketOwnerProvenance) { p.FinishedAt = at.Add(2001 * time.Millisecond) }},
		{"helper too long", func(p *SocketOwnerProvenance) { p.FinishedAt = p.StartedAt.Add(5*time.Second + time.Nanosecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := p
			tc.change(&bad)
			if ValidateSocketOwnerProvenance(bad, at, duration) == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
	for name, bad := range map[string][]byte{
		"unknown":                      bytes.Replace(raw, []byte(`"schemaVersion":`), []byte(`"unknown":true,"schemaVersion":`), 1),
		"duplicate":                    bytes.Replace(raw, []byte(`"scope":`), []byte(`"scope":"x","scope":`), 1),
		"null":                         bytes.Replace(raw, []byte(`"contextId":"`+p.ContextID+`"`), []byte(`"contextId":null`), 1),
		"missing":                      bytes.Replace(raw, []byte(`"contextId":"`+p.ContextID+`",`), nil, 1),
		"offset":                       bytes.ReplaceAll(raw, []byte(`Z"`), []byte(`+00:00"`)),
		"noncanonical fractional time": bytes.ReplaceAll(raw, []byte(`123456789Z`), []byte(`1234567890Z`)),
		"trailing":                     append(bytes.Clone(raw), []byte(`{}`)...),
		"oversize":                     append(bytes.Clone(raw), bytes.Repeat([]byte(" "), MaxSocketOwnerProvenanceBytes)...),
		"invalid utf8":                 append(bytes.Clone(raw), 0xff),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSocketOwnerProvenance(bad, at, duration); err == nil {
				t.Fatal("ambiguous source accepted")
			}
		})
	}
}

func TestSocketOwnerProvenanceIntervalRoundingAndOverflow(t *testing.T) {
	p, at, _ := provenanceFixture()
	p.StartedAt = at
	for _, tc := range []struct {
		name     string
		end      time.Time
		duration int64
		ok       bool
	}{
		{"zero", at, 0, true},
		{"submillisecond", at.Add(time.Millisecond - time.Nanosecond), 0, true},
		{"one millisecond beyond", at.Add(time.Millisecond), 0, false},
		{"cross second truncation", at.Add(5 * time.Second), 5000, true},
		{"helper limit", at.Add(5*time.Second + time.Nanosecond), 5001, false},
		{"negative batch", at, -1, false},
		{"safe integer exceeded", at, MaxSafeInteger + 1, false},
		{"huge duration no overflow", at, MaxSafeInteger, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.FinishedAt = tc.end
			if (ValidateSocketOwnerProvenance(p, at, tc.duration) == nil) != tc.ok {
				t.Fatal("wrong interval result")
			}
		})
	}
	// More than time.Duration's 292-year range still checks the actual batch
	// milliseconds rather than a saturated/overflowed time.Duration.
	late := time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC)
	p.StartedAt, p.FinishedAt = late, late
	at = at.Truncate(time.Second)
	elapsed := late.UnixMilli() - at.UnixMilli()
	if ValidateSocketOwnerProvenance(p, at, elapsed-1) == nil || ValidateSocketOwnerProvenance(p, at, elapsed) != nil {
		t.Fatal("overflowed interval")
	}
}
