package windowsservicehealth

import (
	"context"
	"localrmm/internal/windowsfullservices"
	"sort"
	"time"
)

const CompleteStateSchema = "tracebolt.windows-service-state.v2"
const CompleteSchemaVersion = "tracebolt.windows-service-view.v2"
const CompleteSourceKind = "windows_full_services"

// The default foreground cycle waits 30 seconds after serialized optional work.
// Complete services capture at most once per minute; successful context/transfer
// stages can exceed the old preview's 120-second window. Five minutes is an
// explicit source-age ceiling, not a guarantee of delivery or a refreshed age.
const CompleteMaxAge = 5 * time.Minute

type SourceBinding struct {
	Kind          string `json:"kind"`
	GrantID       string `json:"grantId"`
	GrantRevision uint64 `json:"grantRevision"`
}
type Provenance struct {
	Kind              string    `json:"kind"`
	GrantID           string    `json:"grantId"`
	GrantRevision     uint64    `json:"grantRevision"`
	GenerationID      string    `json:"generationId"`
	ManifestSHA256    string    `json:"manifestSha256"`
	Sequence          uint64    `json:"sequence"`
	CapturedAt        time.Time `json:"capturedAt"`
	CaptureFinishedAt time.Time `json:"captureFinishedAt"`
	ReceivedAt        time.Time `json:"receivedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	RowCount          int       `json:"rowCount"`
}
type CompleteSample struct {
	Source Provenance
	Rows   []windowsfullservices.Row
}

func (p Provenance) Binding() SourceBinding { return SourceBinding{p.Kind, p.GrantID, p.GrantRevision} }
func (p Provenance) Valid() bool {
	return p.Kind == CompleteSourceKind && windowsfullservices.ValidHex(p.GrantID, 32) && windowsfullservices.ValidSequence(p.GrantRevision) && windowsfullservices.ValidHex(p.ManifestSHA256, 64) && len(p.GenerationID) == 39 && p.GenerationID[:7] == "sample_" && windowsfullservices.ValidHex(p.GenerationID[7:], 32) && windowsfullservices.ValidSequence(p.Sequence) && validTime(p.CapturedAt) && validTime(p.CaptureFinishedAt) && !p.CaptureFinishedAt.Before(p.CapturedAt) && p.CaptureFinishedAt.Sub(p.CapturedAt) <= windowsfullservices.CaptureTimeout && validTime(p.ReceivedAt) && !p.ReceivedAt.Before(p.CaptureFinishedAt) && p.ExpiresAt.Equal(p.CapturedAt.Add(windowsfullservices.Retention)) && p.RowCount >= 0 && p.RowCount <= windowsfullservices.MaxRows
}
func (p Provenance) Fresh(now time.Time) bool {
	return p.Valid() && freshAge(p.CapturedAt, now, CompleteMaxAge) && freshAge(p.ReceivedAt, now, CompleteMaxAge) && now.Before(p.ExpiresAt)
}
func freshAge(at, now time.Time, age time.Duration) bool {
	return validTime(at) && validTime(now) && !at.After(now) && now.Sub(at) <= age
}
func CompleteServices(names []string) ([]string, error) {
	if names == nil || len(names) > MaxServices {
		return nil, ErrInvalid
	}
	out := append([]string{}, names...)
	sort.Strings(out)
	for i, n := range out {
		if !completeName(n) || i > 0 && out[i-1] == n {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func completeName(n string) bool {
	return windowsfullservices.ValidateRow(windowsfullservices.Row{Name: n, DisplayNameQuality: "unavailable", StateQuality: "unavailable", PIDQuality: "unavailable"}) == nil
}
func (s State) complete() bool { return s.SchemaVersion == CompleteStateSchema }
func NewComplete() State       { s := New(); s.SchemaVersion = CompleteStateSchema; return s }
func (s State) names(names []string) ([]string, error) {
	if s.complete() {
		return CompleteServices(names)
	}
	return Services(names)
}
func (s State) validName(n string) bool {
	if s.complete() {
		return completeName(n)
	}
	return validText(n, true)
}
func (in Input) completeInventory(now time.Time) *Inventory {
	sample := in.Sample.Complete
	if !in.authorized(now) || sample == nil || !sample.Source.Fresh(now) || sample.Rows == nil || len(sample.Rows) > MaxServices || len(sample.Rows) > sample.Source.RowCount {
		return nil
	}
	source := sample.Source
	expected, e := windowsfullservices.GenerationID(in.DeviceID, source.GrantID, source.Sequence)
	if e != nil || source.GenerationID != expected {
		return nil
	}
	rows := []Choice{}
	for i, r := range sample.Rows {
		if windowsfullservices.ValidateRow(r) != nil || i > 0 && sample.Rows[i-1].Name >= r.Name {
			return nil
		}
		display, state := "", "unknown"
		if r.DisplayName != nil {
			display = *r.DisplayName
		}
		if r.State != nil {
			state = *r.State
		}
		rows = append(rows, Choice{Name: r.Name, DisplayName: display, State: state})
	}
	return &Inventory{CollectedAt: source.CapturedAt, ReceivedAt: source.ReceivedAt, Sequence: source.Sequence, Quality: "healthy", Complete: true, CountExact: true, ObservedCount: uint32(source.RowCount), Services: rows, Source: &source}
}
func (in Input) normalized() Input {
	if !in.Complete {
		return in
	}
	in.Sequence = 0
	in.ReceivedAt = time.Time{}
	in.Sample.CollectedAt = time.Time{}
	if in.Sample.Complete != nil {
		p := in.Sample.Complete.Source
		in.Sequence = p.Sequence
		in.ReceivedAt = p.ReceivedAt
		in.Sample.CollectedAt = p.CapturedAt
	}
	return in
}
func sameObservation(a, b Observation) bool {
	if a.State != b.State || !a.CollectedAt.Equal(b.CollectedAt) || !a.ReceivedAt.Equal(b.ReceivedAt) || a.Sequence != b.Sequence || (a.Source == nil) != (b.Source == nil) {
		return false
	}
	return a.Source == nil || *a.Source == *b.Source
}
func validSourceObservation(o Observation, at time.Time) bool {
	if o.Source == nil {
		return validObservation(o, at)
	}
	return (o.State == "running" || bad(o.State)) && o.Source.Fresh(at) && o.Sequence == o.Source.Sequence && o.CollectedAt.Equal(o.Source.CapturedAt) && o.ReceivedAt.Equal(o.Source.ReceivedAt)
}

// Requested exact names are internal bounded selectors, not endpoint grants.
type completeSelectionsKey struct{}

func WithCompleteSelections(ctx context.Context, selections map[string][]string) context.Context {
	copy := map[string][]string{}
	for id, names := range selections {
		copy[id] = append([]string{}, names...)
	}
	return context.WithValue(ctx, completeSelectionsKey{}, copy)
}
func CompleteSelections(ctx context.Context) (map[string][]string, error) {
	v, _ := ctx.Value(completeSelectionsKey{}).(map[string][]string)
	if len(v) > MaxDevices {
		return nil, ErrInvalid
	}
	for _, names := range v {
		if _, e := CompleteServices(names); e != nil {
			return nil, e
		}
	}
	return v, nil
}
func validBinding(b SourceBinding) bool {
	return b.Kind == CompleteSourceKind && windowsfullservices.ValidHex(b.GrantID, 32) && windowsfullservices.ValidSequence(b.GrantRevision)
}

func (s State) validEvidence(o Observation, at time.Time) bool {
	if (o.Source != nil) != s.complete() || !validSourceObservation(o, at) {
		return false
	}
	if o.Source != nil {
		generation, e := windowsfullservices.GenerationID(s.DeviceID, o.Source.GrantID, o.Source.Sequence)
		return e == nil && generation == o.Source.GenerationID
	}
	return true
}

func generationFor(device string, p Provenance) (string, error) {
	return windowsfullservices.GenerationID(device, p.GrantID, p.Sequence)
}
