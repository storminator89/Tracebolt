// Package windowsstorageio carries separately consented, fixed local aggregate
// PhysicalDisk(_Total) performance context. It does not attribute I/O to a disk,
// volume, process or device, or establish an atomic/stable provider population.
package windowsstorageio

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-storage-io.v1"
const ConsentVersion = "tracebolt.windows-storage-io-consent.v1"
const Scope = "windows-storage-io-v1"
const Source = "PDH PhysicalDisk(_Total)"
const MaxBytes = 2 * 1024
const ProviderBudget = 2 * time.Second
const CollectionBudget = ProviderBudget
const MinSampleInterval = time.Second
const Privacy = "Read and send eight fixed local aggregate PhysicalDisk(_Total) performance counters: read/write bytes per second, read/write operations per second, read/write average latency in seconds, average queue length and current queue length, with sample timing and independent unavailable states. Separate default-off local scope; earlier scopes and receipts do not authorize it. Two samples at least one second apart; provider aggregate only, without an atomic snapshot or stable disk-population claim. No per-disk, volume, process or device attribution, cross-source joins, identifiers, arbitrary counters/queries, enumeration, counter enablement, IOCTLs, shell, remote reads, writes, privileges or health verdict. Operator-only; no AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test sends aggregate disk read/write throughput, operations, latency, queue lengths and sample timing in plaintext. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_storage_io_invalid")
var ErrDisabled = errors.New("windows_storage_io_scope_disabled")
var ErrDenied = errors.New("windows_storage_io_access_denied")
var ErrUnavailable = errors.New("windows_storage_io_unavailable")
var ErrUnsupported = errors.New("windows_storage_io_unsupported_platform")
var ErrMetadata = errors.New("windows_storage_io_invalid_metadata")
var ErrBounds = errors.New("windows_storage_io_bounds")
var ErrPartial = errors.New("windows_storage_io_partial_result")
var ErrBudget = errors.New("windows_storage_io_budget_exhausted")
var ErrMissing = errors.New("windows_storage_io_counter_missing")
var ErrReset = errors.New("windows_storage_io_counter_reset")
var ErrTimebase = errors.New("windows_storage_io_invalid_timebase")
var ErrIdle = errors.New("windows_storage_io_idle")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Metric struct {
	Value   *float64 `json:"value"`
	Quality string   `json:"quality"`
	Reason  string   `json:"reason"`
}
type PerfDisk struct {
	Quality                  string     `json:"quality"`
	Reason                   string     `json:"reason"`
	Source                   string     `json:"source"`
	SampleStartedAt          *time.Time `json:"sampleStartedAt"`
	SampleEndedAt            *time.Time `json:"sampleEndedAt"`
	IntervalMilliseconds     *uint64    `json:"intervalMilliseconds"`
	ReadBytesPerSecond       Metric     `json:"readBytesPerSecond"`
	WriteBytesPerSecond      Metric     `json:"writeBytesPerSecond"`
	ReadOperationsPerSecond  Metric     `json:"readOperationsPerSecond"`
	WriteOperationsPerSecond Metric     `json:"writeOperationsPerSecond"`
	ReadLatencySeconds       Metric     `json:"readLatencySeconds"`
	WriteLatencySeconds      Metric     `json:"writeLatencySeconds"`
	AverageQueueLength       Metric     `json:"averageQueueLength"`
	CurrentQueueLength       Metric     `json:"currentQueueLength"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	PerfDisk      PerfDisk  `json:"perfDisk"`
}
type Request struct {
	Consent       Consent
	SenderBinding string
	GenerationID  string
	CollectedAt   time.Time
}

func hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func canonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func DecodeConsent(raw []byte, binding string) (Consent, error) {
	var c Consent
	if canonical(raw, &c, 1024) != nil || c.SchemaVersion != ConsentVersion || c.Scope != Scope || !hex(binding, 64) || c.SenderBinding != binding || !hex(c.GrantID, 32) {
		return Consent{}, ErrInvalid
	}
	return c, nil
}
func EncodeConsent(c Consent, binding string) ([]byte, error) {
	b, e := json.Marshal(c)
	if e != nil {
		return nil, ErrInvalid
	}
	if _, e = DecodeConsent(b, binding); e != nil {
		return nil, e
	}
	return b, nil
}
func validReason(s string) bool {
	switch s {
	case ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrBudget.Error(), ErrMissing.Error(), ErrReset.Error(), ErrTimebase.Error():
		return true
	}
	return false
}
func unavailableQuality(reason string) string {
	if reason == ErrDenied.Error() {
		return "denied"
	}
	return "unavailable"
}
func validMetric(m Metric, latency bool) bool {
	if m.Quality == "observed" {
		return m.Value != nil && !math.IsNaN(*m.Value) && !math.IsInf(*m.Value, 0) && *m.Value >= 0 && !math.Signbit(*m.Value) && m.Reason == ""
	}
	return m.Value == nil && m.Quality == unavailableQuality(m.Reason) && (validReason(m.Reason) || latency && m.Reason == ErrIdle.Error())
}
func metricPointers(p *PerfDisk) [8]*Metric {
	return [8]*Metric{&p.ReadBytesPerSecond, &p.WriteBytesPerSecond, &p.ReadOperationsPerSecond, &p.WriteOperationsPerSecond, &p.ReadLatencySeconds, &p.WriteLatencySeconds, &p.AverageQueueLength, &p.CurrentQueueLength}
}

// Source summaries are mechanically derived from the eight independent fields.
// Idle latency is unavailable context, not a zero-latency observation.
func summarize(p *PerfDisk) {
	fields := metricPointers(p)
	allObserved, same := true, true
	reason := fields[0].Reason
	for _, m := range fields {
		allObserved = allObserved && m.Quality == "observed"
		same = same && m.Reason == reason && m.Quality == fields[0].Quality
	}
	switch {
	case allObserved:
		p.Quality = "observed"
		p.Reason = ""
	case same:
		p.Quality = fields[0].Quality
		p.Reason = reason
	default:
		p.Quality = "partial"
		p.Reason = ErrPartial.Error()
	}
}
func validPerfDisk(p PerfDisk) bool {
	if p.Source != Source {
		return false
	}
	fields := metricPointers(&p)
	observed := false
	for i, m := range fields {
		if !validMetric(*m, i == 4 || i == 5) {
			return false
		}
		observed = observed || m.Quality == "observed"
	}
	for _, pair := range [][2]int{{2, 4}, {3, 5}} {
		ops, latency := fields[pair[0]], fields[pair[1]]
		if latency.Reason == ErrIdle.Error() && (ops.Value == nil || *ops.Value != 0) {
			return false
		}
		if latency.Quality == "observed" && (ops.Value == nil || *ops.Value <= 0) {
			return false
		}
		// A valid idle rate always suppresses a misleading measured zero latency.
		if ops.Value != nil && *ops.Value == 0 && latency.Reason != ErrIdle.Error() {
			return false
		}
	}
	hasTime := p.SampleStartedAt != nil || p.SampleEndedAt != nil || p.IntervalMilliseconds != nil
	if hasTime {
		if p.SampleStartedAt == nil || p.SampleEndedAt == nil || p.IntervalMilliseconds == nil || !validTime(*p.SampleStartedAt) || !validTime(*p.SampleEndedAt) {
			return false
		}
		elapsed := p.SampleEndedAt.Sub(*p.SampleStartedAt)
		if elapsed < MinSampleInterval || elapsed > ProviderBudget || *p.IntervalMilliseconds != uint64(elapsed.Milliseconds()) {
			return false
		}
	} else if observed {
		return false
	}
	expected := p
	summarize(&expected)
	return p.Quality == expected.Quality && p.Reason == expected.Reason
}
func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validPerfDisk(s.PerfDisk) {
		return ErrInvalid
	}
	if s.PerfDisk.SampleStartedAt != nil && s.PerfDisk.SampleStartedAt.Before(s.CollectedAt) {
		return ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxBytes {
		return ErrInvalid
	}
	return nil
}
func Decode(raw []byte) (Snapshot, error) {
	var s Snapshot
	if canonical(raw, &s, MaxBytes) != nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
func Encode(s Snapshot) ([]byte, error) {
	if Validate(s) != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(s)
}
func ValidateBinding(s Snapshot, generation, grant string, at time.Time) error {
	if Validate(s) != nil || s.GenerationID != generation || s.GrantID != grant || !s.CollectedAt.Equal(at) {
		return ErrInvalid
	}
	return nil
}
func EmptyMetric(reason string) Metric {
	return Metric{Quality: unavailableQuality(reason), Reason: reason}
}
func EmptyPerfDisk(reason string) PerfDisk {
	p := PerfDisk{Quality: unavailableQuality(reason), Reason: reason, Source: Source}
	for _, m := range metricPointers(&p) {
		*m = EmptyMetric(reason)
	}
	return p
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptyPerfDisk(reason)}
}
func Meaningful(s Snapshot) bool {
	if Validate(s) != nil {
		return false
	}
	for _, m := range metricPointers(&s.PerfDisk) {
		if m.Quality == "observed" {
			return true
		}
	}
	return false
}
func FitBudget(s Snapshot, budget int) (Snapshot, error) {
	b, e := Encode(s)
	if e != nil {
		return Snapshot{}, e
	}
	if len(b) > budget {
		return Snapshot{}, ErrBounds
	}
	return s, nil
}
