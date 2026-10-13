// Package macosinventorywire is an inactive, pure macOS inventory contract.
// Validation proves canonical structure and supplied bindings, never consent,
// fresh enrollment, TLS possession, current-leaf validity or scope admission.
// There is no transport, clock, storage, collector call or runtime registration.
package macosinventorywire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"localrmm/internal/macosinventory"
)

const (
	Profile          = "macos-read-inventory-v1"
	Platform         = "darwin"
	ReportVersion    = "tracebolt.macos-read-inventory-report.v1"
	ControlVersion   = "tracebolt.macos-read-inventory-control.v1"
	ReceiptVersion   = "tracebolt.macos-read-inventory-receipt.v1"
	MaxSnapshotBytes = 512 * 1024
	MaxReportBytes   = 520 * 1024
	MaxControlBytes  = 2048
	MaxReceiptBytes  = 2048
	MaxSequence      = uint64(1<<53 - 1)
	CaptureInterval  = time.Minute
	Retention        = 24 * time.Hour
)

var (
	ErrInvalid  = errors.New("macos_inventory_wire_invalid")
	ErrBounds   = errors.New("macos_inventory_wire_bounds")
	ErrConflict = errors.New("macos_inventory_wire_conflict")
	ErrDisabled = errors.New("macos_inventory_wire_terminal_disabled")
	ErrExpired  = errors.New("macos_inventory_wire_expired")
)

// Binding refers to the ORIGINAL enrollment/sender binding, not a renewable
// current leaf. Its provenance and the profile's freshness are external checks.
type Binding struct {
	Platform      string `json:"platform"`
	Profile       string `json:"profile"`
	DeviceID      string `json:"deviceId"`
	SenderBinding string `json:"senderBinding"`
}

// Control v1 has exactly one grant: enabled at revisions (1,1), terminally
// disabled at (1,2). The immutable enable records initial CaptureFloor zero;
// live floors are separate durable state. Disable records the final durably
// reserved sequence, including lost/failed/pending attempts (zero if none).
// Neither a new ID nor a higher revision may reenable this identity in v1.
type Control struct {
	SchemaVersion   string    `json:"schemaVersion"`
	Binding         Binding   `json:"binding"`
	GrantID         string    `json:"grantId"`
	GrantRevision   uint64    `json:"grantRevision"`
	ControlRevision uint64    `json:"controlRevision"`
	Enabled         bool      `json:"enabled"`
	CaptureFloor    uint64    `json:"captureFloor"`
	ChangedAt       time.Time `json:"changedAt"`
}

// Report embeds a typed canonical JSON object, never base64 or an unchecked raw
// JSON fragment. SourceQuality describes only these five selected sources and
// their emitted fields, never all installed apps, processes or network topology.
type Report struct {
	SchemaVersion   string                  `json:"schemaVersion"`
	Binding         Binding                 `json:"binding"`
	GrantID         string                  `json:"grantId"`
	GrantRevision   uint64                  `json:"grantRevision"`
	ControlRevision uint64                  `json:"controlRevision"`
	CaptureSequence uint64                  `json:"captureSequence"`
	GenerationID    string                  `json:"generationId"`
	CollectedAt     time.Time               `json:"collectedAt"`
	ExpiresAt       time.Time               `json:"expiresAt"`
	SnapshotSHA256  string                  `json:"snapshotSha256"`
	SourceQuality   string                  `json:"sourceQuality"`
	Snapshot        macosinventory.Snapshot `json:"snapshot"`
}

// Receipt is a data contract, not proof of authentication or durable admission.
// The future integrator may emit it only after its separately guarded commit.
// RequestSHA256 covers exact request bytes; retries retain the original receipt.
type Receipt struct {
	SchemaVersion   string     `json:"schemaVersion"`
	Kind            string     `json:"kind"`
	Binding         Binding    `json:"binding"`
	GrantID         string     `json:"grantId"`
	GrantRevision   uint64     `json:"grantRevision"`
	ControlRevision uint64     `json:"controlRevision"`
	CaptureFloor    uint64     `json:"captureFloor"`
	GenerationID    string     `json:"generationId"`
	CollectedAt     *time.Time `json:"collectedAt"`
	SnapshotSHA256  string     `json:"snapshotSha256"`
	RequestSHA256   string     `json:"requestSha256"`
	Status          string     `json:"status"`
	ReceivedAt      time.Time  `json:"receivedAt"`
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func validSequence(n uint64) bool { return n > 0 && n <= MaxSequence }
func ValidateBinding(b Binding) error {
	if b.Platform != Platform || b.Profile != Profile || len(b.DeviceID) != 38 || b.DeviceID[:6] != "agent_" || !validHex(b.DeviceID[6:], 32) || !validHex(b.SenderBinding, 64) {
		return ErrInvalid
	}
	return nil
}
func digest(domain string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(domain + "\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func requestDigest(raw []byte) string {
	return digest("tracebolt.macos-read-inventory.request.v1", raw)
}
func canonical(raw []byte, max int, out any) error {
	if len(raw) > max {
		return ErrBounds
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, encoded) {
		return ErrInvalid
	}
	return nil
}
func encode(v any, max int) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(raw) > max {
		return nil, ErrBounds
	}
	return raw, nil
}

func ValidateControl(c Control) error {
	if c.SchemaVersion != ControlVersion || ValidateBinding(c.Binding) != nil || !validHex(c.GrantID, 32) || c.GrantRevision != 1 || !validTime(c.ChangedAt) || c.CaptureFloor > MaxSequence {
		return ErrInvalid
	}
	if c.Enabled {
		if c.ControlRevision != 1 || c.CaptureFloor != 0 {
			return ErrInvalid
		}
	} else if c.ControlRevision != 2 {
		return ErrInvalid
	}
	return nil
}
func EncodeControl(c Control) ([]byte, error) {
	if err := ValidateControl(c); err != nil {
		return nil, err
	}
	return encode(c, MaxControlBytes)
}
func DecodeControl(raw []byte) (Control, error) {
	var c Control
	if err := canonical(raw, MaxControlBytes, &c); err != nil {
		return Control{}, err
	}
	if err := ValidateControl(c); err != nil {
		return Control{}, err
	}
	return c, nil
}

// GenerationID is deterministic and domain-separated. It grants no authority.
func GenerationID(b Binding, grant string, revision, sequence uint64) (string, error) {
	if ValidateBinding(b) != nil || !validHex(grant, 32) || revision != 1 || !validSequence(sequence) {
		return "", ErrInvalid
	}
	raw, _ := json.Marshal(struct {
		Binding         Binding `json:"binding"`
		GrantID         string  `json:"grantId"`
		GrantRevision   uint64  `json:"grantRevision"`
		CaptureSequence uint64  `json:"captureSequence"`
	}{b, grant, revision, sequence})
	return "sample_" + digest("tracebolt.macos-read-inventory.generation.v1", raw)[:32], nil
}
func SnapshotDigest(s macosinventory.Snapshot) (string, error) {
	raw, err := macosinventory.Encode(s)
	if err != nil {
		return "", ErrInvalid
	}
	if len(raw) > MaxSnapshotBytes {
		return "", ErrBounds
	}
	return digest("tracebolt.macos-read-inventory.snapshot.v1", raw), nil
}
func sourceQuality(s macosinventory.Snapshot) string {
	observed := 0
	for _, q := range []string{s.Hardware.Quality, s.Receipts.Quality, s.Processes.Quality, s.Network.IPv4.Quality, s.Network.IPv6.Quality} {
		if q == "observed" {
			observed++
		}
	}
	if observed == 0 {
		return "unknown"
	}
	if observed != 5 {
		return "partial"
	}
	for _, p := range s.Processes.Rows {
		if p.NameQuality != "observed" {
			return "partial"
		}
	}
	return "full"
}
func ValidateReport(r Report) error {
	id, err := GenerationID(r.Binding, r.GrantID, r.GrantRevision, r.CaptureSequence)
	if err != nil || r.SchemaVersion != ReportVersion || r.ControlRevision != 1 || r.GenerationID != id || !validTime(r.CollectedAt) || !validTime(r.ExpiresAt) || !r.ExpiresAt.Equal(r.CollectedAt.Add(Retention)) {
		return ErrInvalid
	}
	if macosinventory.ValidateBinding(r.Snapshot, r.GenerationID, r.GrantID, r.CollectedAt) != nil {
		return ErrInvalid
	}
	hash, err := SnapshotDigest(r.Snapshot)
	if err != nil || hash != r.SnapshotSHA256 || r.SourceQuality != sourceQuality(r.Snapshot) {
		return ErrInvalid
	}
	_, err = encode(r, MaxReportBytes)
	return err
}
func EncodeReport(r Report) ([]byte, error) {
	if err := ValidateReport(r); err != nil {
		return nil, err
	}
	return encode(r, MaxReportBytes)
}
func DecodeReport(raw []byte) (Report, error) {
	var r Report
	if err := canonical(raw, MaxReportBytes, &r); err != nil {
		return Report{}, err
	}
	if err := ValidateReport(r); err != nil {
		return Report{}, err
	}
	return r, nil
}

// BuildReport does not repair or rewrite snapshot bindings, source status or age.
// The caller must reserve sequence and generate the matching ID before capture.
func BuildReport(c Control, sequence uint64, s macosinventory.Snapshot) (Report, error) {
	if ValidateControl(c) != nil {
		return Report{}, ErrInvalid
	}
	if !c.Enabled {
		return Report{}, ErrDisabled
	}
	hash, err := SnapshotDigest(s)
	if err != nil {
		return Report{}, err
	}
	r := Report{ReportVersion, c.Binding, c.GrantID, c.GrantRevision, c.ControlRevision, sequence, s.GenerationID, s.CollectedAt, s.CollectedAt.Add(Retention), hash, sourceQuality(s), s}
	if err := ValidateReportBinding(r, c); err != nil {
		return Report{}, err
	}
	return r, nil
}

// ValidateReportBinding compares supplied values only. A syntactically valid
// Control or collector Consent does not establish authentic current authority.
func ValidateReportBinding(r Report, c Control) error {
	if ValidateReport(r) != nil || ValidateControl(c) != nil {
		return ErrInvalid
	}
	if !c.Enabled {
		return ErrDisabled
	}
	if r.Binding != c.Binding || r.GrantID != c.GrantID || r.GrantRevision != c.GrantRevision || r.ControlRevision != c.ControlRevision || r.CollectedAt.Before(c.ChangedAt) {
		return ErrConflict
	}
	return nil
}

// Quality preserves immutable source coverage alongside caller-evaluated age.
// Stale starts at the next one-minute sampling boundary; retention ends exactly
// 24 hours after original capture. Neither value is written back into a report.
type Quality struct {
	SourceQuality string
	Freshness     string // fresh, stale, expired
	Age           time.Duration
}

func Assess(r Report, now time.Time) (Quality, error) {
	if ValidateReport(r) != nil || !validTime(now) || now.Before(r.CollectedAt) {
		return Quality{}, ErrInvalid
	}
	age := now.Sub(r.CollectedAt)
	if !r.CollectedAt.Add(age).Equal(now) {
		return Quality{}, ErrInvalid // time.Duration overflow must not fabricate age.
	}
	q := Quality{SourceQuality: r.SourceQuality, Freshness: "fresh", Age: age}
	if !now.Before(r.ExpiresAt) {
		q.Freshness = "expired"
	} else if q.Age >= CaptureInterval {
		q.Freshness = "stale"
	}
	return q, nil
}
func ValidateLifetime(r Report, now time.Time) error {
	q, err := Assess(r, now)
	if err != nil {
		return err
	}
	if q.Freshness == "expired" {
		return ErrExpired
	}
	return nil
}
