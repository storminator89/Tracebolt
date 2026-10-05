// Package journalgeneration defines public, content-free policy binding values.
// A tuple is not authorization: its source and durable floor must independently
// be validated by the caller. No local or remote state is changed here.
package journalgeneration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	ReportVersion       = "tracebolt.journal-generation-report.v1"
	ReportSchemaVersion = ReportVersion
	MaxReportBytes      = 4096
	MaxTupleBytes       = 256
)

var ErrInvalid = errors.New("journal_generation_invalid")

// Tuple is a detached comparable value. Zero means no generation only at an
// explicitly versioned legacy boundary; it is not a valid generation itself.
type Tuple struct {
	Revision     uint64 `json:"revision,string"`
	Generation   string `json:"generation"`
	PolicyDigest string `json:"policyDigest"`
}

func ValidGeneration(s string) bool {
	if len(s) != 64 || strings.Trim(s, "0") == "" {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}
func Validate(t Tuple) error {
	if t.Revision == 0 || !ValidGeneration(t.Generation) || !strings.HasPrefix(t.PolicyDigest, "sha256:") || !ValidGeneration(strings.TrimPrefix(t.PolicyDigest, "sha256:")) {
		return ErrInvalid
	}
	return nil
}
func Encode(t Tuple) ([]byte, error) {
	if Validate(t) != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(t)
}
func Decode(raw []byte) (Tuple, error) {
	type plain Tuple
	var p plain
	if strict(raw, &p, MaxTupleBytes) != nil || Validate(Tuple(p)) != nil {
		return Tuple{}, ErrInvalid
	}
	return Tuple(p), nil
}

// UnmarshalJSON protects nested tuples from duplicate, missing and unknown
// members, numeric revision precision loss, and noncanonical integer spellings.
func (t *Tuple) UnmarshalJSON(raw []byte) error {
	p, err := Decode(raw)
	if err != nil {
		return err
	}
	*t = p
	return nil
}

// Report carries only public binding metadata. Observation age and sequence
// floors are enforced by the authenticated receiver and durable sender state.
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	Tuple         Tuple     `json:"policyGeneration"`
	Sequence      uint64    `json:"sequence,string"`
	ObservedAt    time.Time `json:"observedAt"`
}

func ValidateReport(r Report) error {
	if r.SchemaVersion != ReportSchemaVersion || Validate(r.Tuple) != nil || r.Sequence == 0 || r.ObservedAt.Location() != time.UTC || r.ObservedAt.Unix() <= 0 || r.ObservedAt.Year() > 9999 {
		return ErrInvalid
	}
	return nil
}
func EncodeReport(r Report) ([]byte, error) {
	if ValidateReport(r) != nil {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxReportBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func DecodeReport(raw []byte) (Report, error) {
	type plain Report
	var r plain
	if strict(raw, &r, MaxReportBytes) != nil || ValidateReport(Report(r)) != nil {
		return Report{}, ErrInvalid
	}
	return Report(r), nil
}
func (r *Report) UnmarshalJSON(raw []byte) error {
	p, err := DecodeReport(raw)
	if err != nil {
		return err
	}
	*r = p
	return nil
}
func strict(raw []byte, target any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalid
	}
	return nil
}
