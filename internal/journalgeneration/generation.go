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
	"localrmm/internal/journalview"
	"slices"
	"strings"
	"time"
)

const (
	ReportVersion       = "tracebolt.journal-generation-report.v1"
	ReportSchemaVersion = ReportVersion
	ReportVersionV2     = "tracebolt.journal-generation-report.v2"
	ReportVersionV3     = "tracebolt.journal-generation-report.v3"
	MaxReportBytes      = 12 << 10
	MaxAllowedUnits     = 32
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

// ServiceAuthorization describes a locally acknowledged service scope. It is
// presentation metadata, never independent authority for a capture.
type ServiceAuthorization string

const (
	ExactUnits        ServiceAuthorization = "exact-units"
	AllSystemServices ServiceAuthorization = "all-system-services"
)

// Report v1 preserves its original bytes and carries no permission information.
// Only a freshly acknowledged v3 policy may produce a v2 permission summary.
type Report struct {
	SchemaVersion        string
	Tuple                Tuple
	Sequence             uint64
	ObservedAt           time.Time
	PolicyEnabled        bool
	ServiceAuthorization ServiceAuthorization
	AllowedUnits         []string
	BrowsingContract     string
}
type reportV1 struct {
	SchemaVersion string    `json:"schemaVersion"`
	Tuple         Tuple     `json:"policyGeneration"`
	Sequence      uint64    `json:"sequence,string"`
	ObservedAt    time.Time `json:"observedAt"`
}
type reportV2 struct {
	reportV1
	PolicyEnabled        bool                 `json:"policyEnabled"`
	ServiceAuthorization ServiceAuthorization `json:"serviceAuthorization"`
	AllowedUnits         []string             `json:"allowedUnits"`
}

type reportV3 struct {
	reportV2
	BrowsingContract string `json:"browsingContract"`
}

func ValidateServiceAuthorization(scope ServiceAuthorization, units []string) error {
	if units == nil || len(units) > MaxAllowedUnits {
		return ErrInvalid
	}
	if scope == AllSystemServices {
		if len(units) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if scope != ExactUnits || len(units) == 0 {
		return ErrInvalid
	}
	at := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	for i, unit := range units {
		if i > 0 && units[i-1] >= unit || journalview.ValidateQuery(journalview.Query{Unit: unit, Start: at.Add(-time.Minute), End: at, MaxPriority: 7}, at) != nil {
			return ErrInvalid
		}
	}
	return nil
}
func ValidateReport(r Report) error {
	if Validate(r.Tuple) != nil || r.Sequence == 0 || r.ObservedAt.Location() != time.UTC || r.ObservedAt.Unix() <= 0 || r.ObservedAt.Year() > 9999 {
		return ErrInvalid
	}
	switch r.SchemaVersion {
	case ReportVersion:
		if r.PolicyEnabled || r.ServiceAuthorization != "" || r.AllowedUnits != nil || r.BrowsingContract != "" {
			return ErrInvalid
		}
	case ReportVersionV2:
		if r.BrowsingContract != "" {
			return ErrInvalid
		}
		return ValidateServiceAuthorization(r.ServiceAuthorization, r.AllowedUnits)
	case ReportVersionV3:
		if r.BrowsingContract != journalview.BrowseContract {
			return ErrInvalid
		}
		return ValidateServiceAuthorization(r.ServiceAuthorization, r.AllowedUnits)
	default:
		return ErrInvalid
	}
	return nil
}
func (r Report) MarshalJSON() ([]byte, error) {
	base := reportV1{r.SchemaVersion, r.Tuple, r.Sequence, r.ObservedAt}
	if r.SchemaVersion == ReportVersion {
		return json.Marshal(base)
	}
	v2 := reportV2{base, r.PolicyEnabled, r.ServiceAuthorization, r.AllowedUnits}
	if r.SchemaVersion == ReportVersionV3 {
		return json.Marshal(reportV3{v2, r.BrowsingContract})
	}
	return json.Marshal(v2)
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
	var version struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if len(raw) == 0 || len(raw) > MaxReportBytes || json.Unmarshal(raw, &version) != nil {
		return Report{}, ErrInvalid
	}
	var r Report
	switch version.SchemaVersion {
	case ReportVersion:
		var v reportV1
		if strict(raw, &v, 4096) != nil {
			return Report{}, ErrInvalid
		}
		r = Report{SchemaVersion: v.SchemaVersion, Tuple: v.Tuple, Sequence: v.Sequence, ObservedAt: v.ObservedAt}
	case ReportVersionV2:
		var v reportV2
		if strict(raw, &v, MaxReportBytes) != nil {
			return Report{}, ErrInvalid
		}
		r = Report{SchemaVersion: v.SchemaVersion, Tuple: v.Tuple, Sequence: v.Sequence, ObservedAt: v.ObservedAt, PolicyEnabled: v.PolicyEnabled, ServiceAuthorization: v.ServiceAuthorization, AllowedUnits: v.AllowedUnits}
	case ReportVersionV3:
		var v reportV3
		if strict(raw, &v, MaxReportBytes) != nil {
			return Report{}, ErrInvalid
		}
		r = Report{SchemaVersion: v.SchemaVersion, Tuple: v.Tuple, Sequence: v.Sequence, ObservedAt: v.ObservedAt, PolicyEnabled: v.PolicyEnabled, ServiceAuthorization: v.ServiceAuthorization, AllowedUnits: v.AllowedUnits, BrowsingContract: v.BrowsingContract}
	default:
		return Report{}, ErrInvalid
	}
	if ValidateReport(r) != nil {
		return Report{}, ErrInvalid
	}
	return r, nil
}
func (r *Report) UnmarshalJSON(raw []byte) error {
	p, err := DecodeReport(raw)
	if err != nil {
		return err
	}
	*r = p
	return nil
}
func SameAuthorization(a, b Report) bool {
	return a.SchemaVersion == b.SchemaVersion && a.PolicyEnabled == b.PolicyEnabled && a.BrowsingContract == b.BrowsingContract && a.ServiceAuthorization == b.ServiceAuthorization && slices.Equal(a.AllowedUnits, b.AllowedUnits)
}
func EqualReport(a, b Report) bool {
	return a.Tuple == b.Tuple && a.Sequence == b.Sequence && a.ObservedAt == b.ObservedAt && SameAuthorization(a, b)
}
func CloneReport(r Report) Report { r.AllowedUnits = slices.Clone(r.AllowedUnits); return r }
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
