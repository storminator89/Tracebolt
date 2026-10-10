// Package windowsprocessmetrics carries separately consented, private process
// CPU and working-set observations. It does not enumerate processes or export evidence.
package windowsprocessmetrics

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-process-metrics.v1"
const ConsentVersion = "tracebolt.windows-process-metrics-consent.v1"
const Scope = "windows-process-metrics-v1"
const MaxBytes = 12 << 10
const MaxRows = 128
const Privacy = "Read and send interval CPU percent and working-set memory bytes for up to 128 already inventoried process IDs. CPU is percent of one logical processor and may exceed 100. Process creation identity stays local to prevent PID reuse errors. No new process enumeration, command lines, executable paths, environment, memory contents, elevated rights or AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test sends process CPU and memory metadata in plaintext. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_process_metrics_invalid")
var ErrDenied = errors.New("windows_process_metrics_access_denied")
var ErrUnavailable = errors.New("windows_process_metrics_unavailable")
var ErrUnsupported = errors.New("windows_process_metrics_unsupported_platform")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Process struct {
	PID           uint32   `json:"pid"`
	CPUPercent    *float64 `json:"cpuPercent"`
	CPUQuality    string   `json:"cpuQuality"`
	MemoryBytes   *string  `json:"memoryBytes"`
	MemoryQuality string   `json:"memoryQuality"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	ObservedCount uint32    `json:"observedCount"`
	Truncated     bool      `json:"truncated"`
	Rows          []Process `json:"rows"`
}

func hex(s string, n int) bool {
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
func validGeneration(g string) bool {
	return strings.HasPrefix(g, "sample_") && hex(strings.TrimPrefix(g, "sample_"), 32)
}

func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !validGeneration(s.GenerationID) || s.CollectedAt.IsZero() || s.CollectedAt.Location() != time.UTC || s.CollectedAt.Year() < 1970 || s.CollectedAt.Year() > 9999 || s.Rows == nil || len(s.Rows) > MaxRows || s.ObservedCount > MaxRows || int(s.ObservedCount) < len(s.Rows) || s.Truncated != (int(s.ObservedCount) > len(s.Rows)) {
		return ErrInvalid
	}
	var previous uint32
	for i, r := range s.Rows {
		if i > 0 && r.PID <= previous {
			return ErrInvalid
		}
		previous = r.PID
		switch r.CPUQuality {
		case "observed":
			if r.CPUPercent == nil || math.IsNaN(*r.CPUPercent) || math.IsInf(*r.CPUPercent, 0) || *r.CPUPercent < 0 || math.Signbit(*r.CPUPercent) || *r.CPUPercent > float64(math.MaxUint32)*100 {
				return ErrInvalid
			}
		case "first-sample", "reset", "denied", "unavailable":
			if r.CPUPercent != nil {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		switch r.MemoryQuality {
		case "observed":
			if r.MemoryBytes == nil {
				return ErrInvalid
			}
			n, e := strconv.ParseUint(*r.MemoryBytes, 10, 64)
			if e != nil || strconv.FormatUint(n, 10) != *r.MemoryBytes {
				return ErrInvalid
			}
		case "denied", "unavailable":
			if r.MemoryBytes != nil {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
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

// FitBudget drops highest-PID complete rows and preserves original capture/count.
func FitBudget(s Snapshot, maxBytes int) (Snapshot, error) {
	return FitBudgetWithSelfPID(s, maxBytes, 0)
}

// FitBudgetWithSelfPID protects an existing local self row during a fresh,
// consented capture. Missing self is never inserted. It fails closed when the
// existing self row and envelope cannot fit, and never changes the input slice.
func FitBudgetWithSelfPID(s Snapshot, maxBytes int, selfPID uint32) (Snapshot, error) {
	if Validate(s) != nil || maxBytes <= 0 {
		return Snapshot{}, ErrInvalid
	}
	return fitWithSelfPID(s, maxBytes, selfPID)
}
func fitWithSelfPID(s Snapshot, maxBytes int, selfPID uint32) (Snapshot, error) {
	if maxBytes > MaxBytes {
		maxBytes = MaxBytes
	}
	s.Rows = append([]Process{}, s.Rows...)
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
		if len(b) <= maxBytes {
			if Validate(s) != nil {
				return Snapshot{}, ErrInvalid
			}
			return s, nil
		}
		i := len(s.Rows) - 1
		for i >= 0 && selfPID != 0 && s.Rows[i].PID == selfPID {
			i--
		}
		if i < 0 {
			return Snapshot{}, ErrInvalid
		}
		copy(s.Rows[i:], s.Rows[i+1:])
		s.Rows = s.Rows[:len(s.Rows)-1]
		s.Truncated = true
	}
}
