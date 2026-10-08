package windowsmanaged

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"
)

const (
	ServiceStartupSchemaVersion  = "tracebolt.windows-service-startup.v1"
	ServiceStartupConsentVersion = "tracebolt.windows-service-startup-consent.v1"
	ServiceStartupScope          = "windows-service-startup-v1"
	ServiceStartupMaxBytes       = 16 << 10
	ServiceStartupMaxRows        = 128
	ServiceStartupMaxConfigBytes = 8 << 10
	ServiceStartupPrivacy        = "Read and send startup mode (automatic, manual or disabled) and delayed-auto-start configuration for up to 128 services already present in the final bounded inventory. Each result refers to that exact service row array; configuration is a later, non-atomic observation, not a re-read of current state or process ID. Only local SCM_CONNECT and SERVICE_QUERY_CONFIG are requested. QueryServiceConfigW temporarily returns an aggregate configuration buffer that can include paths and accounts; only numeric startup and service-type fields are read, no pointers are followed, and the buffer is cleared before return. No new enumeration, executable paths, accounts, dependencies, descriptions, security descriptors, service control, elevated rights or AI/provider export."
	ServiceStartupHTTPPrivacy    = "WARNING: HTTP-test sends service startup mode and delayed-auto-start metadata in plaintext, associated with service names, display names, state and process IDs in the inventory. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."
)

var (
	ErrServiceStartupInvalid     = errors.New("windows_service_startup_invalid")
	ErrServiceStartupDenied      = errors.New("windows_service_startup_access_denied")
	ErrServiceStartupUnavailable = errors.New("windows_service_startup_unavailable")
	ErrServiceStartupUnsupported = errors.New("windows_service_startup_unsupported_platform")
)

// ServiceStartupConsent is an independent, identity-bound, default-off local
// scope. Older inventory or observation receipts cannot confer this consent.
type ServiceStartupConsent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}

// ServiceStartupRow refers only to the zero-based index in the exact final base
// Services.Rows array. It deliberately duplicates neither identity nor status.
type ServiceStartupRow struct {
	ServiceIndex       uint32  `json:"serviceIndex"`
	StartupMode        *string `json:"startupMode"`
	StartupQuality     string  `json:"startupQuality"`
	DelayedAutoStart   *bool   `json:"delayedAutoStart"`
	DelayedAutoQuality string  `json:"delayedAutoQuality"`
}

type ServiceStartupSnapshot struct {
	SchemaVersion  string              `json:"schemaVersion"`
	Scope          string              `json:"scope"`
	GrantID        string              `json:"grantId"`
	GenerationID   string              `json:"generationId"`
	ServicesSHA256 string              `json:"servicesSHA256"`
	CollectedAt    time.Time           `json:"collectedAt"`
	RequestedCount uint32              `json:"requestedCount"`
	Truncated      bool                `json:"truncated"`
	Rows           []ServiceStartupRow `json:"rows"`
}

func serviceStartupHex(s string, n int) bool {
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

// Canonical re-encoding rejects duplicate, unknown, missing, wrong-case and
// noncanonical members, null scalars, exponent integers and non-UTC times.
func serviceStartupCanonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrServiceStartupInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrServiceStartupInvalid
	}
	b, err := json.Marshal(v)
	if err != nil || !bytes.Equal(raw, b) {
		return ErrServiceStartupInvalid
	}
	return nil
}

func DecodeServiceStartupConsent(raw []byte, binding string) (ServiceStartupConsent, error) {
	var c ServiceStartupConsent
	if serviceStartupCanonical(raw, &c, 1024) != nil || c.SchemaVersion != ServiceStartupConsentVersion || c.Scope != ServiceStartupScope || !serviceStartupHex(binding, 64) || c.SenderBinding != binding || !serviceStartupHex(c.GrantID, 32) {
		return ServiceStartupConsent{}, ErrServiceStartupInvalid
	}
	return c, nil
}

func EncodeServiceStartupConsent(c ServiceStartupConsent, binding string) ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, ErrServiceStartupInvalid
	}
	if _, err := DecodeServiceStartupConsent(b, binding); err != nil {
		return nil, err
	}
	return b, nil
}

// ServiceStartupRowsSHA256 hashes Go's canonical JSON encoding of the exact
// final base array, preserving row order and every v1 field. It never sorts,
// changes or re-enumerates rows. Nil is not the canonical empty array ([]).
func ServiceStartupRowsSHA256(services []Service) (string, error) {
	if services == nil || len(services) > ServiceStartupMaxRows {
		return "", ErrServiceStartupInvalid
	}
	for _, s := range services {
		if !validService(s) {
			return "", ErrServiceStartupInvalid
		}
	}
	b, err := json.Marshal(services)
	if err != nil {
		return "", ErrServiceStartupInvalid
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), nil
}

func validServiceStartupRow(r ServiceStartupRow) bool {
	if r.StartupQuality != "observed" {
		if r.StartupQuality != "denied" && r.StartupQuality != "unavailable" && r.StartupQuality != "unknown" {
			return false
		}
		return r.StartupMode == nil && r.DelayedAutoStart == nil && r.DelayedAutoQuality == r.StartupQuality
	}
	if r.StartupMode == nil {
		return false
	}
	switch *r.StartupMode {
	case "manual", "disabled":
		return r.DelayedAutoStart == nil && r.DelayedAutoQuality == "not-applicable"
	case "automatic":
		switch r.DelayedAutoQuality {
		case "observed":
			return r.DelayedAutoStart != nil
		case "denied", "unavailable", "unknown":
			return r.DelayedAutoStart == nil
		}
	}
	return false
}

func validateServiceStartup(s ServiceStartupSnapshot, checkBytes bool) error {
	if s.SchemaVersion != ServiceStartupSchemaVersion || s.Scope != ServiceStartupScope || !serviceStartupHex(s.GrantID, 32) || !validGeneration(s.GenerationID) || !serviceStartupHex(s.ServicesSHA256, 64) || !validTime(s.CollectedAt) || s.Rows == nil || len(s.Rows) > ServiceStartupMaxRows || s.RequestedCount > ServiceStartupMaxRows || int(s.RequestedCount) < len(s.Rows) || s.Truncated != (int(s.RequestedCount) > len(s.Rows)) {
		return ErrServiceStartupInvalid
	}
	for i, r := range s.Rows {
		if r.ServiceIndex >= s.RequestedCount || i > 0 && r.ServiceIndex <= s.Rows[i-1].ServiceIndex || !validServiceStartupRow(r) {
			return ErrServiceStartupInvalid
		}
	}
	if checkBytes {
		b, err := json.Marshal(s)
		if err != nil || len(b) > ServiceStartupMaxBytes {
			return ErrServiceStartupInvalid
		}
	}
	return nil
}

func ValidateServiceStartup(s ServiceStartupSnapshot) error { return validateServiceStartup(s, true) }

func DecodeServiceStartup(raw []byte) (ServiceStartupSnapshot, error) {
	var s ServiceStartupSnapshot
	if serviceStartupCanonical(raw, &s, ServiceStartupMaxBytes) != nil || ValidateServiceStartup(s) != nil {
		return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
	}
	return s, nil
}

func EncodeServiceStartup(s ServiceStartupSnapshot) ([]byte, error) {
	if err := ValidateServiceStartup(s); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// FitServiceStartupBudget drops highest-index complete rows. It preserves the
// exact base-array digest, requested count, generation, grant and original age.
// It accepts a structurally valid pre-fit snapshot up to the bounded row cap.
func FitServiceStartupBudget(s ServiceStartupSnapshot, maxBytes int) (ServiceStartupSnapshot, error) {
	if maxBytes <= 0 || validateServiceStartup(s, false) != nil {
		return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
	}
	if maxBytes > ServiceStartupMaxBytes {
		maxBytes = ServiceStartupMaxBytes
	}
	s.Rows = append([]ServiceStartupRow{}, s.Rows...)
	for i := range s.Rows {
		if s.Rows[i].StartupMode != nil {
			v := *s.Rows[i].StartupMode
			s.Rows[i].StartupMode = &v
		}
		if s.Rows[i].DelayedAutoStart != nil {
			v := *s.Rows[i].DelayedAutoStart
			s.Rows[i].DelayedAutoStart = &v
		}
	}
	for {
		b, err := json.Marshal(s)
		if err != nil {
			return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
		}
		if len(b) <= maxBytes {
			return s, nil
		}
		if len(s.Rows) == 0 {
			return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
		}
		s.Rows = s.Rows[:len(s.Rows)-1]
		s.Truncated = true
	}
}
