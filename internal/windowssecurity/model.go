// Package windowssecurity carries separately consented local Defender and
// Windows Firewall observations. It never establishes overall protection.
package windowssecurity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-security-posture.v1"
const ConsentVersion = "tracebolt.windows-security-posture-consent.v1"
const Scope = "windows-security-posture-v1"
const MaxBytes = 4096
const CollectionBudget = 5 * time.Second
const ProviderBudget = 2 * time.Second
const Privacy = "Read and send fixed local Microsoft Defender mode, antivirus/service/real-time flags and signature version/age; and Windows Firewall domain/private/public profile activity and locally configured enabled flags. Sources are independent, may be denied or unavailable under the existing service identity, and do not establish overall protection, third-party antivirus status, effective firewall policy, connectivity or compliance. No scans, updates, server contact, rule reads or changes, paths, processes, user data, recovery keys, remote WMI, arbitrary queries, credentials, privilege changes or AI/provider export. This separate default-off local scope is not granted by existing Windows Setup or any earlier receipt."
const HTTPPrivacy = "WARNING: HTTP-test sends local Defender and Windows Firewall posture metadata in plaintext. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_security_posture_invalid")
var ErrDisabled = errors.New("windows_security_posture_scope_disabled")
var ErrDenied = errors.New("windows_security_posture_access_denied")
var ErrUnavailable = errors.New("windows_security_posture_unavailable")
var ErrUnsupported = errors.New("windows_security_posture_unsupported_platform")
var ErrMetadata = errors.New("windows_security_posture_invalid_metadata")
var ErrBounds = errors.New("windows_security_posture_bounds")
var ErrPartial = errors.New("windows_security_posture_partial_result")
var ErrBudget = errors.New("windows_security_posture_budget_exhausted")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Defender struct {
	Quality                   string  `json:"quality"`
	Reason                    string  `json:"reason"`
	Mode                      string  `json:"mode"`
	ServiceEnabled            string  `json:"serviceEnabled"`
	AntivirusEnabled          string  `json:"antivirusEnabled"`
	RealTimeProtectionEnabled string  `json:"realTimeProtectionEnabled"`
	SignatureVersion          *string `json:"signatureVersion"`
	SignatureAgeDays          *uint32 `json:"signatureAgeDays"`
}
type Profile struct {
	Profile string `json:"profile"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}
type Firewall struct {
	Quality  string    `json:"quality"`
	Reason   string    `json:"reason"`
	Profiles []Profile `json:"profiles"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Defender      Defender  `json:"defender"`
	Firewall      Firewall  `json:"firewall"`
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
	case "", ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrPartial.Error(), ErrBudget.Error():
		return true
	}
	return false
}
func state(s string) bool { return s == "on" || s == "off" || s == "unknown" }

var signaturePattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`)

func validSignature(s string) bool { return len(s) <= 64 && signaturePattern.MatchString(s) }
func sourceQuality(quality, reason string, known, total int) bool {
	if !validReason(reason) {
		return false
	}
	switch quality {
	case "observed":
		return known == total && reason == ""
	case "partial":
		return known > 0 && reason != ""
	case "denied", "unavailable":
		return known == 0 && reason != "" && (quality == "denied") == (reason == ErrDenied.Error())
	}
	return false
}
func defenderKnown(d Defender) int {
	n := 0
	if d.Mode != "unknown" {
		n++
	}
	for _, s := range []string{d.ServiceEnabled, d.AntivirusEnabled, d.RealTimeProtectionEnabled} {
		if s != "unknown" {
			n++
		}
	}
	if d.SignatureVersion != nil {
		n++
	}
	if d.SignatureAgeDays != nil {
		n++
	}
	return n
}
func firewallKnown(f Firewall) int {
	n := 0
	for _, p := range f.Profiles {
		if p.Active != "unknown" {
			n++
		}
		if p.Enabled != "unknown" {
			n++
		}
	}
	return n
}
func validDefender(d Defender) bool {
	if d.Mode != "normal" && d.Mode != "passive" && d.Mode != "edr-block" && d.Mode != "unknown" || !state(d.ServiceEnabled) || !state(d.AntivirusEnabled) || !state(d.RealTimeProtectionEnabled) || d.SignatureVersion != nil && !validSignature(*d.SignatureVersion) || d.SignatureAgeDays != nil && *d.SignatureAgeDays > 65534 {
		return false
	}
	return sourceQuality(d.Quality, d.Reason, defenderKnown(d), 6)
}
func validFirewall(f Firewall) bool {
	if len(f.Profiles) != 3 {
		return false
	}
	for i, name := range []string{"domain", "private", "public"} {
		p := f.Profiles[i]
		if p.Profile != name || !state(p.Active) || !state(p.Enabled) {
			return false
		}
	}
	return sourceQuality(f.Quality, f.Reason, firewallKnown(f), 6)
}
func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validDefender(s.Defender) || !validFirewall(s.Firewall) {
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
func EmptyDefender(reason string) Defender {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Defender{Quality: q, Reason: reason, Mode: "unknown", ServiceEnabled: "unknown", AntivirusEnabled: "unknown", RealTimeProtectionEnabled: "unknown"}
}
func EmptyFirewall(reason string) Firewall {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Firewall{Quality: q, Reason: reason, Profiles: []Profile{{"domain", "unknown", "unknown"}, {"private", "unknown", "unknown"}, {"public", "unknown", "unknown"}}}
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptyDefender(reason), EmptyFirewall(reason)}
}
