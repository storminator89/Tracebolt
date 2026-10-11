// Package windowsadapters carries separately consented local adapter context.
// It never resolves names, probes networks or exports provider evidence.
package windowsadapters

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-adapter-context.v1"
const ConsentVersion = "tracebolt.windows-adapter-context-consent.v1"
const Scope = "windows-adapter-context-v1"
const MaxBytes = 16 << 10
const MaxRows = 32
const MaxObservedRows = 128
const MaxAddresses = 8
const MaxNativeBytes = 1 << 20
const MaxAddressNodes = 512
const MaxSafeInteger = 1<<53 - 1
const Privacy = "Read and send caller-visible IP adapter names and temporary IPv4/IPv6 interface indices, native operational state, directional link speeds, and configured numeric DNS-server and gateway addresses. Retain at most 32 adapters and 8 addresses per list. This is a local IP Helper snapshot, not reachability, routing preference, DNS resolution or measured throughput. No DNS suffixes, MAC addresses, DHCP servers, credentials, packet capture, traffic payloads, probes, route tables, control actions, privilege changes or AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test sends adapter names, link state/speed and configured DNS-server and gateway addresses in plaintext. Network observers can read them; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_adapter_context_invalid")
var ErrDenied = errors.New("windows_adapter_context_access_denied")
var ErrUnavailable = errors.New("windows_adapter_context_unavailable")
var ErrUnsupported = errors.New("windows_adapter_context_unsupported_platform")
var ErrBounds = errors.New("windows_adapter_context_bounds")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}

type AddressList struct {
	Quality   string   `json:"quality"`
	Addresses []string `json:"addresses"`
}
type Adapter struct {
	IfIndex     uint32      `json:"ifIndex"`
	IPv6IfIndex uint32      `json:"ipv6IfIndex"`
	Name        string      `json:"name"`
	State       string      `json:"state"`
	TxLinkBps   *uint64     `json:"txLinkBps"`
	TxQuality   string      `json:"txQuality"`
	RxLinkBps   *uint64     `json:"rxLinkBps"`
	RxQuality   string      `json:"rxQuality"`
	DNSServers  AddressList `json:"dnsServers"`
	Gateways    AddressList `json:"gateways"`
}

type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Quality       string    `json:"quality"`
	CountExact    bool      `json:"countExact"`
	ObservedCount uint32    `json:"observedCount"`
	Truncated     bool      `json:"truncated"`
	Rows          []Adapter `json:"rows"`
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
func validGeneration(s string) bool {
	return strings.HasPrefix(s, "sample_") && hex(strings.TrimPrefix(s, "sample_"), 32)
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}

func validAddress(s string) bool {
	if len(s) > 56 {
		return false
	}
	a, e := netip.ParseAddr(s)
	if e != nil || a.String() != s {
		return false
	}
	if z := a.Zone(); z != "" {
		n, e := strconv.ParseUint(z, 10, 32)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != z {
			return false
		}
	}
	return true
}
func validList(v AddressList) bool {
	if v.Addresses == nil || len(v.Addresses) > MaxAddresses {
		return false
	}
	switch v.Quality {
	case "observed", "partial":
	case "unavailable":
		if len(v.Addresses) != 0 {
			return false
		}
	default:
		return false
	}
	for i, a := range v.Addresses {
		if !validAddress(a) || i > 0 && a <= v.Addresses[i-1] {
			return false
		}
	}
	return true
}
func validSpeed(v *uint64, q string) bool {
	if q == "observed" {
		return v != nil && *v > 0 && *v <= MaxSafeInteger
	}
	return (q == "unknown" || q == "unavailable") && v == nil
}
func validName(s string) bool {
	if len(s) == 0 || len(s) > 96 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 || c >= 0x202a && c <= 0x202e || c >= 0x2066 && c <= 0x2069 {
			return false
		}
	}
	return true
}
func validAdapter(r Adapter) bool {
	if r.IfIndex == 0 && r.IPv6IfIndex == 0 || !validName(r.Name) || !validSpeed(r.TxLinkBps, r.TxQuality) || !validSpeed(r.RxLinkBps, r.RxQuality) || !validList(r.DNSServers) || !validList(r.Gateways) {
		return false
	}
	switch r.State {
	case "up", "down", "testing", "unknown", "dormant", "not-present", "lower-layer-down":
		return true
	}
	return false
}
func compareRows(a, b Adapter) int {
	if n := cmp.Compare(a.IfIndex, b.IfIndex); n != 0 {
		return n
	}
	if n := cmp.Compare(a.IPv6IfIndex, b.IPv6IfIndex); n != 0 {
		return n
	}
	return cmp.Compare(a.Name, b.Name)
}
func validate(s Snapshot, checkBytes bool) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !validGeneration(s.GenerationID) || !validTime(s.CollectedAt) || s.Rows == nil || len(s.Rows) > MaxRows || s.ObservedCount > MaxObservedRows || int(s.ObservedCount) < len(s.Rows) || s.Truncated != (int(s.ObservedCount) > len(s.Rows)) {
		return ErrInvalid
	}
	switch s.Quality {
	case "observed":
		if !s.CountExact {
			return ErrInvalid
		}
	case "partial":
		if s.CountExact {
			return ErrInvalid
		}
	case "denied", "unavailable", "unsupported":
		if s.CountExact || s.ObservedCount != 0 || len(s.Rows) != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	for i, r := range s.Rows {
		if !validAdapter(r) || i > 0 && (compareRows(s.Rows[i-1], r) >= 0 || s.Rows[i-1].IfIndex == r.IfIndex && s.Rows[i-1].IPv6IfIndex == r.IPv6IfIndex) {
			return ErrInvalid
		}
	}
	if checkBytes {
		b, e := json.Marshal(s)
		if e != nil || len(b) > MaxBytes {
			return ErrInvalid
		}
	}
	return nil
}
func Validate(s Snapshot) error { return validate(s, true) }
func Decode(raw []byte) (Snapshot, error) {
	var s Snapshot
	if canonical(raw, &s, MaxBytes) != nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}

// FitBudget drops highest-sorted complete rows without changing capture, grant,
// generation, quality, observed count or its exact/lower-bound meaning.
func FitBudget(s Snapshot, maxBytes int) (Snapshot, error) {
	if Validate(s) != nil || maxBytes <= 0 {
		return Snapshot{}, ErrInvalid
	}
	return fit(s, maxBytes)
}
func fit(s Snapshot, maxBytes int) (Snapshot, error) {
	if maxBytes > MaxBytes {
		maxBytes = MaxBytes
	}
	if maxBytes <= 0 || validate(s, false) != nil {
		return Snapshot{}, ErrInvalid
	}
	s.Rows = append([]Adapter{}, s.Rows...)
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
		if len(s.Rows) == 0 {
			return Snapshot{}, ErrInvalid
		}
		s.Rows = s.Rows[:len(s.Rows)-1]
		s.Truncated = true
	}
}
