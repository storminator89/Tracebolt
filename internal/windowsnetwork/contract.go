// Package windowsnetwork carries separately consented, private Windows endpoint
// table observations. It does not resolve names, inspect processes or export evidence.
package windowsnetwork

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

const SchemaVersion = "tracebolt.windows-network-endpoints.v1"
const ConsentVersion = "tracebolt.windows-network-consent.v1"
const Scope = "windows-network-endpoints-v1"
const MaxBytes = 12 << 10
const MaxRows = 64
const MaxRowsPerTable = 4096
const MaxObservedRows = 4 * MaxRowsPerTable
const MaxTableBytes = 1 << 20
const MaxTableCalls = 4
const Privacy = "Read and send caller-visible TCP and UDP endpoints for IPv4 and IPv6: numeric local and remote addresses and ports, TCP state and API-reported owning process ID. Up to 64 endpoint rows are retained; bounded coverage and exact or lower-bound counts are explicit. UDP has no remote endpoint or connection state; listening TCP sockets have no applicable remote peer. Process IDs are snapshot values, not stable identities. No DNS, hostnames, process-name joins, payloads, packet capture, executable paths, elevated rights or AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test sends network endpoint addresses, ports, states and process IDs in plaintext. Network observers can read them; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_network_invalid")
var ErrDenied = errors.New("windows_network_access_denied")
var ErrUnavailable = errors.New("windows_network_unavailable")
var ErrUnsupported = errors.New("windows_network_unsupported_platform")
var ErrBounds = errors.New("windows_network_bounds")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}

type Endpoint struct {
	Protocol      string  `json:"protocol"`
	Family        string  `json:"family"`
	LocalAddress  string  `json:"localAddress"`
	LocalPort     uint16  `json:"localPort"`
	RemoteAddress *string `json:"remoteAddress"`
	RemotePort    *uint16 `json:"remotePort"`
	State         *string `json:"state"`
	PID           uint32  `json:"pid"`
}

type Snapshot struct {
	SchemaVersion string     `json:"schemaVersion"`
	Scope         string     `json:"scope"`
	GrantID       string     `json:"grantId"`
	GenerationID  string     `json:"generationId"`
	CollectedAt   time.Time  `json:"collectedAt"`
	Quality       string     `json:"quality"`
	CountExact    bool       `json:"countExact"`
	ObservedCount uint32     `json:"observedCount"`
	Truncated     bool       `json:"truncated"`
	Rows          []Endpoint `json:"rows"`
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

// A zone is the numeric scope ID returned by IP Helper, never an interface name.
func address(s, family string) (netip.Addr, bool) {
	if len(s) > 56 {
		return netip.Addr{}, false
	}
	a, e := netip.ParseAddr(s)
	if e != nil || a.String() != s {
		return netip.Addr{}, false
	}
	switch family {
	case "ipv4":
		if !a.Is4() || a.Zone() != "" {
			return netip.Addr{}, false
		}
	case "ipv6":
		if !a.Is6() {
			return netip.Addr{}, false
		}
	default:
		return netip.Addr{}, false
	}
	if z := a.Zone(); z != "" {
		n, e := strconv.ParseUint(z, 10, 32)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != z {
			return netip.Addr{}, false
		}
	}
	return a, true
}
func validState(s string) bool {
	switch s {
	case "closed", "listen", "syn-sent", "syn-received", "established", "fin-wait-1", "fin-wait-2", "close-wait", "closing", "last-ack", "time-wait", "delete-tcb":
		return true
	}
	return false
}
func validEndpoint(r Endpoint) bool {
	if _, ok := address(r.LocalAddress, r.Family); !ok {
		return false
	}
	switch r.Protocol {
	case "udp":
		return r.RemoteAddress == nil && r.RemotePort == nil && r.State == nil
	case "tcp":
		if r.State == nil || !validState(*r.State) {
			return false
		}
		if *r.State == "listen" {
			return r.RemoteAddress == nil && r.RemotePort == nil
		}
		if r.RemoteAddress == nil || r.RemotePort == nil {
			return false
		}
		_, ok := address(*r.RemoteAddress, r.Family)
		return ok
	}
	return false
}
func compareAddress(x, y string) int {
	a, _ := netip.ParseAddr(x)
	b, _ := netip.ParseAddr(y)
	if n := a.WithZone("").Compare(b.WithZone("")); n != 0 {
		return n
	}
	az, _ := strconv.ParseUint(a.Zone(), 10, 32)
	bz, _ := strconv.ParseUint(b.Zone(), 10, 32)
	return cmp.Compare(az, bz)
}
func compareRows(a, b Endpoint) int {
	if n := cmp.Compare(a.Protocol, b.Protocol); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Family, b.Family); n != 0 {
		return n
	}
	if n := compareAddress(a.LocalAddress, b.LocalAddress); n != 0 {
		return n
	}
	if n := cmp.Compare(a.LocalPort, b.LocalPort); n != 0 {
		return n
	}
	if a.Protocol == "tcp" {
		if a.RemoteAddress == nil && b.RemoteAddress != nil {
			return -1
		}
		if a.RemoteAddress != nil && b.RemoteAddress == nil {
			return 1
		}
		if a.RemoteAddress != nil {
			if n := compareAddress(*a.RemoteAddress, *b.RemoteAddress); n != 0 {
				return n
			}
			if n := cmp.Compare(*a.RemotePort, *b.RemotePort); n != 0 {
				return n
			}
		}
		if n := cmp.Compare(*a.State, *b.State); n != 0 {
			return n
		}
	}
	return cmp.Compare(a.PID, b.PID)
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
	case "denied", "unavailable":
		if s.CountExact || s.ObservedCount != 0 || len(s.Rows) != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	for i, r := range s.Rows {
		if !validEndpoint(r) || i > 0 && compareRows(s.Rows[i-1], r) > 0 {
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
	s.Rows = append([]Endpoint{}, s.Rows...)
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
