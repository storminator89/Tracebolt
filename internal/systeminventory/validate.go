package systeminventory

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var generationPattern = regexp.MustCompile(`^sample_[0-9a-f]{32}$`)
var statePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != SnapshotScope || !generationPattern.MatchString(s.GenerationID) || !validTime(s.CollectedAt) || s.DurationMS < 0 || s.DurationMS > MaxSafeInteger {
		return ErrInvalidSnapshot
	}
	if !validMeta(s.Services.Meta, s.GenerationID, s.CollectedAt, len(s.Services.Items)) || !validMeta(s.Sockets.Meta, s.GenerationID, s.CollectedAt, len(s.Sockets.Items)) || s.Services.Items == nil || s.Sockets.Items == nil {
		return ErrInvalidSnapshot
	}
	if len(s.Services.Items) > MaxServiceRows || len(s.Sockets.Items) > MaxSocketRows {
		return ErrSnapshotLimit
	}
	for i, row := range s.Services.Items {
		if !validService(row) || i > 0 && s.Services.Items[i-1].Name >= row.Name {
			return ErrInvalidSnapshot
		}
	}
	for i, row := range s.Sockets.Items {
		if !validSocket(row) || i > 0 && socketLess(row, s.Sockets.Items[i-1]) {
			return ErrInvalidSnapshot
		}
	}
	for _, section := range []any{s.Services, s.Sockets} {
		b, e := json.Marshal(section)
		if e != nil {
			return ErrInvalidSnapshot
		}
		if len(b) > MaxSectionBytes {
			return ErrSnapshotLimit
		}
	}
	b, e := json.Marshal(s)
	if e != nil {
		return ErrInvalidSnapshot
	}
	if len(b) > MaxSnapshotBytes {
		return ErrSnapshotLimit
	}
	return nil
}
func Encode(s Snapshot) ([]byte, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func validMeta(m SectionMeta, id string, at time.Time, n int) bool {
	if m.GenerationID != id || !m.ObservedAt.Equal(at) || !validTime(m.ObservedAt) {
		return false
	}
	switch m.Coverage {
	case Complete:
		return m.Reason == ReasonNone && m.CountExact && m.ObservedCount != nil && *m.ObservedCount == uint64(n)
	case Failed:
		return validFailureReason(m.Reason) && !m.CountExact && m.ObservedCount == nil && n == 0
	default:
		return false
	}
}
func validFailureReason(r Reason) bool {
	switch r {
	case ReasonSourceMissing, ReasonPermissionDenied, ReasonNotSupported, ReasonTimeout, ReasonInvalidSource, ReasonReadFailed, ReasonItemLimit, ReasonByteLimit, ReasonCollectorBusy, ReasonNotCollected:
		return true
	}
	return false
}
func validService(s Service) bool {
	if !validServiceName(s.Name) || s.MainPID != nil || s.Runtime == nil && s.Enablement == nil {
		return false
	}
	if s.Runtime != nil && (!statePattern.MatchString(s.Runtime.LoadState) || !statePattern.MatchString(s.Runtime.ActiveState) || !statePattern.MatchString(s.Runtime.SubState)) {
		return false
	}
	return s.Enablement == nil || statePattern.MatchString(*s.Enablement)
}
func validServiceName(s string) bool {
	if len(s) < 9 || len(s) > 255 || !strings.HasSuffix(s, ".service") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:@-", rune(c)) {
			continue
		}
		if c == '\\' && i+3 < len(s) && s[i+1] == 'x' && lowerHex(s[i+2]) && lowerHex(s[i+3]) {
			i += 3
			continue
		}
		return false
	}
	return true
}
func lowerHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }
func validProcessName(s string) bool {
	if len(s) == 0 || len(s) > MaxProcessNameBytes || !utf8.ValidString(s) || strings.ContainsAny(s, "/\\") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}
func validSocket(s Socket) bool {
	if s.Protocol != "tcp" && s.Protocol != "udp" || s.Family != "ipv4" && s.Family != "ipv6" || s.Owners == nil || len(s.Owners) > MaxOwnersPerSocket {
		return false
	}
	for _, e := range []Endpoint{s.Local, s.Remote} {
		a, err := netip.ParseAddr(e.Address)
		if err != nil || a.Zone() != "" || a.String() != e.Address || s.Family == "ipv4" && !a.Is4() || s.Family == "ipv6" && !a.Is6() {
			return false
		}
	}
	kind, ok := socketKind(s.Protocol, s.State)
	if !ok || s.Kind != kind {
		return false
	}
	if s.Protocol == "udp" && ((s.State == "unbound") != (s.Local.Port == 0 && s.Remote.Port == 0)) {
		return false
	}
	a := s.Attribution
	switch a.Coverage {
	case AttributionObserved:
		if a.Reason != ReasonNone || len(s.Owners) == 0 {
			return false
		}
	case AttributionPartial:
		if !validAttributionFailure(a.Reason) {
			return false
		}
	case AttributionUnavailable:
		if !validAttributionFailure(a.Reason) || len(s.Owners) != 0 {
			return false
		}
	default:
		return false
	}
	for i, o := range s.Owners {
		if o.PID == 0 || o.PID > 2147483647 || i > 0 && s.Owners[i-1].PID >= o.PID {
			return false
		}
		if o.ProcessName == nil {
			if !validAttributionFailure(o.NameReason) || o.NameReason == ReasonNoMatch || a.Coverage == AttributionObserved {
				return false
			}
		} else if o.NameReason != ReasonNone || !validProcessName(*o.ProcessName) {
			return false
		}
	}
	return true
}
func validAttributionFailure(r Reason) bool {
	switch r {
	case ReasonPermissionDenied, ReasonTimeout, ReasonInvalidSource, ReasonReadFailed, ReasonNoMatch, ReasonProcessGone, ReasonWorkLimit, ReasonOwnerLimit, ReasonNotCollected, ReasonNotSupported:
		return true
	}
	return false
}
func socketKind(proto, state string) (string, bool) {
	if proto == "udp" {
		switch state {
		case "bound":
			return "bound", true
		case "connected":
			return "connection", true
		case "unbound":
			return "unclassified", true
		}
		return "", false
	}
	switch state {
	case "listen":
		return "listener", true
	case "bound-inactive":
		return "bound", true
	case "closed":
		return "unclassified", true
	case "established", "syn-sent", "syn-recv", "fin-wait-1", "fin-wait-2", "time-wait", "close-wait", "last-ack", "closing", "new-syn-recv":
		return "connection", true
	}
	return "", false
}

// ValidateService and ValidateSocket validate one operator-visible row without
// decoding or allocating a whole snapshot (for bounded manager pages).
func ValidateService(s Service) error {
	if !validService(s) {
		return ErrInvalidSnapshot
	}
	return nil
}
func ValidateSocket(s Socket) error {
	if !validSocket(s) {
		return ErrInvalidSnapshot
	}
	return nil
}

// ValidateSectionMeta checks a standalone retained section without relabelling
// its original identity/time. rowCount is the total section count, not page size.
func ValidateSectionMeta(m SectionMeta, rowCount int) error {
	if rowCount < 0 || rowCount > MaxSocketRows || !generationPattern.MatchString(m.GenerationID) || !validTime(m.ObservedAt) || !validMeta(m, m.GenerationID, m.ObservedAt, rowCount) {
		return ErrInvalidSnapshot
	}
	return nil
}
