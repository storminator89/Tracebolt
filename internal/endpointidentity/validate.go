package endpointidentity

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

func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !generationPattern.MatchString(s.GenerationID) || !validTime(s.CollectedAt) || s.DurationMS < 0 || s.DurationMS > MaxSafeInteger {
		return ErrInvalidSnapshot
	}
	h := s.ReportedHostname
	if h.Coverage == Complete {
		if h.Reason != ReasonNone || h.Value == nil || !safeText(*h.Value, MaxHostnameBytes) {
			return ErrInvalidSnapshot
		}
	} else if h.Coverage != Failed || !failureReasonValid(h.Reason) || h.Value != nil {
		return ErrInvalidSnapshot
	}
	if s.Interfaces.Items == nil || !validMeta(s.Interfaces.Meta, len(s.Interfaces.Items), true) {
		return ErrInvalidSnapshot
	}
	if len(s.Interfaces.Items) > MaxInterfaces {
		return ErrSnapshotLimit
	}
	addresses, incomplete := 0, false
	names := make(map[string]bool, len(s.Interfaces.Items))
	for i, row := range s.Interfaces.Items {
		if row.Index == 0 || row.Index > 1<<31-1 || !safeInterfaceName(row.Name) || names[row.Name] || row.HardwareKind != "unknown" || i > 0 && s.Interfaces.Items[i-1].Index >= row.Index {
			return ErrInvalidSnapshot
		}
		names[row.Name] = true
		for family, section := range map[string]AddressSection{"ipv4": row.Addresses.IPv4, "ipv6": row.Addresses.IPv6} {
			if section.Items == nil || !validMeta(section.Meta, len(section.Items), false) {
				return ErrInvalidSnapshot
			}
			if len(section.Items) > MaxAddressesPerInterface {
				return ErrSnapshotLimit
			}
			if section.Meta.Coverage == Failed {
				incomplete = true
			}
			for j, addr := range section.Items {
				if addr.Family != family || !validAddress(addr) || j > 0 && compareAddress(section.Items[j-1], addr) >= 0 {
					return ErrInvalidSnapshot
				}
			}
			addresses += len(section.Items)
		}
		if len(row.Addresses.IPv4.Items)+len(row.Addresses.IPv6.Items) > MaxAddressesPerInterface {
			return ErrSnapshotLimit
		}

	}
	if addresses > MaxAddresses {
		return ErrSnapshotLimit
	}
	if s.Interfaces.Meta.Coverage == Partial && !incomplete || s.Interfaces.Meta.Coverage == Complete && incomplete {
		return ErrInvalidSnapshot
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return ErrInvalidSnapshot
	}
	if len(raw) > MaxSnapshotBytes {
		return ErrSnapshotLimit
	}
	return nil
}
func Encode(s Snapshot) ([]byte, error) {
	if e := Validate(s); e != nil {
		return nil, e
	}
	return json.Marshal(s)
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func validMeta(m SectionMeta, n int, allowPartial bool) bool {
	switch m.Coverage {
	case Complete:
		return m.Reason == ReasonNone && m.CountExact && m.ObservedCount != nil && *m.ObservedCount == uint32(n)
	case Partial:
		return allowPartial && n > 0 && m.Reason == ReasonAddressUnavailable && m.CountExact && m.ObservedCount != nil && *m.ObservedCount == uint32(n)
	case Failed:
		return failureReasonValid(m.Reason) && !m.CountExact && m.ObservedCount == nil && n == 0
	default:
		return false
	}
}
func failureReasonValid(r Reason) bool {
	switch r {
	case ReasonSourceMissing, ReasonPermissionDenied, ReasonNotSupported, ReasonTimeout, ReasonInvalidSource, ReasonReadFailed, ReasonItemLimit, ReasonByteLimit, ReasonCollectorBusy, ReasonNotCollected:
		return true
	}
	return false
}
func safeText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}
func safeInterfaceName(s string) bool {
	if !safeText(s, MaxInterfaceNameBytes) || s == "." || s == ".." || strings.ContainsAny(s, "/:\\") {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
func validAddress(row Address) bool {
	a, e := netip.ParseAddr(row.Address)
	if e != nil || a.Zone() != "" || a.String() != row.Address {
		return false
	}
	family := "ipv6"
	if a.Is4() {
		family = "ipv4"
	}
	return row.Family == family && row.Scope == addressScope(a)
}
func addressScope(a netip.Addr) string {
	switch {
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLoopback():
		return "loopback"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case a.IsMulticast():
		return "multicast"
	case a.IsPrivate():
		return "private"
	default:
		return "other"
	}
}
func compareAddress(a, b Address) int {
	if a.Family != b.Family {
		return strings.Compare(a.Family, b.Family)
	}
	x, _ := netip.ParseAddr(a.Address)
	y, _ := netip.ParseAddr(b.Address)
	if c := x.Compare(y); c != 0 {
		return c
	}
	return 0
}
