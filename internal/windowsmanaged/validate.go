package windowsmanaged

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"localrmm/internal/windowsinventory"
)

func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.CollectionProfile != CollectionProfile || !validGeneration(s.GenerationID) || !validTime(s.CollectedAt) {
		return ErrInvalidSnapshot
	}
	if err := validateSection(s.Hostname, MaxHostnameRows, 1, validHostname); err != nil {
		return err
	}
	if s.Hostname.Complete && len(s.Hostname.Rows) != 1 {
		return ErrInvalidSnapshot
	}
	if err := validateSection(s.Processes, MaxProcessRows, windowsinventory.MaxProcesses, validProcess); err != nil {
		return err
	}
	if err := validateSection(s.Services, MaxServiceRows, windowsinventory.MaxServices, validService); err != nil {
		return err
	}
	if err := validateSection(s.Software, MaxSoftwareRows, windowsinventory.MaxSoftware, validSoftware); err != nil {
		return err
	}
	if err := validateSection(s.Network, MaxNetworkRows, windowsinventory.MaxAddresses, validAddress); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
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

func validateSection[T any](s Section[T], maxRows, maxObserved int, valid func(T) bool) error {
	if len(s.Rows) > maxRows || uint64(s.ObservedCount) > uint64(maxObserved) {
		return ErrSnapshotLimit
	}
	if s.Rows == nil || !validText(s.Source, true, MaxMetadataBytes) || !validText(s.Scope, true, MaxMetadataBytes) || int(s.ObservedCount) < len(s.Rows) {
		return ErrInvalidSnapshot
	}
	// A count difference can only be produced by explicit row omission.
	if int(s.ObservedCount) > len(s.Rows) && !s.Truncated {
		return ErrInvalidSnapshot
	}
	switch s.Quality {
	case QualityHealthy:
		if !s.Complete || !s.CountExact || s.Truncated || int(s.ObservedCount) != len(s.Rows) {
			return ErrInvalidSnapshot
		}
	case QualityPartial:
		if s.Complete || s.CountExact && (!s.Truncated || int(s.ObservedCount) == len(s.Rows)) {
			return ErrInvalidSnapshot
		}
	case QualityDenied, QualityUnavailable:
		if s.Complete || s.CountExact || s.ObservedCount != 0 || len(s.Rows) != 0 {
			return ErrInvalidSnapshot
		}
	default:
		return ErrInvalidSnapshot
	}
	for _, row := range s.Rows {
		if !valid(row) {
			return ErrInvalidSnapshot
		}
	}
	return nil
}

func validGeneration(s string) bool {
	if len(s) != len("sample_")+32 || !strings.HasPrefix(s, "sample_") {
		return false
	}
	for _, c := range s[len("sample_"):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}

func validText(s string, required bool, max int) bool {
	return (!required || strings.TrimSpace(s) != "") && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError || r == '\u2028' || r == '\u2029'
	}) < 0
}

func validHostname(v Hostname) bool { return validText(v.Value, true, MaxTextBytes) }
func validProcess(v Process) bool {
	return validText(v.Name, true, MaxTextBytes) && !strings.ContainsAny(v.Name, `\/`)
}
func validService(v Service) bool {
	if !validText(v.Name, true, MaxTextBytes) || !validText(v.DisplayName, false, MaxTextBytes) {
		return false
	}
	switch v.State {
	case "stopped", "start_pending", "stop_pending", "running", "continue_pending", "pause_pending", "paused":
		return true
	}
	return false
}
func validSoftware(v Software) bool {
	return validText(v.Name, true, MaxTextBytes) && validText(v.Version, false, MaxTextBytes) && validText(v.Publisher, false, MaxTextBytes) && (v.RegistryView == "32" || v.RegistryView == "64")
}
func validAddress(v InterfaceAddress) bool {
	a, err := netip.ParseAddr(v.Address)
	return err == nil && a.Zone() == "" && a.String() == v.Address && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && uint64(v.Index) <= uint64(^uint32(0)) && v.Index > 0 && validText(v.Name, true, MaxTextBytes) && v.PrefixLength >= 0 && v.PrefixLength <= a.BitLen()
}
