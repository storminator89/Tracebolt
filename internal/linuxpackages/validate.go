package linuxpackages

import (
	"encoding/json"
	"errors"
	"localrmm/internal/assessment"
	"regexp"
	"time"
)

var (
	ErrInvalidSnapshot = errors.New("package_snapshot_invalid")
	ErrSnapshotLimit   = errors.New("package_snapshot_limit_exceeded")
	generationPattern  = regexp.MustCompile(`^sample_[0-9a-f]{32}$`)
	packagePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,255}$`)
	archPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// Validate checks the typed, sorted export form and its canonical JSON byte cap.
// Decode must be used for incoming JSON to also reject unknown/duplicate keys,
// omitted members, wrong null/types and oversized raw JSON.
func Validate(s Snapshot) error {
	if err := validateShape(s, MaxExportRows, true); err != nil {
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

func validateShape(s Snapshot, rowLimit int, sorted bool) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != SnapshotScope ||
		!generationPattern.MatchString(s.GenerationID) || !validTime(s.CollectedAt) ||
		s.DurationMS < 0 || s.DurationMS > MaxSafeInteger {
		return ErrInvalidSnapshot
	}
	if !validQualityReason(s.Release.Quality, s.Release.Reason) {
		return ErrInvalidSnapshot
	}
	for _, value := range []*string{s.Release.Fields.ID, s.Release.Fields.VersionID, s.Release.Fields.VersionCodename} {
		if s.Release.Quality != Healthy && value != nil || value != nil && (len(*value) > MaxReleaseValue || !validReleaseIdentifier(*value)) {
			return ErrInvalidSnapshot
		}
	}
	if s.Release.Quality == Healthy && s.Release.Reason != ReasonNone {
		return ErrInvalidSnapshot
	}
	x := s.Inventory
	if !validQualityReason(x.Quality, x.Reason) || x.Items == nil || len(x.Items) > rowLimit {
		return ErrInvalidSnapshot
	}
	if x.Quality != Healthy {
		if len(x.Items) != 0 || x.Complete || x.Truncated || x.CountExact || x.ObservedCount != nil || x.InstalledCount != nil {
			return ErrInvalidSnapshot
		}
		return nil
	}
	if !x.CountExact || x.ObservedCount == nil || x.InstalledCount == nil ||
		*x.ObservedCount > MaxDpkgRecords || *x.InstalledCount > *x.ObservedCount ||
		*x.ObservedCount < uint64(len(x.Items)) {
		return ErrInvalidSnapshot
	}
	if x.Complete {
		if x.Truncated || x.Reason != ReasonNone || *x.ObservedCount != uint64(len(x.Items)) {
			return ErrInvalidSnapshot
		}
	} else if !x.Truncated || *x.ObservedCount <= uint64(len(x.Items)) || (x.Reason != ReasonItemLimit && x.Reason != ReasonByteLimit) {
		return ErrInvalidSnapshot
	}
	seen := make(map[string]bool, len(x.Items))
	var installed uint64
	for i, p := range x.Items {
		if !validPackageRow(p) {
			return ErrInvalidSnapshot
		}
		identity := p.Name + ":" + p.Architecture
		if seen[identity] || sorted && i > 0 && rowLess(p, x.Items[i-1]) {
			return ErrInvalidSnapshot
		}
		seen[identity] = true
		if p.InstallState == "installed" {
			installed++
		}
	}
	// Omitted rows can contain at most one installed package per omitted row.
	// This checks both lower and upper feasibility for a truncated source total.
	if *x.InstalledCount < installed || *x.InstalledCount-installed > *x.ObservedCount-uint64(len(x.Items)) {
		return ErrInvalidSnapshot
	}
	return nil
}

func validPackageRow(p PackageRow) bool {
	if !packagePattern.MatchString(p.Name) || !packagePattern.MatchString(p.SourcePackage) ||
		!archPattern.MatchString(p.Architecture) || !binaryArchitecture(p.Architecture) ||
		!assessment.ValidDebianVersion(p.Version) || !assessment.ValidDebianVersion(p.SourceVersion) ||
		(p.InstallState != "installed" && p.InstallState != "incomplete") {
		return false
	}
	switch p.SourceMapping {
	case "binary-default":
		return p.SourcePackage == p.Name && p.SourceVersion == p.Version
	case "source-field":
		return true
	default:
		return false
	}
}

func validQualityReason(q Quality, r Reason) bool {
	if !validReason(r) {
		return false
	}
	switch q {
	case Healthy:
		return r == ReasonNone || r == ReasonItemLimit || r == ReasonByteLimit
	case Unknown:
		return r != ReasonNone && r != ReasonPermissionDenied
	case Denied:
		return r == ReasonPermissionDenied
	default:
		return false
	}
}

func validReason(r Reason) bool {
	switch r {
	case ReasonNone, ReasonSourceMissing, ReasonPermissionDenied, ReasonNotSupported,
		ReasonTimeout, ReasonInvalidSource, ReasonReadFailed, ReasonSourceChanged,
		ReasonItemLimit, ReasonByteLimit, ReasonNotImplemented, ReasonCollectorBusy:
		return true
	default:
		return false
	}
}

func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}

func rowLess(a, b PackageRow) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Architecture < b.Architecture
}
