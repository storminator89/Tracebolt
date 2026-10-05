package cachedupdates

import (
	"context"
	"encoding/json"
	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/linuxpackages"
	"regexp"
	"time"
)

var generationPattern = regexp.MustCompile(`^sample_[0-9a-f]{32}$`)
var packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,255}$`)
var architecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var releasePattern = regexp.MustCompile(`^[a-z0-9._-]{0,128}$`)

func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func Validate(s Snapshot) error {
	bad := ErrInvalidSnapshot
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !generationPattern.MatchString(s.GenerationID) || !validTime(s.CollectedAt) || s.DurationMS < 0 || s.DurationMS > 1<<53-1 || s.Items == nil || len(s.Items) > MaxRows {
		return bad
	}
	for _, f := range []*string{s.Release.ID, s.Release.VersionID, s.Release.VersionCodename} {
		if f != nil && !releasePattern.MatchString(*f) {
			return bad
		}
	}
	m := s.Metadata
	if m.Refresh != "not_attempted" || m.AgeBasis != "oldest-local-package-index-mtime" || (m.Freshness != "unknown" && m.Freshness != "stale") || (m.AgeSeconds == nil) != (m.OldestIndexModifiedAt == nil) {
		return bad
	}
	if m.OldestIndexModifiedAt != nil {
		if !validTime(*m.OldestIndexModifiedAt) || m.OldestIndexModifiedAt.After(s.CollectedAt) || *m.AgeSeconds != metadataAgeSeconds(s.CollectedAt, *m.OldestIndexModifiedAt) || *m.AgeSeconds > 1<<53-1 {
			return bad
		}
		if (m.Freshness == "stale") != (*m.AgeSeconds >= uint64(MetadataStaleAfter/time.Second)) {
			return bad
		}
	} else if m.Freshness != "unknown" {
		return bad
	}
	if s.Coverage == "unavailable" {
		if !failureReason(s.Reason) || s.InstalledCount != nil || s.CheckedCount != nil || s.CandidateCount != nil || s.HeldCount != nil || s.UnknownCount != nil || len(s.Items) > 0 || s.Truncated {
			return bad
		}
	} else {
		if s.Release.Target() != linuxpackages.Debian13 && s.Release.Target() != linuxpackages.Ubuntu2404 || m.OldestIndexModifiedAt == nil {
			return bad
		}
		if s.InstalledCount == nil || s.CheckedCount == nil || s.CandidateCount == nil || s.HeldCount == nil || s.UnknownCount == nil {
			return bad
		}
		installed, checked, candidates, held, unknown := *s.InstalledCount, *s.CheckedCount, *s.CandidateCount, *s.HeldCount, *s.UnknownCount
		if installed > MaxInstalledRows || checked > installed || unknown > installed || checked+unknown != installed || candidates > checked || held > candidates || uint32(len(s.Items)) > candidates || s.Truncated != (uint32(len(s.Items)) < candidates) {
			return bad
		}
		switch s.Coverage {
		case "complete":
			if s.Reason != ReasonNone || s.Truncated || unknown != 0 {
				return bad
			}
		case "partial":
			if !s.Truncated && unknown == 0 || s.Reason != ReasonItemLimit && s.Reason != ReasonByteLimit && s.Reason != ReasonCandidateUnknown || !s.Truncated && s.Reason != ReasonCandidateUnknown || s.Reason == ReasonCandidateUnknown && unknown == 0 {
				return bad
			}
		default:
			return bad
		}
		shownHeld := uint32(0)
		for i, row := range s.Items {
			if ValidateCandidate(row) != nil {
				return bad
			}
			if i > 0 && (s.Items[i-1].Name > row.Name || s.Items[i-1].Name == row.Name && s.Items[i-1].Architecture >= row.Architecture) {
				return bad
			}
			if row.State == "held" {
				shownHeld++
			}
		}
		if shownHeld > held || held-shownHeld > candidates-uint32(len(s.Items)) {
			return bad
		}
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxSnapshotBytes {
		return bad
	}
	return nil
}
func Encode(s Snapshot) ([]byte, error) {
	if e := Validate(s); e != nil {
		return nil, e
	}
	return json.Marshal(s)
}
func trim(s Snapshot) (Snapshot, error) {
	if len(s.Items) > MaxRows {
		s.Items = s.Items[:MaxRows]
		s.Truncated = true
		s.Coverage = "partial"
		s.Reason = ReasonItemLimit
	}
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalidSnapshot
		}
		if len(b) <= MaxSnapshotBytes {
			return s, Validate(s)
		}
		if len(s.Items) == 0 {
			return Snapshot{}, ErrInvalidSnapshot
		}
		s.Items = s.Items[:len(s.Items)-1]
		s.Truncated = true
		s.Coverage = "partial"
		s.Reason = ReasonByteLimit
	}
}

// Avoid time.Duration saturation for legal RFC3339 dates centuries apart.
func metadataAgeSeconds(at, then time.Time) uint64 {
	seconds := at.Unix() - then.Unix()
	if at.Nanosecond() < then.Nanosecond() {
		seconds--
	}
	return uint64(seconds)
}

// ValidateCandidate is the existing pure per-row grammar and newer-version
// check, independent of the bounded preview's row/byte/count limits. It grants
// no collection or full-row transmission consent and makes no installability,
// repository freshness or CVE assertion.
func ValidateCandidate(row Candidate) error {
	if !packagePattern.MatchString(row.Name) || !architecturePattern.MatchString(row.Architecture) || !assessment.ValidDebianVersion(row.InstalledVersion) || !assessment.ValidDebianVersion(row.CandidateVersion) || row.Installability != "not_evaluated" || (row.State != "candidate_only" && row.State != "held") {
		return ErrInvalidSnapshot
	}
	cmp, err := (debianversion.Comparator{}).Compare(context.Background(), row.InstalledVersion, row.CandidateVersion)
	if err != nil || cmp >= 0 {
		return ErrInvalidSnapshot
	}
	return nil
}
