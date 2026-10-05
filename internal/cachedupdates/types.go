// Package cachedupdates observes native APT candidates from existing local
// metadata only. It never refreshes metadata, installs packages, or assesses CVEs.
package cachedupdates

import (
	"errors"
	"localrmm/internal/linuxpackages"
	"time"
)

const (
	SchemaVersion      = "tracebolt.cached-apt-updates.v1"
	Scope              = "agent-visible-dpkg-and-existing-apt-cache"
	MaxSnapshotBytes   = 2 << 10
	MaxRows            = 16
	MaxInstalledRows   = 16384
	CollectionTimeout  = 15 * time.Second
	MetadataStaleAfter = 48 * time.Hour
	MaxConsentBytes    = 1024
	ConsentVersion     = "tracebolt.cached-apt-updates-local-consent.v1"
)

var ErrInvalidInput = errors.New("cached_updates_invalid_input")
var ErrInvalidSnapshot = errors.New("cached_updates_invalid_snapshot")

type Reason string

const (
	ReasonNone             Reason = "none"
	ReasonNotSupported     Reason = "not_supported"
	ReasonSourceMissing    Reason = "source_missing"
	ReasonCacheMissing     Reason = "cache_missing"
	ReasonPermissionDenied Reason = "permission_denied"
	ReasonReadFailed       Reason = "read_failed"
	ReasonInvalidSource    Reason = "invalid_source"
	ReasonSourceChanged    Reason = "source_changed"
	ReasonTimeout          Reason = "timeout"
	ReasonCollectorBusy    Reason = "collector_busy"
	ReasonItemLimit        Reason = "item_limit"
	ReasonByteLimit        Reason = "byte_limit"
	ReasonWorkLimit        Reason = "work_limit"
	ReasonCandidateUnknown Reason = "candidate_unknown"
)

type Snapshot struct {
	SchemaVersion  string                      `json:"schemaVersion"`
	Scope          string                      `json:"scope"`
	GenerationID   string                      `json:"generationId"`
	CollectedAt    time.Time                   `json:"collectedAt"`
	DurationMS     int64                       `json:"durationMs"`
	Release        linuxpackages.ReleaseFields `json:"release"`
	Coverage       string                      `json:"coverage"` // complete, partial, unavailable
	Reason         Reason                      `json:"reason"`
	Metadata       Metadata                    `json:"metadata"`
	InstalledCount *uint32                     `json:"installedCount"`
	CheckedCount   *uint32                     `json:"checkedCount"`
	CandidateCount *uint32                     `json:"candidateCount"` // newer native candidates, including holds
	HeldCount      *uint32                     `json:"heldCount"`
	UnknownCount   *uint32                     `json:"unknownCount"`
	Truncated      bool                        `json:"truncated"`
	Items          []Candidate                 `json:"items"`
}
type Metadata struct {
	Freshness             string     `json:"freshness"` // unknown or stale; mtime never proves refresh success
	OldestIndexModifiedAt *time.Time `json:"oldestIndexModifiedAt"`
	AgeSeconds            *uint64    `json:"ageSeconds"`
	AgeBasis              string     `json:"ageBasis"`
	Refresh               string     `json:"refresh"` // not_attempted
}
type Candidate struct {
	Name             string `json:"name"`
	Architecture     string `json:"architecture"`
	InstalledVersion string `json:"installedVersion"`
	CandidateVersion string `json:"candidateVersion"`
	State            string `json:"state"`          // candidate_only or held
	Installability   string `json:"installability"` // not_evaluated
}

func Empty(generation string, at time.Time, reason Reason) Snapshot {
	if !failureReason(reason) {
		reason = ReasonReadFailed
	}
	return Snapshot{SchemaVersion: SchemaVersion, Scope: Scope, GenerationID: generation, CollectedAt: at,
		Coverage: "unavailable", Reason: reason, Metadata: unknownMetadata(), Items: []Candidate{}}
}
func unknownMetadata() Metadata {
	return Metadata{Freshness: "unknown", AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}
}
func failureReason(r Reason) bool {
	switch r {
	case ReasonNotSupported, ReasonSourceMissing, ReasonCacheMissing, ReasonPermissionDenied, ReasonReadFailed, ReasonInvalidSource, ReasonSourceChanged, ReasonTimeout, ReasonCollectorBusy, ReasonByteLimit, ReasonWorkLimit:
		return true
	}
	return false
}
