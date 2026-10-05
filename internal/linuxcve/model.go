// Package linuxcve imports bounded, explicitly supplied distribution advisory
// records and evaluates installed source versions. It has no network client,
// collector, scheduler, package installer, or persistent store. Local imports do
// not authenticate their claimed publisher, freshness, or installed origin.
package linuxcve

import (
	"context"
	"errors"
	"io"
	"localrmm/internal/linuxpackages"
	"sync"
	"time"
)

const (
	BundleSchemaVersion = "linux-cve-bundle-1"
	ResultSchemaVersion = "tracebolt.linux-cve-result.v1"
	DebianProvider      = "debian-security-tracker"
	UbuntuProvider      = "canonical-ubuntu-osv"
	MaxBundleBytes      = 32 << 20
	// The measured official Debian identity response is 81,530,876 bytes.
	// This scoped decoded JSON bound does not enlarge manual import budgets.
	MaxOfficialJSONBytes  = 96 << 20
	MaxRecords            = 250000
	MaxFindings           = 100
	MaxBinariesPerFinding = 20
	MaxBinaryRows         = 128
	MaxComparisons        = 2000
	MaxResultBytes        = 230 << 10
	FeedTTL               = 48 * time.Hour
	InventoryTTL          = 24 * time.Hour
)

var (
	ErrInvalid  = errors.New("linux_cve_bundle_invalid")
	ErrLimit    = errors.New("linux_cve_limit_exceeded")
	ErrCanceled = errors.New("linux_cve_canceled")
	ErrRollback = errors.New("linux_cve_rollback_rejected")
)

// FeedMetadata describes only the records actually imported. SHA256 hashes the
// exact payload bytes, not a signature; SourceURL is attribution, not proof that
// a local bundle was obtained there. Freshness uses the supplied fetch time.
type FeedMetadata struct {
	Provider    string                      `json:"provider"`
	Target      linuxpackages.ReleaseTarget `json:"target"`
	SourceURL   string                      `json:"sourceUrl"`
	License     string                      `json:"license"`
	SHA256      string                      `json:"sha256"`
	FetchedAt   time.Time                   `json:"fetchedAt"`
	ValidatedAt time.Time                   `json:"validatedAt"`
	ExpiresAt   time.Time                   `json:"expiresAt"`
	Freshness   string                      `json:"freshness"`
	Trust       string                      `json:"trust"`
	Coverage    string                      `json:"coverage"`
	SourceCount int                         `json:"sourceCount"`
	RecordCount int                         `json:"recordCount"`
}

// Snapshot can only be populated by Parse. It is immutable and safe to share.
type Snapshot struct {
	metadata FeedMetadata
	rules    map[string][]rule
	valid    bool
}

type interval struct{ introduced, fixed string }
type rule struct {
	cve         string
	fixed       string
	advisoryURL string
	reason      string
	intervals   []interval
}

func (s *Snapshot) Metadata(now time.Time) FeedMetadata {
	if s == nil || !s.valid {
		return FeedMetadata{Freshness: "unknown"}
	}
	m := s.metadata
	m.Freshness = freshness(m.FetchedAt, m.ExpiresAt, now)
	return m
}

type Binary struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type Finding struct {
	CVEID                  string   `json:"cveId"`
	SourcePackage          string   `json:"sourcePackage"`
	InstalledSourceVersion string   `json:"installedSourceVersion"`
	PublishedFixedVersion  string   `json:"publishedFixedVersion"`
	Basis                  string   `json:"basis"`
	AdvisoryURL            string   `json:"advisoryUrl"`
	Binaries               []Binary `json:"binaries"`
	BinariesTruncated      bool     `json:"binariesTruncated"`
}

// Result rows are lossless version matches, not a distinct warning count. A UI
// groups rows by CVEID and SourcePackage to display one warning with every
// installed-source/fixed-version pair.
// Result never means secure, exploitable, or that an update is available from
// the endpoint's configured repositories. Zero findings is a scoped observation.
// Status is unavailable, partial, or stale; imported subsets and unverified
// installed origin intentionally cannot produce a complete coverage state.
type Result struct {
	SchemaVersion        string        `json:"schemaVersion"`
	Status               string        `json:"status"`
	Freshness            string        `json:"freshness"`
	InventoryFreshness   string        `json:"inventoryFreshness"`
	AssessedAt           time.Time     `json:"assessedAt"`
	GenerationID         string        `json:"generationId"`
	Feed                 *FeedMetadata `json:"feed"`
	Findings             []Finding     `json:"findings"`
	ReasonCodes          []string      `json:"reasonCodes"`
	EvaluatedSourceCount int           `json:"evaluatedSourceCount"`
	SkippedPackageCount  int           `json:"skippedPackageCount"`
	Truncated            bool          `json:"truncated"`
}

type StoreView struct {
	Snapshots     []FeedMetadata `json:"snapshots"`
	LastAttemptAt *time.Time     `json:"lastAttemptAt"`
	Outcome       string         `json:"outcome"`
	FailureReason string         `json:"failureReason"`
}

// Store is a zero-value-ready, per-provider atomic last-good in-memory store.
// Restarting loses snapshots. Failed parse/promotion never clears a snapshot.
type Store struct {
	mu            sync.RWMutex
	snapshots     map[linuxpackages.ReleaseTarget]*Snapshot
	lastAttemptAt *time.Time
	outcome       string
	failureReason string
}

func (s *Store) Import(ctx context.Context, r io.Reader, now time.Time) (FeedMetadata, error) {
	snapshot, err := Parse(ctx, r, now)
	if err != nil {
		s.RecordFailure(now, err.Error())
		return FeedMetadata{}, err
	}
	if err = s.Replace(snapshot, now); err != nil {
		s.RecordFailure(now, err.Error())
		return FeedMetadata{}, err
	}
	return snapshot.Metadata(now), nil
}
