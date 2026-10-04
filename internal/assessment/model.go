// Package assessment contains isolated, read-only software assessment foundations.
// Its normalized snapshot parser is used by offline catalog validation; matching
// and native inventory remain disconnected. An assessed scope never claims that
// an endpoint is secure, and an advisory fix is never an offered update.
package assessment

import (
	"context"
	"time"
)

const SchemaVersion = "assessment-foundation-1"

type Coverage string

const (
	Assessed Coverage = "assessed"
	Partial  Coverage = "partial"
	Unknown  Coverage = "unknown"
)

type Freshness string

const (
	Fresh            Freshness = "fresh"
	Stale            Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

type Status string

const (
	StatusAssessed Status = "assessed"
	StatusPartial  Status = "partial"
	StatusUnknown  Status = "unknown"
	StatusStale    Status = "stale"
)

// Quality preserves coverage independently from age: partial and stale coexist.
// Counts are nil when enumeration/assessment did not run successfully.
type Quality struct {
	Coverage        Coverage  `json:"coverage"`
	Freshness       Freshness `json:"freshness"`
	Scope           string    `json:"scope"`
	ExcludedScopes  []string  `json:"excludedScopes"`
	ReasonCodes     []string  `json:"reasonCodes"`
	AssessedAt      time.Time `json:"assessedAt"`
	AssessedItems   *int      `json:"assessedItems"`
	UnassessedItems *int      `json:"unassessedItems"`
}

func (q Quality) Status() Status {
	if q.Freshness == Stale {
		return StatusStale
	}
	switch q.Coverage {
	case Assessed:
		return StatusAssessed
	case Partial:
		return StatusPartial
	default:
		return StatusUnknown
	}
}

type SourceSnapshot struct {
	ID          string    `json:"id"`
	Provider    string    `json:"provider"`
	Kind        string    `json:"kind"`
	PublicURL   string    `json:"publicUrl,omitempty"`
	SHA256      string    `json:"sha256"`
	Revision    string    `json:"revision,omitempty"`
	FetchedAt   time.Time `json:"fetchedAt"`
	ValidatedAt time.Time `json:"validatedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	// Trust is supplied by a trusted ingestion adapter, NEVER by feed JSON.
	Trust     string `json:"trust"`
	Synthetic bool   `json:"synthetic"`
}

func (s SourceSnapshot) FreshnessAt(now time.Time) Freshness {
	if s.FetchedAt.IsZero() || s.ValidatedAt.IsZero() || s.ExpiresAt.IsZero() || s.FetchedAt.After(now) || s.ValidatedAt.After(now) || s.ValidatedAt.Before(s.FetchedAt) || !s.ExpiresAt.After(s.ValidatedAt) {
		return FreshnessUnknown
	}
	if !now.Before(s.ExpiresAt) {
		return Stale
	}
	return Fresh
}

type Platform struct {
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	Distribution    string `json:"distribution"`
	Version         string `json:"version"`
	Codename        string `json:"codename"`
	CollectionScope string `json:"collectionScope"`
}

func (p Platform) supportedDebian() bool {
	return p.OS == "linux" && p.Distribution == "debian" && p.Codename == "trixie" && p.Version == "13"
}

// OriginEvidence must bind the exact installed artifact and source mapping to a
// validated vendor repository. Name/version coincidence is NOT this evidence.
// The local dpkg reader intentionally leaves it empty.
type OriginEvidence struct {
	Distribution              string `json:"distribution"`
	Release                   string `json:"release"`
	RepositoryID              string `json:"repositoryId"`
	EvidenceID                string `json:"evidenceId"`
	Package                   string `json:"package"`
	BinaryVersion             string `json:"binaryVersion"`
	Architecture              string `json:"architecture"`
	SourcePackage             string `json:"sourcePackage"`
	SourceVersion             string `json:"sourceVersion"`
	VerifiedMetadata          bool   `json:"verifiedMetadata"`
	InstalledArtifactVerified bool   `json:"installedArtifactVerified"`
}
type InstalledPackage struct {
	Name          string         `json:"name"`
	Version       string         `json:"version"`
	Architecture  string         `json:"architecture"`
	SourcePackage string         `json:"sourcePackage"`
	SourceVersion string         `json:"sourceVersion"`
	SourceMapping string         `json:"sourceMapping"`
	InstallState  string         `json:"installState"`
	Origin        OriginEvidence `json:"origin"`
}
type Inventory struct {
	SchemaVersion  string             `json:"schemaVersion"`
	Platform       Platform           `json:"platform"`
	Source         SourceSnapshot     `json:"source"`
	Quality        Quality            `json:"quality"`
	Packages       []InstalledPackage `json:"packages"`
	InstalledCount *int               `json:"installedCount"`
}

// AvailableUpdate is populated only by a separate native/catalog adapter.
// PublishedFixedVersion from an advisory must never create one of these rows.
type AvailableUpdate struct {
	Package        string `json:"package"`
	TargetVersion  string `json:"targetVersion"`
	NativeID       string `json:"nativeId"`
	OfferedState   string `json:"offeredState"`
	Installability string `json:"installability"`
}
type OfferedUpdates struct {
	Source       *SourceSnapshot   `json:"source"`
	Quality      Quality           `json:"quality"`
	Updates      []AvailableUpdate `json:"updates"`
	OfferedCount *int              `json:"offeredCount"`
}
type Verdict string

const (
	Affected       Verdict = "affected"
	Fixed          Verdict = "fixed"
	NotAffected    Verdict = "not_affected"
	NeedsReview    Verdict = "needs_review"
	VerdictUnknown Verdict = "unknown"
)

type Match struct {
	Package                string   `json:"package"`
	Architecture           string   `json:"architecture"`
	SourcePackage          string   `json:"sourcePackage"`
	InstalledSourceVersion string   `json:"installedSourceVersion"`
	AdvisoryID             string   `json:"advisoryId"`
	CVEID                  string   `json:"cveId,omitempty"`
	VendorStatus           string   `json:"vendorStatus"`
	Qualifications         []string `json:"qualifications"`
	Verdict                Verdict  `json:"verdict"`
	Basis                  string   `json:"basis"`
	Reason                 string   `json:"reason"`
	PublishedFixedVersion  string   `json:"publishedFixedVersion,omitempty"`
	FixAvailability        string   `json:"fixAvailability"`
	Activation             string   `json:"activation"`
	SnapshotID             string   `json:"snapshotId"`
	Synthetic              bool     `json:"synthetic"`
}
type VulnerabilityAssessment struct {
	Quality          Quality          `json:"quality"`
	Sources          []SourceSnapshot `json:"sources"`
	Matches          []Match          `json:"matches"`
	AffectedCVEs     *int             `json:"affectedCves"`
	ReviewCandidates *int             `json:"reviewCandidates"`
}
type Report struct {
	SchemaVersion   string                  `json:"schemaVersion"`
	Inventory       Inventory               `json:"inventory"`
	OfferedUpdates  OfferedUpdates          `json:"offeredUpdates"`
	Vulnerabilities VulnerabilityAssessment `json:"vulnerabilities"`
}

// Future Windows/macOS adapters implement these independently. Their absence is
// explicit; neither a successful inventory nor a CVE match implies update coverage.
type InventoryProvider interface {
	Collect(context.Context, Platform, time.Time) Inventory
}
type UpdateProvider interface {
	ObserveCached(context.Context, Inventory, time.Time) OfferedUpdates
}
type VersionComparator interface {
	Compare(context.Context, string, string) (int, error)
}

func UnimplementedUpdates(now time.Time) OfferedUpdates {
	return OfferedUpdates{Quality: Quality{Coverage: Unknown, Freshness: FreshnessUnknown, Scope: "configured-source-offered-updates", AssessedAt: now.UTC(), ReasonCodes: []string{"update_adapter_unimplemented"}}}
}
func unknownInventory(p Platform, now time.Time, reason string) Inventory {
	return Inventory{SchemaVersion: SchemaVersion, Platform: p, Quality: Quality{Coverage: Unknown, Freshness: FreshnessUnknown, Scope: "installed-os-packages", AssessedAt: now.UTC(), ReasonCodes: []string{reason}}}
}
func count(n int) *int { return &n }
