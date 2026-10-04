package offlinecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"localrmm/internal/assessment"
	"localrmm/internal/linuxpackages"
)

const (
	ReviewSchemaVersion  = "tracebolt.offline-review.v1"
	MaxReviewRows        = 128
	MaxReviewPairs       = 4096
	MaxReviewComparisons = 1024
	MaxReviewBytes       = 64 << 10
)

var ErrReviewContextRequired = errors.New("review_context_required")
var ErrReviewEncoding = errors.New("review_encoding_failed")

// ReviewResult describes only a bounded conditional inspection of reported
// metadata. Status complete never means complete CVE coverage or a secure host.
// Catalog, Snapshot and Candidates are independent copies owned by the caller.
// Confirmed affected-CVE and offered-update counts are always null.
type ReviewResult struct {
	SchemaVersion           string            `json:"schemaVersion"`
	Scope                   string            `json:"scope"`
	Status                  string            `json:"status"`
	ReasonCodes             []string          `json:"reasonCodes"`
	Revision                string            `json:"revision"`
	Catalog                 *Metadata         `json:"catalog"`
	CatalogUsage            string            `json:"catalogUsage"`
	Snapshot                ReviewSnapshot    `json:"snapshot"`
	InstalledArtifactOrigin string            `json:"installedArtifactOrigin"`
	SnapshotFreshness       string            `json:"snapshotFreshness"`
	Candidates              []ReviewCandidate `json:"candidates"`
	AffectedCVEs            *int              `json:"affectedCves"`
	OfferedUpdates          *int              `json:"offeredUpdates"`
	PairsInspected          int               `json:"pairsInspected"`
	Comparisons             int               `json:"comparisons"`
	Limits                  ReviewLimits      `json:"limits"`
}

type ReviewSnapshot struct {
	GenerationID      string                      `json:"generationId"`
	CollectedAt       time.Time                   `json:"collectedAt"`
	Release           linuxpackages.ReleaseFields `json:"release"`
	InventoryComplete bool                        `json:"inventoryComplete"`
	InventoryRows     int                         `json:"inventoryRows"`
}

type ReviewLimits struct {
	MaxRows        int `json:"maxRows"`
	MaxPairs       int `json:"maxPairs"`
	MaxComparisons int `json:"maxComparisons"`
	MaxBytes       int `json:"maxBytes"`
}

// ReviewCandidate has no verdict, offered version, archive, or trusted-origin
// field. DeclaredFixedVersion is unverified catalog content, not an update.
type ReviewCandidate struct {
	Package               string   `json:"package"`
	Architecture          string   `json:"architecture"`
	ReportedSourcePackage string   `json:"reportedSourcePackage"`
	ReportedSourceVersion string   `json:"reportedSourceVersion"`
	SourceMapping         string   `json:"sourceMapping"`
	AdvisoryID            string   `json:"advisoryId"`
	DeclaredStatus        string   `json:"declaredStatus"`
	DeclaredFixedVersion  string   `json:"declaredFixedVersion"`
	Qualifications        []string `json:"qualifications"`
	Basis                 string   `json:"basis"`
	Reason                string   `json:"reason"`
}

// Review accepts the validated observation contract, validating it again at the
// boundary. Callers must not concurrently mutate snapshot during this call.
// expectedRevision must be the nonempty revision the caller intends to inspect.
// No catalog lock is held while invoking the explicitly supplied comparator.
// The comparator must honor ctx; there is no default, subprocess, or fallback.
// Errors (including cancellation/replacement) always return a zero result.
func (s *Store) Review(ctx context.Context, expectedRevision string, snapshot linuxpackages.Snapshot, comparator assessment.VersionComparator) (ReviewResult, error) {
	if ctx == nil {
		return ReviewResult{}, ErrReviewContextRequired
	}
	if err := ctx.Err(); err != nil {
		return ReviewResult{}, err
	}
	if s == nil || s.state == nil {
		return ReviewResult{}, ErrUnavailable
	}
	s.state.mu.RLock()
	catalog, revision := s.state.catalog, s.state.revision
	s.state.mu.RUnlock()
	if expectedRevision == "" || expectedRevision != revision {
		return ReviewResult{}, ErrChanged
	}
	if err := linuxpackages.Validate(snapshot); err != nil {
		return ReviewResult{}, err
	}
	// Retain no mutable snapshot storage, including pointers inside release facts.
	packages := append([]linuxpackages.PackageRow(nil), snapshot.Inventory.Items...)
	result := ReviewResult{
		SchemaVersion: ReviewSchemaVersion, Scope: "conditional-reported-source-catalog-review",
		Status: "unavailable", ReasonCodes: []string{}, Revision: revision,
		CatalogUsage: "unavailable", InstalledArtifactOrigin: "unknown", SnapshotFreshness: "unknown",
		Candidates: []ReviewCandidate{}, Limits: ReviewLimits{MaxReviewRows, MaxReviewPairs, MaxReviewComparisons, MaxReviewBytes},
		Snapshot: ReviewSnapshot{GenerationID: snapshot.GenerationID, CollectedAt: snapshot.CollectedAt,
			Release: copyReviewRelease(snapshot.Release.Fields), InventoryComplete: snapshot.Inventory.Complete,
			InventoryRows: len(packages)},
	}
	if catalog != nil {
		metadata := catalog.metadata
		if metadata.PublishedAt != nil {
			publishedAt := *metadata.PublishedAt
			metadata.PublishedAt = &publishedAt
		}
		result.Catalog = &metadata
		result.CatalogUsage = "unverified-conditional-review"
		result.addReason("catalog_origin_unverified")
		result.addReason("catalog_freshness_unknown")
	}
	result.addReason("installed_artifact_origin_unknown")
	result.addReason("snapshot_freshness_not_evaluated")
	finish := func() (ReviewResult, error) {
		if err := result.boundBytes(ctx); err != nil {
			return ReviewResult{}, err
		}
		s.state.mu.RLock()
		defer s.state.mu.RUnlock()
		if err := ctx.Err(); err != nil {
			return ReviewResult{}, err
		}
		if s.state.revision != revision {
			return ReviewResult{}, ErrChanged
		}
		return result, nil
	}
	if catalog == nil {
		result.addReason("catalog_unavailable")
		return finish()
	}
	if catalog.metadata.Synthetic {
		result.CatalogUsage = "synthetic-fixture-not-for-live-review"
		result.addReason("synthetic_catalog")
		return finish()
	}
	if snapshot.Release.Quality != linuxpackages.Healthy {
		result.addReason("release_unavailable")
		return finish()
	}
	switch result.Snapshot.Release.Target() {
	case linuxpackages.Incomplete:
		result.addReason("release_facts_missing")
		return finish()
	case linuxpackages.Inconsistent:
		result.addReason("release_facts_inconsistent")
		return finish()
	case linuxpackages.Debian13:
		if catalog.metadata.DeclaredRelease != *result.Snapshot.Release.VersionCodename {
			result.addReason("catalog_release_mismatch")
			return finish()
		}
	default:
		result.addReason("unsupported_release")
		return finish()
	}
	if snapshot.Inventory.Quality != linuxpackages.Healthy {
		result.addReason("inventory_unavailable")
		return finish()
	}
	result.Status = "complete"
	if !result.Snapshot.InventoryComplete {
		result.incomplete("inventory_partial")
	}
	// Indexing is bounded by Parse's 10,000-rule cap. Sorting indices never
	// changes the captured immutable document or copies archive-version content.
	rules := make(map[string][]int)
	covered := make(map[string]bool, len(catalog.document.CoveredSources))
	for _, source := range catalog.document.CoveredSources {
		if err := ctx.Err(); err != nil {
			return ReviewResult{}, err
		}
		covered[string(source)] = true
	}
	for i, rule := range catalog.document.Rules {
		if err := ctx.Err(); err != nil {
			return ReviewResult{}, err
		}
		rules[string(rule.SourcePackage)] = append(rules[string(rule.SourcePackage)], i)
	}
	for _, indices := range rules {
		if err := ctx.Err(); err != nil {
			return ReviewResult{}, err
		}
		sort.Slice(indices, func(i, j int) bool {
			return catalog.document.Rules[indices[i]].AdvisoryID < catalog.document.Rules[indices[j]].AdvisoryID
		})
	}
	for _, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return ReviewResult{}, err
		}
		if pkg.InstallState != "installed" {
			result.incomplete("package_installation_incomplete")
			continue
		}
		if !covered[pkg.SourcePackage] {
			result.incomplete("source_package_not_covered")
			continue
		}
		for _, index := range rules[pkg.SourcePackage] {
			if err := ctx.Err(); err != nil {
				return ReviewResult{}, err
			}
			if len(result.Candidates) == MaxReviewRows {
				result.incomplete("review_row_limit")
				return finish()
			}
			if result.PairsInspected == MaxReviewPairs {
				result.incomplete("review_pair_limit")
				return finish()
			}
			rule := catalog.document.Rules[index]
			result.PairsInspected++
			candidate := ReviewCandidate{
				Package: pkg.Name, Architecture: pkg.Architecture, ReportedSourcePackage: pkg.SourcePackage,
				ReportedSourceVersion: pkg.SourceVersion, SourceMapping: pkg.SourceMapping,
				AdvisoryID: string(rule.AdvisoryID), DeclaredStatus: string(rule.Status),
				DeclaredFixedVersion: string(rule.FixedVersion), Qualifications: make([]string, len(rule.Qualifications)),
			}
			for i, value := range rule.Qualifications {
				candidate.Qualifications[i] = string(value)
			}
			switch {
			case rule.Status == "resolved" && rule.FixedVersion == "0":
				// The declaration's sentinel is not an installed not-affected claim.
				continue
			case rule.Status == "resolved" && rule.FixedVersion != "":
				candidate.Basis = "comparison_unavailable"
				candidate.Reason = "comparator_unavailable"
				if comparator != nil {
					if result.Comparisons == MaxReviewComparisons {
						result.incomplete("review_comparison_limit")
						return finish()
					}
					result.Comparisons++
					order, err := comparator.Compare(ctx, pkg.SourceVersion, string(rule.FixedVersion))
					if canceled := ctx.Err(); canceled != nil {
						return ReviewResult{}, canceled
					}
					if err != nil || order < -1 || order > 1 {
						candidate.Reason = "comparison_failed"
					} else if order >= 0 {
						// Omission is not a fixed or not-affected verdict.
						continue
					} else {
						candidate.Basis = "conditional_reported_source_below_declared_fix"
						candidate.Reason = "reported_source_below_declared_fix"
					}
				}
			case (rule.Status == "open" || rule.Status == "undetermined") && rule.FixedVersion == "":
				candidate.Basis = "declared_unresolved"
				candidate.Reason = "declared_status_requires_review"
			default:
				candidate.Basis = "comparison_unavailable"
				candidate.Reason = "declared_rule_uninterpretable"
			}
			if candidate.Basis == "comparison_unavailable" {
				result.incomplete(candidate.Reason)
			}
			result.Candidates = append(result.Candidates, candidate)
		}
	}
	return finish()
}

func (r *ReviewResult) addReason(reason string) {
	for _, existing := range r.ReasonCodes {
		if existing == reason {
			return
		}
	}
	r.ReasonCodes = append(r.ReasonCodes, reason)
}

func (r *ReviewResult) incomplete(reason string) {
	r.Status = "partial"
	r.addReason(reason)
}

// Byte trimming keeps the largest ordered whole-row prefix. Counters remain
// work actually performed, including inspected rows omitted by this final cap.
func (r *ReviewResult) boundBytes(ctx context.Context) error {
	fits := func() (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			return false, ErrReviewEncoding
		}
		return len(encoded) <= MaxReviewBytes, nil
	}
	if ok, err := fits(); err != nil || ok {
		return err
	}
	r.incomplete("review_byte_limit")
	rows := r.Candidates
	low, high := 0, len(rows)
	for low < high {
		middle := low + (high-low+1)/2
		r.Candidates = rows[:middle:middle]
		ok, err := fits()
		if err != nil {
			return err
		}
		if ok {
			low = middle
		} else {
			high = middle - 1
		}
	}
	r.Candidates = rows[:low:low]
	if ok, err := fits(); err != nil {
		return err
	} else if !ok {
		return ErrReviewEncoding
	}
	return nil
}

func copyReviewRelease(in linuxpackages.ReleaseFields) linuxpackages.ReleaseFields {
	copyString := func(value *string) *string {
		if value == nil {
			return nil
		}
		copied := *value
		return &copied
	}
	return linuxpackages.ReleaseFields{ID: copyString(in.ID), VersionID: copyString(in.VersionID), VersionCodename: copyString(in.VersionCodename)}
}
