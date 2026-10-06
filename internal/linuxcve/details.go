package linuxcve

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"time"
)

const (
	FindingsPageSchemaVersion = "tracebolt.linux-cve-findings-page.v1"
	BinariesPageSchemaVersion = "tracebolt.linux-cve-binaries-page.v1"
	// Page boundaries depend only on serialized rows. Reserve the entire fixed
	// envelope (including the longest UTC clock representation), never its current
	// encoding length. The outer HTTP response has the same 230 KiB bound.
	DetailEnvelopeReserve = 4096
	detailDataBudget      = MaxResultBytes - DetailEnvelopeReserve
)

var (
	ErrDetailQuery       = errors.New("linux_cve_detail_query_invalid")
	ErrDetailBinding     = errors.New("linux_cve_detail_binding_changed")
	ErrDetailIncomplete  = errors.New("linux_cve_detail_assessment_incomplete")
	ErrDetailUnavailable = errors.New("linux_cve_detail_unavailable")
)

type FindingsQuery struct {
	AssessmentID       string `json:"assessmentId"`
	AssessmentRevision uint64 `json:"assessmentRevision"`
	FromCheck          uint64 `json:"fromCheck"`
	Limit              int    `json:"limit"`
}
type BinariesQuery struct {
	AssessmentID       string `json:"assessmentId"`
	AssessmentRevision uint64 `json:"assessmentRevision"`
	CheckIndex         uint64 `json:"checkIndex"`
	FromBinary         uint64 `json:"fromBinary"`
	Limit              int    `json:"limit"`
}
type DetailBinding struct {
	SchemaVersion      string    `json:"schemaVersion"`
	DeviceID           string    `json:"deviceId"`
	ServerNow          time.Time `json:"serverNow"`
	AssessmentID       string    `json:"assessmentId"`
	AssessmentRevision uint64    `json:"assessmentRevision"`
}
type FindingItem struct {
	CheckIndex  uint64  `json:"checkIndex"`
	Finding     Finding `json:"finding"`
	BinaryCount int     `json:"binaryCount"`
}
type FindingsPage struct {
	DetailBinding
	FromCheck         uint64        `json:"fromCheck"`
	NextCheck         uint64        `json:"nextCheck"`
	ScannedCheckCount uint64        `json:"scannedCheckCount"`
	Exhausted         bool          `json:"exhausted"`
	StopReason        string        `json:"stopReason"`
	ComparisonCount   int           `json:"comparisonCount"`
	Items             []FindingItem `json:"items"`
}
type BinariesPage struct {
	DetailBinding
	CheckIndex             uint64   `json:"checkIndex"`
	CVEID                  string   `json:"cveId"`
	SourcePackage          string   `json:"sourcePackage"`
	InstalledSourceVersion string   `json:"installedSourceVersion"`
	PublishedFixedVersion  string   `json:"publishedFixedVersion"`
	BinaryCount            int      `json:"binaryCount"`
	FromBinary             uint64   `json:"fromBinary"`
	NextBinary             uint64   `json:"nextBinary"`
	Exhausted              bool     `json:"exhausted"`
	Items                  []Binary `json:"items"`
}

// detailPlan validates the same evidence/plan/checkpoint as continuation. A
// caller's offset is only a location in that plan, never completion evidence.
// This function has no store and cannot save, project/trim or advance progress.
func detailPlan(ctx context.Context, snapshot *Snapshot, manifest fullinventory.Manifest, rows []linuxpackages.PackageRow, now time.Time, identity AssessmentIdentity, prior []byte, id string, revision uint64) (workPlan, uint64, error) {
	if ctx.Err() != nil {
		return workPlan{}, 0, ErrCanceled
	}
	if !validTime(now) || InventoryFreshness(manifest.CollectedAt, now) != "fresh" || !validInventory(ctx, manifest, rows) {
		if ctx.Err() != nil {
			return workPlan{}, 0, ErrCanceled
		}
		return workPlan{}, 0, ErrDetailUnavailable
	}
	if snapshot == nil || !snapshot.valid || snapshot.metadata.Target != manifest.Release.Fields.Target() || snapshot.Metadata(now).Freshness == "unknown" || snapshot.metadata.ValidatedAt.After(now) {
		return workPlan{}, 0, ErrDetailUnavailable
	}
	actual, err := AssessmentID(snapshot, manifest, identity)
	if err != nil {
		return workPlan{}, 0, ErrDetailUnavailable
	}
	if id != actual {
		return workPlan{}, 0, ErrDetailBinding
	}
	result := Result{}
	plan, ok := planInventory(ctx, snapshot, rows, &result)
	if !ok {
		return workPlan{}, 0, ErrCanceled
	}
	if len(prior) == 0 {
		return workPlan{}, 0, ErrCheckpoint
	}
	p, err := decodeCheckpoint(prior, id, plan, result.Coverage.TotalCheckCount, now)
	if err != nil || p.AssessedAt.Before(manifest.CollectedAt) || p.AssessedAt.Before(snapshot.metadata.FetchedAt) {
		return workPlan{}, 0, ErrCheckpoint
	}
	if p.Revision != revision {
		return workPlan{}, 0, ErrDetailBinding
	}
	if p.Completed != result.Coverage.TotalCheckCount {
		return workPlan{}, 0, ErrDetailIncomplete
	}
	return plan, result.Coverage.TotalCheckCount, nil
}

// seek uses source-group arithmetic. No comparison (or prefix check visit) is
// performed for the caller's skipped prefix. The ordinal is bounded by total.
func (plan workPlan) seek(index uint64) (checkpoint, bool) {
	p := checkpoint{}
	for i, s := range plan.sources {
		count := uint64(len(s.rules)) * uint64(len(s.versions))
		if index < count {
			p.Source = i
			p.Record = int(index / uint64(len(s.versions)))
			p.InstalledVersion = int(index % uint64(len(s.versions)))
			return p, true
		}
		index -= count
	}
	p.Source = len(plan.sources)
	return p, index == 0
}

func detailCompare(ctx context.Context, comparator assessment.VersionComparator, count *int) func(string, string) (int, error) {
	memo := map[string]int{}
	return func(a, b string) (int, error) {
		if ctx.Err() != nil {
			return 0, ErrCanceled
		}
		key := a + "\x00" + b
		if v, ok := memo[key]; ok {
			return v, nil
		}
		if *count >= MaxComparisons {
			return 0, ErrLimit
		}
		if comparator == nil {
			return 0, ErrDetailUnavailable
		}
		*count++
		v, e := comparator.Compare(ctx, a, b)
		if ctx.Err() != nil {
			return 0, ErrCanceled
		}
		if errors.Is(e, debianversion.ErrVersionInvalid) || errors.Is(e, debianversion.ErrVersionUnsupported) || errors.Is(e, debianversion.ErrEpochUnsupported) {
			return 0, assessment.ErrComparatorUnavailable
		}
		if e != nil || v < -1 || v > 1 {
			return 0, ErrDetailUnavailable
		}
		memo[key] = v
		return v, nil
	}
}

// QueryFindings replays bounded checks against immutable evidence. Production
// uses the same pure Debian comparator as EvaluateStep. Stateful/inconsistent
// test comparators are not replay-equivalent. Timeouts fail the whole read;
// successful boundaries depend only on input, check/comparison/row/byte limits.
func QueryFindings(ctx context.Context, snapshot *Snapshot, manifest fullinventory.Manifest, rows []linuxpackages.PackageRow, comparator assessment.VersionComparator, now time.Time, identity AssessmentIdentity, prior []byte, query FindingsQuery) (FindingsPage, error) {
	if ctx == nil {
		return FindingsPage{}, ErrCanceled
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if query.Limit < 1 || query.Limit > MaxFindings || query.AssessmentRevision == 0 {
		return FindingsPage{}, ErrDetailQuery
	}
	plan, total, err := detailPlan(ctx, snapshot, manifest, rows, now, identity, prior, query.AssessmentID, query.AssessmentRevision)
	if err != nil {
		return FindingsPage{}, err
	}
	if query.FromCheck > total {
		return FindingsPage{}, ErrDetailQuery
	}
	p, _ := plan.seek(query.FromCheck)
	out := FindingsPage{DetailBinding: DetailBinding{FindingsPageSchemaVersion, identity.DeviceID, now.UTC(), query.AssessmentID, query.AssessmentRevision}, FromCheck: query.FromCheck, NextCheck: query.FromCheck, Items: []FindingItem{}}
	compare := detailCompare(ctx, comparator, &out.ComparisonCount)
	dataBytes := 2 // array delimiters
	for out.NextCheck < total {
		if ctx.Err() != nil {
			return FindingsPage{}, ErrCanceled
		}
		if len(out.Items) == query.Limit {
			out.StopReason = "finding_limit_exceeded"
			break
		}
		if out.ScannedCheckCount == MaxVisitedChecks {
			out.StopReason = "visited_check_limit_exceeded"
			break
		}
		s := plan.sources[p.Source]
		r := s.rules[p.Record]
		g := s.versions[p.InstalledVersion]
		if r.reason == "" {
			fixed, matched, e := matchRule(r, g.version, compare)
			if errors.Is(e, ErrLimit) {
				out.StopReason = "comparison_limit_exceeded"
				break
			}
			// An invalid interval is the same deterministic vendor/comparison gap
			// that continuation counted as unassessed; it is not a matching row.
			if errors.Is(e, assessment.ErrVersionInvalid) || errors.Is(e, assessment.ErrComparatorUnavailable) {
				e = nil
				matched = false
			}
			if e != nil {
				return FindingsPage{}, e
			}
			if matched {
				item := FindingItem{CheckIndex: out.NextCheck, BinaryCount: len(g.binaries), Finding: Finding{CVEID: r.cve, SourcePackage: g.source, InstalledSourceVersion: g.version, PublishedFixedVersion: fixed, Basis: "distribution_package_version_match", AdvisoryURL: r.advisoryURL, Binaries: []Binary{g.binaries[0]}, BinariesTruncated: len(g.binaries) > 1}}
				raw, e := json.Marshal(item)
				if e != nil || len(raw)+2 > detailDataBudget {
					return FindingsPage{}, ErrDetailUnavailable
				}
				need := len(raw)
				if len(out.Items) > 0 {
					need++
				}
				if dataBytes+need > detailDataBudget {
					out.StopReason = "response_byte_limit_exceeded"
					break
				}
				dataBytes += need
				out.Items = append(out.Items, item)
			}
		}
		p.advance(plan)
		out.NextCheck++
		out.ScannedCheckCount++
	}
	if ctx.Err() != nil {
		return FindingsPage{}, ErrCanceled
	}
	out.Exhausted = out.NextCheck == total
	if out.Exhausted {
		out.StopReason = "exhausted"
	}
	if !out.Exhausted && out.NextCheck == out.FromCheck {
		return FindingsPage{}, ErrDetailUnavailable
	}
	return out, nil
}

// QueryBinaries resolves and verifies one matching check server-side, then
// pages only its exact eligible source/version binaries in inventory order.
func QueryBinaries(ctx context.Context, snapshot *Snapshot, manifest fullinventory.Manifest, rows []linuxpackages.PackageRow, comparator assessment.VersionComparator, now time.Time, identity AssessmentIdentity, prior []byte, query BinariesQuery) (BinariesPage, error) {
	if ctx == nil {
		return BinariesPage{}, ErrCanceled
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if query.Limit < 1 || query.Limit > MaxBinariesPerFinding || query.AssessmentRevision == 0 {
		return BinariesPage{}, ErrDetailQuery
	}
	plan, total, err := detailPlan(ctx, snapshot, manifest, rows, now, identity, prior, query.AssessmentID, query.AssessmentRevision)
	if err != nil {
		return BinariesPage{}, err
	}
	if query.CheckIndex >= total {
		return BinariesPage{}, ErrDetailQuery
	}
	p, _ := plan.seek(query.CheckIndex)
	s := plan.sources[p.Source]
	r := s.rules[p.Record]
	g := s.versions[p.InstalledVersion]
	if r.reason != "" || query.FromBinary > uint64(len(g.binaries)) {
		return BinariesPage{}, ErrDetailQuery
	}
	comparisons := 0
	fixed, matched, err := matchRule(r, g.version, detailCompare(ctx, comparator, &comparisons))
	if errors.Is(err, assessment.ErrVersionInvalid) || errors.Is(err, assessment.ErrComparatorUnavailable) {
		return BinariesPage{}, ErrDetailQuery
	}
	if err != nil {
		return BinariesPage{}, err
	}
	if !matched {
		return BinariesPage{}, ErrDetailQuery
	}
	end := min(query.FromBinary+uint64(query.Limit), uint64(len(g.binaries)))
	out := BinariesPage{DetailBinding: DetailBinding{BinariesPageSchemaVersion, identity.DeviceID, now.UTC(), query.AssessmentID, query.AssessmentRevision}, CheckIndex: query.CheckIndex, CVEID: r.cve, SourcePackage: g.source, InstalledSourceVersion: g.version, PublishedFixedVersion: fixed, BinaryCount: len(g.binaries), FromBinary: query.FromBinary, NextBinary: end, Exhausted: end == uint64(len(g.binaries)), Items: append([]Binary{}, g.binaries[query.FromBinary:end]...)}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > MaxResultBytes-DetailEnvelopeReserve {
		return BinariesPage{}, ErrDetailUnavailable
	}
	if ctx.Err() != nil {
		return BinariesPage{}, ErrCanceled
	}
	return out, nil
}
