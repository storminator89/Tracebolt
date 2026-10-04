package offlinecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/linuxpackages"
)

// All fixture content is invented. Some documents deliberately declare
// synthetic:false to exercise the unverified, non-synthetic input branch;
// this is not a vendor source, installed inventory or real CVE evidence.
type reviewComparator func(context.Context, string, string) (int, error)

func (f reviewComparator) Compare(ctx context.Context, a, b string) (int, error) {
	return f(ctx, a, b)
}

func reviewPtr[T any](value T) *T { return &value }

func reviewSnapshot() linuxpackages.Snapshot {
	return linuxpackages.Snapshot{
		SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope,
		GenerationID: "sample_0123456789abcdef0123456789abcdef", CollectedAt: testTime(),
		Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
			Fields: linuxpackages.ReleaseFields{ID: reviewPtr("debian"), VersionID: reviewPtr("13"), VersionCodename: reviewPtr("trixie")}},
		Inventory: linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
			Complete: true, CountExact: true, ObservedCount: reviewPtr(uint64(1)), InstalledCount: reviewPtr(uint64(1)),
			Items: []linuxpackages.PackageRow{{Name: "fixture-binary", Version: "9:999.0-1+b2", Architecture: "amd64",
				SourcePackage: "fixture-source", SourceVersion: "1:2.0~rc1-1", SourceMapping: "source-field", InstallState: "installed"}}},
	}
}

func reviewRule(index int, status, fixed string) normalizedRule {
	return normalizedRule{SourcePackage: "fixture-source", AdvisoryID: strictString(fmt.Sprintf("CVE-2099-%08d", index)),
		Release: "trixie", Status: strictString(status), FixedVersion: strictString(fixed),
		Qualifications: strictStrings{}, ArchiveVersions: strictArchives{}}
}

func reviewCatalog(t *testing.T, synthetic bool, rules ...normalizedRule) Candidate {
	t.Helper()
	if rules == nil {
		rules = []normalizedRule{}
	}
	raw, err := json.Marshal(normalizedDocument{Schema: assessment.DebianSnapshotSchema, Synthetic: synthetic,
		CoveredSources: strictStrings{"fixture-source"}, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := Parse(context.Background(), raw, testTime())
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func reviewStore(t *testing.T, synthetic bool, rules ...normalizedRule) (*Store, View) {
	t.Helper()
	store := New()
	view, err := store.Replace(context.Background(), store.View(testTime()).Revision, reviewCatalog(t, synthetic, rules...), testTime())
	if err != nil {
		t.Fatal(err)
	}
	return store, view
}

func mustReview(t *testing.T, store *Store, snapshot linuxpackages.Snapshot, comparator assessment.VersionComparator) ReviewResult {
	t.Helper()
	result, err := store.Review(context.Background(), store.View(testTime()).Revision, snapshot, comparator)
	if err != nil {
		t.Fatal(err)
	}
	if result.AffectedCVEs != nil || result.OfferedUpdates != nil {
		t.Fatal("review manufactured authoritative counts")
	}
	if result.InstalledArtifactOrigin != "unknown" || result.SnapshotFreshness != "unknown" {
		t.Fatal("review manufactured observation authority")
	}
	if result.Catalog != nil && (result.Catalog.OriginAssurance != "unverified" || result.Catalog.Freshness != "unknown" || result.Catalog.PublishedAt != nil) {
		t.Fatal("review manufactured catalog authority")
	}
	if result.Candidates == nil || result.ReasonCodes == nil {
		t.Fatal("review arrays must not be null")
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxReviewBytes {
		t.Fatalf("review byte bound failed: %d %v", len(encoded), err)
	}
	return result
}

func hasReviewReason(result ReviewResult, want string) bool {
	for _, reason := range result.ReasonCodes {
		if reason == want {
			return true
		}
	}
	return false
}

func TestReviewContractSourceNotBinaryAndEpochTildeInjection(t *testing.T) {
	store, view := reviewStore(t, false, reviewRule(1, "resolved", "1:2.0-1"))
	snapshot := reviewSnapshot()
	calls := 0
	comparator := reviewComparator(func(ctx context.Context, a, b string) (int, error) {
		calls++
		if a != snapshot.Inventory.Items[0].SourceVersion || b != "1:2.0-1" || a == snapshot.Inventory.Items[0].Version {
			t.Fatal("compared anything except exact reported source and declared fix")
		}
		return (debianversion.Comparator{}).Compare(ctx, a, b)
	})
	result := mustReview(t, store, snapshot, comparator)
	if calls != 1 || result.Comparisons != 1 || result.PairsInspected != 1 || len(result.Candidates) != 1 || result.Status != "complete" {
		t.Fatalf("unexpected work/result: %#v", result)
	}
	row := result.Candidates[0]
	if row.Basis != "conditional_reported_source_below_declared_fix" || row.ReportedSourceVersion != "1:2.0~rc1-1" || row.ReportedSourcePackage != "fixture-source" || row.SourceMapping != "source-field" {
		t.Fatalf("wrong candidate: %#v", row)
	}
	if result.Revision != view.Revision || !reflect.DeepEqual(result.Catalog, view.Catalog) || result.Snapshot.GenerationID != snapshot.GenerationID || !result.Snapshot.CollectedAt.Equal(snapshot.CollectedAt) {
		t.Fatal("lost input identities")
	}
	if result.SchemaVersion != ReviewSchemaVersion || result.CatalogUsage != "unverified-conditional-review" || result.Limits != (ReviewLimits{128, 4096, 1024, 65536}) {
		t.Fatal("wrong contract")
	}
	encoded, _ := json.Marshal(result)
	var root map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &root)
	requireKeys(t, root, "schemaVersion", "scope", "status", "reasonCodes", "revision", "catalog", "catalogUsage", "snapshot", "installedArtifactOrigin", "snapshotFreshness", "candidates", "affectedCves", "offeredUpdates", "pairsInspected", "comparisons", "limits")
	if string(root["affectedCves"]) != "null" || string(root["offeredUpdates"]) != "null" {
		t.Fatal("authoritative counts omitted or not null")
	}
	for _, forbidden := range []string{`"verdict"`, `"affected"`, `"fixed"`, `"not_affected"`, `"offeredVersion"`, `"archiveVersions"`, `"binaryVersion"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("unrequested authoritative/extraneous output %s", forbidden)
		}
	}
	// Epoch ordering outranks upstream digits; no semver/lexical shortcut.
	snapshot.Inventory.Items[0].SourceVersion = "2:0.1-1"
	result = mustReview(t, store, snapshot, debianversion.Comparator{})
	if len(result.Candidates) != 0 || result.Comparisons != 1 {
		t.Fatal("epoch did not reach injected comparator")
	}
	// No normalization or stripping a binNMU-looking source suffix.
	snapshot.Inventory.Items[0].SourceVersion = "1:2.0-1+b3"
	result = mustReview(t, store, snapshot, reviewComparator(func(_ context.Context, a, b string) (int, error) {
		if a != "1:2.0-1+b3" {
			t.Fatal("modified reported source version")
		}
		return -1, nil
	}))
	if len(result.Candidates) != 1 {
		t.Fatal("caller comparator was not authoritative for ordering")
	}
}

func TestReviewUnavailableAndPartialFacts(t *testing.T) {
	store, _ := reviewStore(t, false, reviewRule(1, "open", ""))
	cases := []struct {
		name, status, reason string
		edit                 func(*linuxpackages.Snapshot)
	}{
		{"missing release", "unavailable", "release_facts_missing", func(s *linuxpackages.Snapshot) { s.Release.Fields.ID = nil }},
		{"empty release", "unavailable", "release_facts_missing", func(s *linuxpackages.Snapshot) { s.Release.Fields.VersionID = reviewPtr("") }},
		{"release unknown", "unavailable", "release_unavailable", func(s *linuxpackages.Snapshot) {
			s.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}
		}},
		{"release inconsistent", "unavailable", "release_facts_inconsistent", func(s *linuxpackages.Snapshot) { s.Release.Fields.VersionID = reviewPtr("12") }},
		{"unsupported Debian", "unavailable", "unsupported_release", func(s *linuxpackages.Snapshot) {
			s.Release.Fields.VersionID, s.Release.Fields.VersionCodename = reviewPtr("12"), reviewPtr("bookworm")
		}},
		{"Ubuntu", "unavailable", "unsupported_release", func(s *linuxpackages.Snapshot) {
			s.Release.Fields = linuxpackages.ReleaseFields{ID: reviewPtr("ubuntu"), VersionID: reviewPtr("24.04"), VersionCodename: reviewPtr("noble")}
		}},
		{"derivative", "unavailable", "unsupported_release", func(s *linuxpackages.Snapshot) { s.Release.Fields.ID = reviewPtr("other") }},
		{"unknown inventory", "unavailable", "inventory_unavailable", func(s *linuxpackages.Snapshot) {
			s.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonReadFailed, Items: []linuxpackages.PackageRow{}}
		}},
		{"denied inventory", "unavailable", "inventory_unavailable", func(s *linuxpackages.Snapshot) {
			s.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Denied, Reason: linuxpackages.ReasonPermissionDenied, Items: []linuxpackages.PackageRow{}}
		}},
		{"incomplete install", "partial", "package_installation_incomplete", func(s *linuxpackages.Snapshot) {
			s.Inventory.Items[0].InstallState = "incomplete"
			s.Inventory.InstalledCount = reviewPtr(uint64(0))
		}},
		{"uncovered source", "partial", "source_package_not_covered", func(s *linuxpackages.Snapshot) { s.Inventory.Items[0].SourcePackage = "other-source" }},
		{"empty selected partial", "partial", "inventory_partial", func(s *linuxpackages.Snapshot) {
			s.Inventory.Complete, s.Inventory.Truncated, s.Inventory.Reason = false, true, linuxpackages.ReasonByteLimit
			s.Inventory.Items = []linuxpackages.PackageRow{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := reviewSnapshot()
			tc.edit(&snapshot)
			result := mustReview(t, store, snapshot, reviewComparator(func(context.Context, string, string) (int, error) {
				t.Fatal("unavailable facts compared")
				return 0, nil
			}))
			if result.Status != tc.status || !hasReviewReason(result, tc.reason) || len(result.Candidates) != 0 {
				t.Fatalf("wrong failure fact: %#v", result)
			}
		})
	}
	// No catalog is an explicit unavailable state, not zero CVEs or a read error.
	result := mustReview(t, New(), reviewSnapshot(), nil)
	if result.Catalog != nil || result.Status != "unavailable" || !hasReviewReason(result, "catalog_unavailable") {
		t.Fatal("empty catalog did not remain unavailable")
	}
}

func TestReviewSyntheticCatalogCannotCrossIntoLiveRows(t *testing.T) {
	store, _ := reviewStore(t, true, reviewRule(1, "resolved", "1:2.0-1"))
	result := mustReview(t, store, reviewSnapshot(), reviewComparator(func(context.Context, string, string) (int, error) {
		t.Fatal("synthetic catalog compared with managed observations")
		return -1, nil
	}))
	if result.Status != "unavailable" || !hasReviewReason(result, "synthetic_catalog") || result.CatalogUsage != "synthetic-fixture-not-for-live-review" || !result.Catalog.Synthetic || len(result.Candidates) != 0 || result.Comparisons != 0 || result.PairsInspected != 0 {
		t.Fatal("synthetic catalog gained live review authority")
	}
}

func TestReviewRuleCasesAndUnknownComparator(t *testing.T) {
	for _, tc := range []struct {
		name, status, fixed, basis, reason string
		order                              int
		err                                error
		comparator                         bool
		rows                               int
	}{
		{"below", "resolved", "2.0", "conditional_reported_source_below_declared_fix", "reported_source_below_declared_fix", -1, nil, true, 1},
		{"equal omitted", "resolved", "2.0", "", "", 0, nil, true, 0},
		{"above omitted", "resolved", "2.0", "", "", 1, nil, true, 0},
		{"sentinel omitted", "resolved", "0", "", "", 0, nil, false, 0},
		{"nil comparator", "resolved", "2.0", "comparison_unavailable", "comparator_unavailable", 0, nil, false, 1},
		{"comparator failed", "resolved", "2.0", "comparison_unavailable", "comparison_failed", 0, errors.New("private diagnostic must not be retained"), true, 1},
		{"unsupported version", "resolved", "2.0", "comparison_unavailable", "comparison_failed", 0, debianversion.ErrVersionUnsupported, true, 1},
		{"invalid order", "resolved", "2.0", "comparison_unavailable", "comparison_failed", 2, nil, true, 1},
		{"negative invalid order", "resolved", "2.0", "comparison_unavailable", "comparison_failed", -2, nil, true, 1},
		{"unresolved", "open", "", "declared_unresolved", "declared_status_requires_review", 0, nil, false, 1},
		{"undetermined", "undetermined", "", "declared_unresolved", "declared_status_requires_review", 0, nil, false, 1},
		{"unknown declaration", "unfamiliar", "", "comparison_unavailable", "declared_rule_uninterpretable", 0, nil, false, 1},
		{"missing fix", "resolved", "", "comparison_unavailable", "declared_rule_uninterpretable", 0, nil, false, 1},
		{"contradictory open fix", "open", "2.0", "comparison_unavailable", "declared_rule_uninterpretable", 0, nil, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := reviewStore(t, false, reviewRule(1, tc.status, tc.fixed))
			var comparator assessment.VersionComparator
			if tc.comparator {
				comparator = reviewComparator(func(context.Context, string, string) (int, error) { return tc.order, tc.err })
			}
			result := mustReview(t, store, reviewSnapshot(), comparator)
			if len(result.Candidates) != tc.rows {
				t.Fatalf("got %d rows, want %d", len(result.Candidates), tc.rows)
			}
			if tc.rows != 0 && (result.Candidates[0].Basis != tc.basis || result.Candidates[0].Reason != tc.reason) {
				t.Fatalf("wrong conditional row: %#v", result.Candidates[0])
			}
			if tc.basis == "comparison_unavailable" && (result.Status != "partial" || !hasReviewReason(result, tc.reason)) {
				t.Fatal("unavailable comparison reported complete")
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "private diagnostic") {
				t.Fatal("comparator error leaked")
			}
		})
	}
}

func TestReviewErrorsDiscardAllResultAndCASChanges(t *testing.T) {
	store, view := reviewStore(t, false, reviewRule(1, "resolved", "2.0"))
	check := func(result ReviewResult, err, want error) {
		t.Helper()
		if !errors.Is(err, want) || !reflect.DeepEqual(result, ReviewResult{}) {
			t.Fatalf("wanted zero/error %v, got %#v %v", want, result, err)
		}
	}
	for _, revision := range []string{"", "revision_wrong"} {
		result, err := store.Review(context.Background(), revision, reviewSnapshot(), nil)
		check(result, err, ErrChanged)
	}
	result, err := store.Review(nil, view.Revision, reviewSnapshot(), nil)
	check(result, err, ErrReviewContextRequired)
	for _, unavailable := range []*Store{nil, {}} {
		result, err := unavailable.Review(context.Background(), view.Revision, reviewSnapshot(), nil)
		check(result, err, ErrUnavailable)
	}
	invalid := reviewSnapshot()
	invalid.Inventory.Items[0].SourceVersion = "not a version"
	result, err = store.Review(context.Background(), view.Revision, invalid, nil)
	check(result, err, linuxpackages.ErrInvalidSnapshot)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = store.Review(ctx, view.Revision, reviewSnapshot(), nil)
	check(result, err, context.Canceled)
	ctx, cancel = context.WithDeadline(context.Background(), testTime().Add(-time.Hour))
	defer cancel()
	result, err = store.Review(ctx, view.Revision, reviewSnapshot(), nil)
	check(result, err, context.DeadlineExceeded)
	for _, clear := range []bool{false, true} {
		t.Run(fmt.Sprintf("clear=%v", clear), func(t *testing.T) {
			store, view := reviewStore(t, false, reviewRule(1, "resolved", "2.0"), reviewRule(2, "resolved", "2.0"))
			calls := 0
			result, err := store.Review(context.Background(), view.Revision, reviewSnapshot(), reviewComparator(func(ctx context.Context, _, _ string) (int, error) {
				calls++
				if calls == 2 {
					if clear {
						_, err = store.Clear(ctx, view.Revision, testTime())
					} else {
						_, err = store.Replace(ctx, view.Revision, reviewCatalog(t, false, reviewRule(3, "open", "")), testTime())
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				return -1, nil
			}))
			check(result, err, ErrChanged)
			if store.View(testTime()).Revision == view.Revision {
				t.Fatal("mutation did not proceed outside review lock")
			}
		})
	}
}

func TestReviewCancellationDuringWorkDiscardsRows(t *testing.T) {
	store, view := reviewStore(t, false, reviewRule(1, "resolved", "2.0"), reviewRule(2, "resolved", "2.0"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	result, err := store.Review(ctx, view.Revision, reviewSnapshot(), reviewComparator(func(ctx context.Context, _, _ string) (int, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return -1, nil
	}))
	if calls != 2 || !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, ReviewResult{}) {
		t.Fatal("cancellation retained partial rows")
	}
	// Polls also cover indexing, package/rule loops, byte bounds and final check.
	for _, checks := range []int{2, 3, 5, 7, 9, 10} {
		ctx, cancel := context.WithCancel(context.Background())
		observed := &cancelAfterChecks{Context: ctx, cancel: cancel, remaining: checks}
		result, err := store.Review(observed, view.Revision, reviewSnapshot(), nil)
		cancel()
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, ReviewResult{}) {
			t.Fatalf("cancellation at poll %d escaped", checks)
		}
	}
}

func TestReviewDeterministicBounds(t *testing.T) {
	for _, tc := range []struct {
		name, status, fix, reason   string
		n, pairs, comparisons, rows int
	}{
		{"rows", "open", "", "review_row_limit", MaxReviewRows + 1, MaxReviewRows, 0, MaxReviewRows},
		{"pairs", "resolved", "0", "review_pair_limit", MaxReviewPairs + 1, MaxReviewPairs, 0, 0},
		{"comparisons", "resolved", "2.0", "review_comparison_limit", MaxReviewComparisons + 1, MaxReviewComparisons + 1, MaxReviewComparisons, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := make([]normalizedRule, tc.n)
			for i := range rules {
				rules[i] = reviewRule(tc.n-i, tc.status, tc.fix)
			}
			store, _ := reviewStore(t, false, rules...)
			calls := 0
			result := mustReview(t, store, reviewSnapshot(), reviewComparator(func(context.Context, string, string) (int, error) { calls++; return 1, nil }))
			if result.Status != "partial" || !hasReviewReason(result, tc.reason) || result.PairsInspected != tc.pairs || result.Comparisons != tc.comparisons || calls != tc.comparisons || len(result.Candidates) != tc.rows {
				t.Fatalf("wrong limits result: status %s reason %v pairs %d calls %d rows %d", result.Status, result.ReasonCodes, result.PairsInspected, calls, len(result.Candidates))
			}
			for i, row := range result.Candidates {
				if row.AdvisoryID != string(reviewRule(i+1, tc.status, tc.fix).AdvisoryID) {
					t.Fatal("row prefix was not sorted")
				}
			}
		})
	}
	// Exact row limit with no remaining pair is still a complete inspection.
	rules := make([]normalizedRule, MaxReviewRows)
	for i := range rules {
		rules[i] = reviewRule(i+1, "open", "")
	}
	store, _ := reviewStore(t, false, rules...)
	result := mustReview(t, store, reviewSnapshot(), nil)
	if result.Status != "complete" || len(result.Candidates) != MaxReviewRows {
		t.Fatal("exact bound was spuriously partial")
	}
}

func TestReviewByteBoundKeepsMaximalOrderedWholeRowPrefix(t *testing.T) {
	rules := make([]normalizedRule, 100)
	for i := range rules {
		rules[i] = reviewRule(100-i, "resolved", "1"+strings.Repeat("x", 511))
		for q := 0; q < 16; q++ {
			rules[i].Qualifications = append(rules[i].Qualifications, strictString(strings.Repeat("q", 128)))
		}
	}
	store, _ := reviewStore(t, false, rules...)
	result := mustReview(t, store, reviewSnapshot(), nil)
	if result.Status != "partial" || !hasReviewReason(result, "review_byte_limit") || len(result.Candidates) == 0 || len(result.Candidates) >= len(rules) || result.PairsInspected != len(rules) || result.Comparisons != 0 {
		t.Fatal("byte-bound completeness or counters wrong")
	}
	if cap(result.Candidates) != len(result.Candidates) {
		t.Fatal("trimmed rows recoverable by reslicing")
	}
	for i, row := range result.Candidates {
		if row.AdvisoryID != string(reviewRule(i+1, "", "").AdvisoryID) {
			t.Fatal("byte trimming was not deterministic prefix")
		}
	}
	next := result.Candidates[len(result.Candidates)-1]
	next.AdvisoryID = string(reviewRule(len(result.Candidates)+1, "", "").AdvisoryID)
	result.Candidates = append(result.Candidates, next)
	encoded, _ := json.Marshal(result)
	if len(encoded) <= MaxReviewBytes {
		t.Fatal("byte trimming discarded an extra fitting row")
	}
}

func TestReviewOrderingAliasingAndIndependentOutput(t *testing.T) {
	ruleA, ruleB := reviewRule(2, "open", ""), reviewRule(1, "open", "")
	ruleA.Qualifications, ruleB.Qualifications = strictStrings{"fixture-label"}, strictStrings{"fixture-label"}
	store, _ := reviewStore(t, false, ruleA, ruleB)
	snapshot := reviewSnapshot()
	snapshot.Inventory.Items = append(snapshot.Inventory.Items, snapshot.Inventory.Items[0])
	snapshot.Inventory.Items[1].Architecture = "arm64"
	snapshot.Inventory.ObservedCount, snapshot.Inventory.InstalledCount = reviewPtr(uint64(2)), reviewPtr(uint64(2))
	baseline := mustReview(t, store, snapshot, nil)
	if len(baseline.Candidates) != 4 {
		t.Fatal("binary/arch identities collapsed")
	}
	for i, row := range baseline.Candidates {
		arch := "amd64"
		if i >= 2 {
			arch = "arm64"
		}
		if row.Architecture != arch || row.AdvisoryID != string(reviewRule(i%2+1, "", "").AdvisoryID) {
			t.Fatal("package/architecture/advisory ordering unstable")
		}
	}
	changed := mustReview(t, store, snapshot, nil)
	changed.Candidates[0].Qualifications[0] = "mutated"
	changed.Candidates[0].ReportedSourceVersion = "mutated"
	changed.Catalog.ID, changed.Catalog.OriginAssurance, changed.Catalog.Freshness = "mutated", "verified", "fresh"
	changed.ReasonCodes[0] = "mutated"
	*changed.Snapshot.Release.ID = "mutated"
	if *snapshot.Release.Fields.ID != "debian" {
		t.Fatal("output aliases release input")
	}
	if !reflect.DeepEqual(baseline, mustReview(t, store, snapshot, nil)) {
		t.Fatal("output mutation altered retained catalog or later results")
	}
	if baseline.Candidates[1].Qualifications[0] != "fixture-label" {
		t.Fatal("row qualifications alias")
	}
	// A comparator callback cannot alter later rows via original input aliases.
	store, _ = reviewStore(t, false, reviewRule(1, "resolved", "2.0"))
	result := mustReview(t, store, snapshot, reviewComparator(func(context.Context, string, string) (int, error) {
		snapshot.Inventory.Items[1].SourceVersion = "88.0"
		*snapshot.Release.Fields.ID = "other"
		return -1, nil
	}))
	if len(result.Candidates) != 2 || result.Candidates[1].ReportedSourceVersion != "1:2.0~rc1-1" || *result.Snapshot.Release.ID != "debian" {
		t.Fatal("comparator observed caller-owned mutation")
	}
}
