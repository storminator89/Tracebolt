//go:build linux

package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/offlinecatalog"
)

// Invented documents declaring synthetic:false exercise unverified interchange
// handling only. These fixtures are never real advisory or installed inventory
// evidence. API requests use ordinary generated keys and owned loopback servers.
type conditionalBoundaryComparator func(context.Context, string, string) (int, error)

func (f conditionalBoundaryComparator) Compare(ctx context.Context, a, b string) (int, error) {
	return f(ctx, a, b)
}

func conditionalBoundaryRules(n int, status, fixed string) []assessment.DebianRule {
	rules := make([]assessment.DebianRule, n)
	for i := range rules {
		rules[i] = assessment.DebianRule{SourcePackage: "fixture-source", AdvisoryID: fmt.Sprintf("CVE-2099-%08d", n-i), Release: "trixie", Status: status, FixedVersion: fixed, Qualifications: []string{}, ArchiveVersions: []assessment.ArchiveVersion{}}
	}
	return rules
}

func conditionalBoundaryCatalog(t *testing.T, synthetic bool, rules []assessment.DebianRule) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		Schema         string                  `json:"schema"`
		Synthetic      bool                    `json:"synthetic"`
		CoveredSources []string                `json:"coveredSources"`
		Rules          []assessment.DebianRule `json:"rules"`
	}{assessment.DebianSnapshotSchema, synthetic, []string{"fixture-source"}, rules})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func conditionalBoundaryStore(t *testing.T, synthetic bool, rules []assessment.DebianRule) (*offlinecatalog.Store, offlinecatalog.View) {
	t.Helper()
	at := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	raw := conditionalBoundaryCatalog(t, synthetic, rules)
	candidate, err := offlinecatalog.Parse(context.Background(), raw, at)
	if err != nil {
		t.Fatal("invented catalog rejected", err)
	}
	clear(raw)
	s := offlinecatalog.New()
	view, err := s.Replace(context.Background(), s.View(at).Revision, candidate, at)
	if err != nil {
		t.Fatal(err)
	}
	return s, view
}

func conditionalBoundarySnapshot(t *testing.T, n int) linuxpackages.Snapshot {
	t.Helper()
	at := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	s := packageStoreSnapshot(operationalStoreSnapshot(at, ""), true)
	s.Inventory.Items = make([]linuxpackages.PackageRow, n)
	for i := range s.Inventory.Items {
		s.Inventory.Items[i] = linuxpackages.PackageRow{Name: fmt.Sprintf("fixture-binary-%03d", i), Version: "9:999.0-1+b7", Architecture: "amd64", SourcePackage: "fixture-source", SourceVersion: "1:2.0~rc1-1", SourceMapping: "source-field", InstallState: "installed"}
	}
	count := uint64(n)
	s.Inventory.ObservedCount, s.Inventory.InstalledCount = &count, &count
	if err := linuxpackages.Validate(s); err != nil {
		t.Fatal("invented observation rejected", err)
	}
	return s
}

func conditionalBoundaryRun(t *testing.T, s *offlinecatalog.Store, snapshot linuxpackages.Snapshot, comparator assessment.VersionComparator) offlinecatalog.ReviewResult {
	t.Helper()
	got, err := s.Review(context.Background(), s.View(snapshot.CollectedAt).Revision, snapshot, comparator)
	if err != nil {
		t.Fatal(err)
	}
	conditionalBoundaryNoAuthority(t, got)
	return got
}

func conditionalBoundaryNoAuthority(t *testing.T, result offlinecatalog.ReviewResult) {
	t.Helper()
	if result.AffectedCVEs != nil || result.OfferedUpdates != nil || result.InstalledArtifactOrigin != "unknown" || result.SnapshotFreshness != "unknown" {
		t.Fatal("conditional review gained authoritative counts or provenance")
	}
	if result.Catalog != nil && (result.Catalog.OriginAssurance != "unverified" || result.Catalog.Freshness != "unknown" || result.Catalog.PublishedAt != nil) {
		t.Fatal("catalog import gained origin/publication authority")
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > offlinecatalog.MaxReviewBytes || len(result.Candidates) > offlinecatalog.MaxReviewRows || result.PairsInspected > offlinecatalog.MaxReviewPairs || result.Comparisons > offlinecatalog.MaxReviewComparisons {
		t.Fatal("review exceeded declared work/output bounds")
	}
	for _, forbidden := range []string{`"verdict":`, `"offeredVersion":`, `"archiveVersions":`, `"trustedOrigin":`, `"activation":`, `"binaryVersion":`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("review exposed an authoritative or unrelated field", forbidden)
		}
	}
	if !bytes.Contains(raw, []byte(`"affectedCves":null`)) || !bytes.Contains(raw, []byte(`"offeredUpdates":null`)) || result.Candidates == nil || result.ReasonCodes == nil {
		t.Fatal("unknown counts or empty-array contract lost")
	}
}

func conditionalBoundaryReason(got offlinecatalog.ReviewResult, reason string) bool {
	for _, current := range got.ReasonCodes {
		if current == reason {
			return true
		}
	}
	return false
}

func TestIndependentConditionalReviewSourceOnlyAndImmutable(t *testing.T) {
	rules := conditionalBoundaryRules(2, "resolved", "1:2.0-1")
	rules[0].Qualifications = []string{"no-dsa", "postponed"}
	rules[0].ArchiveVersions = []assessment.ArchiveVersion{{Repository: "fixture-archive-not-offered", Version: "99:999-1"}}
	s, view := conditionalBoundaryStore(t, false, rules)
	snapshot := conditionalBoundarySnapshot(t, 1)
	calls := 0
	comparator := conditionalBoundaryComparator(func(ctx context.Context, installed, fixed string) (int, error) {
		calls++
		if installed != "1:2.0~rc1-1" || fixed != "1:2.0-1" {
			t.Fatal("binary version, archive version, or normalized value used for comparison")
		}
		return (debianversion.Comparator{}).Compare(ctx, installed, fixed)
	})
	got := conditionalBoundaryRun(t, s, snapshot, comparator)
	if calls != 2 || len(got.Candidates) != 2 || got.Status != "complete" || got.Revision != view.Revision || !reflect.DeepEqual(got.Catalog, view.Catalog) || got.Snapshot.GenerationID != snapshot.GenerationID || !got.Snapshot.CollectedAt.Equal(snapshot.CollectedAt) {
		t.Fatal("source comparison or lineage contract changed")
	}
	for i, row := range got.Candidates {
		if row.AdvisoryID != fmt.Sprintf("CVE-2099-%08d", i+1) || row.ReportedSourcePackage != "fixture-source" || row.ReportedSourceVersion != "1:2.0~rc1-1" || row.SourceMapping != "source-field" || row.Basis != "conditional_reported_source_below_declared_fix" {
			t.Fatal("candidate ordering, exact source facts or qualification changed")
		}
	}
	before, _ := json.Marshal(got)
	*got.Snapshot.Release.ID = "changed"
	got.Catalog.OriginAssurance = "changed"
	got.ReasonCodes[0] = "changed"
	got.Candidates[0].ReportedSourceVersion = "changed"
	got.Candidates[1].Qualifications[0] = "changed"
	again := conditionalBoundaryRun(t, s, snapshot, comparator)
	after, _ := json.Marshal(again)
	if !bytes.Equal(before, after) || *snapshot.Release.Fields.ID != "debian" {
		t.Fatal("returned result aliases caller snapshot or retained catalog state")
	}
	*snapshot.Release.Fields.ID = "ubuntu"
	if *again.Snapshot.Release.ID != "debian" {
		t.Fatal("returned release facts alias supplied pointers")
	}
	// A source name mismatch never falls back to binary-name or archive matching.
	snapshot = conditionalBoundarySnapshot(t, 1)
	snapshot.Inventory.Items[0].Name = "fixture-source"
	snapshot.Inventory.Items[0].SourcePackage = "other-source"
	got = conditionalBoundaryRun(t, s, snapshot, nil)
	if len(got.Candidates) != 0 || got.Status != "partial" || !conditionalBoundaryReason(got, "source_package_not_covered") {
		t.Fatal("binary package name gained source authority")
	}
}

func TestIndependentConditionalReviewUnsupportedAndOmittedRowsRemainUnknown(t *testing.T) {
	for _, tc := range []struct{ source, fixed string }{{"2147483648:1", "2"}, {"1:1:2", "2"}, {"1", "2147483648:1"}, {"1", "1:1:2"}} {
		t.Run(tc.source+"/"+tc.fixed, func(t *testing.T) {
			s, _ := conditionalBoundaryStore(t, false, conditionalBoundaryRules(1, "resolved", tc.fixed))
			snapshot := conditionalBoundarySnapshot(t, 1)
			snapshot.Inventory.Items[0].SourceVersion = tc.source
			got := conditionalBoundaryRun(t, s, snapshot, debianversion.Comparator{})
			if got.Status != "partial" || len(got.Candidates) != 1 || got.Candidates[0].ReportedSourceVersion != tc.source || got.Candidates[0].DeclaredFixedVersion != tc.fixed || got.Candidates[0].Basis != "comparison_unavailable" || got.Candidates[0].Reason != "comparison_failed" {
				t.Fatal("unsupported accepted metadata disappeared or became equal/fixed")
			}
		})
	}
	for _, fixed := range []string{"0", "1:2.0~rc1-1", "1:1.0-1"} {
		s, _ := conditionalBoundaryStore(t, false, conditionalBoundaryRules(1, "resolved", fixed))
		got := conditionalBoundaryRun(t, s, conditionalBoundarySnapshot(t, 1), debianversion.Comparator{})
		if len(got.Candidates) != 0 {
			t.Fatal("omitted sentinel/equal/above row became a candidate")
		}
	}
	for _, comparator := range []assessment.VersionComparator{nil, conditionalBoundaryComparator(func(context.Context, string, string) (int, error) { return 0, errors.New("private-comparison-detail") }), conditionalBoundaryComparator(func(context.Context, string, string) (int, error) { return 2, nil })} {
		s, _ := conditionalBoundaryStore(t, false, conditionalBoundaryRules(1, "resolved", "1:2.0-1"))
		got := conditionalBoundaryRun(t, s, conditionalBoundarySnapshot(t, 1), comparator)
		raw, _ := json.Marshal(got)
		if len(got.Candidates) != 1 || got.Status != "partial" || got.Candidates[0].Basis != "comparison_unavailable" || bytes.Contains(raw, []byte("private-comparison-detail")) {
			t.Fatal("comparison failure lost row or leaked raw diagnostic")
		}
	}
}

func TestIndependentConditionalReviewReleaseSyntheticAndPartialGates(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		edit         func(*linuxpackages.Snapshot)
	}{
		{"missing", "release_facts_missing", func(s *linuxpackages.Snapshot) { s.Release.Fields.ID = nil }},
		{"inconsistent", "release_facts_inconsistent", func(s *linuxpackages.Snapshot) { *s.Release.Fields.VersionID = "12" }},
		{"wrong vendor", "unsupported_release", func(s *linuxpackages.Snapshot) { *s.Release.Fields.ID = "derivative" }},
		{"Ubuntu", "unsupported_release", func(s *linuxpackages.Snapshot) {
			*s.Release.Fields.ID, *s.Release.Fields.VersionID, *s.Release.Fields.VersionCodename = "ubuntu", "24.04", "noble"
		}},
		{"unknown inventory", "inventory_unavailable", func(s *linuxpackages.Snapshot) {
			s.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing, Items: []linuxpackages.PackageRow{}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := conditionalBoundaryStore(t, false, conditionalBoundaryRules(1, "resolved", "1:2.0-1"))
			snapshot := conditionalBoundarySnapshot(t, 1)
			tc.edit(&snapshot)
			got := conditionalBoundaryRun(t, s, snapshot, conditionalBoundaryComparator(func(context.Context, string, string) (int, error) {
				t.Fatal("ineligible release/inventory reached comparator")
				return 0, nil
			}))
			if got.Status != "unavailable" || len(got.Candidates) != 0 || !conditionalBoundaryReason(got, tc.reason) {
				t.Fatal("ineligible source produced live review")
			}
		})
	}
	s, _ := conditionalBoundaryStore(t, true, conditionalBoundaryRules(1, "resolved", "1:2.0-1"))
	got := conditionalBoundaryRun(t, s, conditionalBoundarySnapshot(t, 1), conditionalBoundaryComparator(func(context.Context, string, string) (int, error) {
		t.Fatal("synthetic catalog reached comparator")
		return 0, nil
	}))
	if got.Status != "unavailable" || len(got.Candidates) != 0 || got.CatalogUsage != "synthetic-fixture-not-for-live-review" || !conditionalBoundaryReason(got, "synthetic_catalog") {
		t.Fatal("synthetic catalog entered live result")
	}
	s, _ = conditionalBoundaryStore(t, false, conditionalBoundaryRules(1, "open", ""))
	snapshot := conditionalBoundarySnapshot(t, 1)
	snapshot.Inventory.Complete, snapshot.Inventory.Truncated, snapshot.Inventory.Reason = false, true, linuxpackages.ReasonItemLimit
	count := uint64(2)
	snapshot.Inventory.ObservedCount, snapshot.Inventory.InstalledCount = &count, &count
	got = conditionalBoundaryRun(t, s, snapshot, nil)
	if got.Status != "partial" || len(got.Candidates) != 1 || !conditionalBoundaryReason(got, "inventory_partial") || got.Snapshot.InventoryComplete {
		t.Fatal("selected prefix became complete inventory")
	}
	snapshot = conditionalBoundarySnapshot(t, 1)
	snapshot.Inventory.Items[0].InstallState = "incomplete"
	zero := uint64(0)
	snapshot.Inventory.InstalledCount = &zero
	got = conditionalBoundaryRun(t, s, snapshot, nil)
	if len(got.Candidates) != 0 || !conditionalBoundaryReason(got, "package_installation_incomplete") {
		t.Fatal("incomplete package became installed candidate")
	}
}

func TestIndependentConditionalReviewHardWorkAndByteBounds(t *testing.T) {
	for _, tc := range []struct {
		name, status, fixed, reason               string
		packages, rules, rows, pairs, comparisons int
	}{
		{"rows", "open", "", "review_row_limit", 1, 129, 128, 128, 0},
		{"pairs", "resolved", "0", "review_pair_limit", 1, 4097, 0, 4096, 0},
		{"comparisons", "resolved", "1:2.0-1", "review_comparison_limit", 1, 1025, 0, 1025, 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := conditionalBoundaryStore(t, false, conditionalBoundaryRules(tc.rules, tc.status, tc.fixed))
			calls := 0
			got := conditionalBoundaryRun(t, s, conditionalBoundarySnapshot(t, tc.packages), conditionalBoundaryComparator(func(context.Context, string, string) (int, error) { calls++; return 0, nil }))
			if got.Status != "partial" || !conditionalBoundaryReason(got, tc.reason) || len(got.Candidates) != tc.rows || got.PairsInspected != tc.pairs || got.Comparisons != tc.comparisons || calls != tc.comparisons {
				t.Fatalf("hard %s bound changed: rows=%d pairs=%d comparisons=%d calls=%d", tc.name, len(got.Candidates), got.PairsInspected, got.Comparisons, calls)
			}
		})
	}
	rules := conditionalBoundaryRules(128, "open", "")
	for i := range rules {
		rules[i].Qualifications = make([]string, 16)
		for j := range rules[i].Qualifications {
			rules[i].Qualifications[j] = strings.Repeat("q", 128)
		}
	}
	s, _ := conditionalBoundaryStore(t, false, rules)
	got := conditionalBoundaryRun(t, s, conditionalBoundarySnapshot(t, 1), nil)
	if got.Status != "partial" || !conditionalBoundaryReason(got, "review_byte_limit") || len(got.Candidates) == 0 || len(got.Candidates) >= 128 || got.PairsInspected != 128 || got.Comparisons != 0 {
		t.Fatal("byte cap did not preserve bounded whole-row prefix and actual work counts")
	}
	for i, row := range got.Candidates {
		if row.AdvisoryID != fmt.Sprintf("CVE-2099-%08d", i+1) || len(row.Qualifications) != 16 {
			t.Fatal("byte trimming reordered or sliced a candidate")
		}
	}
	// The chosen prefix must be maximal under the declared serialized-byte cap.
	next := got.Candidates[0]
	next.AdvisoryID = fmt.Sprintf("CVE-2099-%08d", len(got.Candidates)+1)
	got.Candidates = append(got.Candidates, next)
	raw, _ := json.Marshal(got)
	if len(raw) <= offlinecatalog.MaxReviewBytes {
		t.Fatal("byte trimming discarded a candidate that still fit")
	}
}

func TestIndependentConditionalReviewContextAndCASDiscardAllOutput(t *testing.T) {
	snapshot := conditionalBoundarySnapshot(t, 1)
	for _, kind := range []string{"nil context", "pre-cancel", "expired", "mid-compare cancel", "stale revision", "clear during compare", "same catalog replacement"} {
		t.Run(kind, func(t *testing.T) {
			s, view := conditionalBoundaryStore(t, false, conditionalBoundaryRules(1, "resolved", "1:2.0-1"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var input context.Context = ctx
			revision, want := view.Revision, error(context.Canceled)
			comparator := conditionalBoundaryComparator(func(context.Context, string, string) (int, error) { return -1, nil })
			switch kind {
			case "nil context":
				input, want = nil, offlinecatalog.ErrReviewContextRequired
			case "pre-cancel":
				cancel()
			case "expired":
				var end context.CancelFunc
				input, end = context.WithDeadline(ctx, time.Unix(1, 0))
				defer end()
				want = context.DeadlineExceeded
			case "mid-compare cancel":
				comparator = func(context.Context, string, string) (int, error) { cancel(); return -1, nil }
			case "stale revision":
				revision, want = "revision_"+strings.Repeat("0", 32), offlinecatalog.ErrChanged
			case "clear during compare", "same catalog replacement":
				want = offlinecatalog.ErrChanged
				comparator = func(ctx context.Context, _, _ string) (int, error) {
					if kind == "clear during compare" {
						_, err := s.Clear(ctx, view.Revision, snapshot.CollectedAt)
						return -1, err
					}
					candidate, err := offlinecatalog.Parse(ctx, conditionalBoundaryCatalog(t, false, conditionalBoundaryRules(1, "resolved", "1:2.0-1")), snapshot.CollectedAt)
					if err != nil {
						return 0, err
					}
					_, err = s.Replace(ctx, view.Revision, candidate, snapshot.CollectedAt)
					return -1, err
				}
			}
			got, err := s.Review(input, revision, snapshot, comparator)
			if !errors.Is(err, want) || !reflect.DeepEqual(got, offlinecatalog.ReviewResult{}) {
				t.Fatal("failed/cancelled/replaced review leaked a partial result", err)
			}
		})
	}
	s, view := conditionalBoundaryStore(t, false, conditionalBoundaryRules(1, "open", ""))
	snapshot.GenerationID = "invalid"
	got, err := s.Review(context.Background(), view.Revision, snapshot, nil)
	if !errors.Is(err, linuxpackages.ErrInvalidSnapshot) || !reflect.DeepEqual(got, offlinecatalog.ReviewResult{}) {
		t.Fatal("invalid supplied observation escaped validation")
	}
}

type conditionalBoundaryHTTPView struct {
	SchemaVersion    string                       `json:"schemaVersion"`
	DeviceID         string                       `json:"deviceId"`
	ServerNow        time.Time                    `json:"serverNow"`
	MaxAgeSeconds    int64                        `json:"maxAgeSeconds"`
	CollectionStatus string                       `json:"collectionStatus"`
	ReceivedAt       *time.Time                   `json:"receivedAt"`
	Sequence         *uint64                      `json:"sequence"`
	Review           *offlinecatalog.ReviewResult `json:"review"`
}

func TestIndependentConditionalReviewHTTPFreshLineageAuthorityAndSessions(t *testing.T) {
	for _, httpTest := range []bool{false, true} {
		t.Run(fmt.Sprintf("http-test=%v", httpTest), func(t *testing.T) {
			h, cases := operationalAPIHTTPFixture(t, httpTest, enrollmentcrypto.CollectionProfilePackages)
			identity := operationalStoreActivate(t, h.f)
			session := h.session(t)
			read := func(r *http.Request) {
				h.browser(session)(r)
				r.Method = http.MethodGet
				r.Header.Del("Origin")
				r.Header.Del("X-CSRF-Token")
			}
			path := "/api/devices/" + identity.Approval.DeviceID + "/security/review"
			get := func() conditionalBoundaryHTTPView {
				t.Helper()
				code, raw, _ := h.request(t, path, nil, read)
				var got conditionalBoundaryHTTPView
				if code != 200 || json.Unmarshal(raw, &got) != nil || len(raw) > 65*1024 {
					t.Fatal("review HTTP result invalid", code)
				}
				if got.SchemaVersion != "tracebolt.advisory-review-view.v1" || got.DeviceID != identity.Approval.DeviceID || got.MaxAgeSeconds != 120 {
					t.Fatal("review envelope lineage lost")
				}
				return got
			}
			if got := get(); got.CollectionStatus != "awaiting" || got.Review != nil {
				t.Fatal("awaiting identity has review")
			}
			op := operationalStoreSnapshot(h.f.clock(), "services,software")
			packages := packageStoreSnapshot(op, true)
			packages.Inventory.Items[0].Version = "9:999-1+b9"
			receipt, err := h.f.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, packageStoreFrame(t, 1, op, packages, false), h.f.clock())
			if err != nil {
				t.Fatal(err)
			}
			if got := get(); got.Review == nil || len(got.Review.Candidates) != 0 || got.Review.Catalog != nil || !conditionalBoundaryReason(*got.Review, "catalog_unavailable") {
				t.Fatal("missing catalog silently gained coverage")
			}
			initial := reviewCatalogRead(t, h, session)
			if code, _ := reviewCatalogPost(t, h, session, initial.Revision, conditionalBoundaryCatalog(t, true, conditionalBoundaryRules(1, "resolved", "2.0-1"))); code != 200 {
				t.Fatal("synthetic fixture import rejected")
			}
			if got := get(); got.Review == nil || len(got.Review.Candidates) != 0 || !conditionalBoundaryReason(*got.Review, "synthetic_catalog") {
				t.Fatal("synthetic catalog produced live review")
			}
			current := reviewCatalogRead(t, h, session)
			if code, _ := reviewCatalogPost(t, h, session, current.Revision, conditionalBoundaryCatalog(t, false, conditionalBoundaryRules(1, "resolved", "2.0-1"))); code != 200 {
				t.Fatal("unverified invented catalog import rejected")
			}
			current = reviewCatalogRead(t, h, session)
			before := operationalStoreRows(t, h.f.path)
			beforeCases, err := cases.Cases()
			if err != nil {
				t.Fatal(err)
			}
			got := get()
			if got.CollectionStatus != "fresh" || got.Review == nil || len(got.Review.Candidates) != 1 || got.Sequence == nil || *got.Sequence != receipt.Sequence || got.ReceivedAt == nil || !got.ReceivedAt.Equal(receipt.ReceivedAt) || got.Review.Revision != current.Revision || got.Review.Snapshot.GenerationID != packages.GenerationID || !got.Review.Snapshot.CollectedAt.Equal(packages.CollectedAt) || got.Review.Candidates[0].ReportedSourceVersion != "1.0-1" || !got.ServerNow.Equal(h.f.clock()) {
				t.Fatal("fresh review lost source-only result or receipt/catalog lineage")
			}
			conditionalBoundaryNoAuthority(t, *got.Review)
			// Repeating a read neither rewrites durable observations nor creates cases.
			_ = get()
			afterCases, err := cases.Cases()
			if err != nil || !reflect.DeepEqual(beforeCases, afterCases) || !bytes.Equal(before, operationalStoreRows(t, h.f.path)) {
				t.Fatal("review mutated durable facts or cases")
			}
			code, raw, _ := h.request(t, strings.TrimSuffix(path, "/review"), nil, read)
			var coverage struct {
				Offered struct {
					Count *uint64 `json:"offeredCount"`
				} `json:"offeredUpdates"`
				Vulnerabilities struct {
					Affected   *uint64 `json:"affectedCves"`
					Candidates *uint64 `json:"reviewCandidates"`
					Coverage   string  `json:"coverage"`
				} `json:"vulnerabilities"`
			}
			if code != 200 || json.Unmarshal(raw, &coverage) != nil || coverage.Offered.Count != nil || coverage.Vulnerabilities.Affected != nil || coverage.Vulnerabilities.Candidates != nil || coverage.Vulnerabilities.Coverage != "unknown" {
				t.Fatal("conditional view upgraded authoritative coverage")
			}
			for name, change := range map[string]func(*http.Request){"no session": func(r *http.Request) { r.Method = "GET" }, "wrong host": func(r *http.Request) { read(r); r.Host = "other.example" }, "wrong origin": func(r *http.Request) { read(r); r.Header.Set("Origin", "https://other.example") }, "cross site": func(r *http.Request) { read(r); r.Header.Set("Sec-Fetch-Site", "cross-site") }} {
				want := 403
				if name == "no session" {
					want = 401
				}
				if code, body, _ := h.request(t, path, nil, change); code != want || bytes.Contains(body, []byte("fixture-binary")) {
					t.Fatal("review session/origin boundary", name, code)
				}
			}
			for _, suffix := range []string{"?", "?source=other", "?catalog=trusted"} {
				if code, _, _ := h.request(t, path+suffix, nil, read); code != 400 {
					t.Fatal("query supplied interpretation", code)
				}
			}
			if code, _, _ := h.request(t, path, []byte(`{}`), read); code != 400 {
				t.Fatal("GET body accepted", code)
			}
			if code, _, _ := h.request(t, "/api/devices/agent_"+strings.Repeat("0", 32)+"/security/review", nil, read); code != 404 {
				t.Fatal("unknown device acquired review", code)
			}
			for _, method := range []string{"HEAD", "PUT", "DELETE"} {
				if code, _, _ := h.request(t, path, nil, func(r *http.Request) { read(r); r.Method = method }); code != 405 {
					t.Fatal("review mutation method admitted", method, code)
				}
			}
			// Store freshness is inclusive at exactly 120s; no old selected-source
			// rows may be returned once its current read becomes stale.
			h.f.now.Add(int64(lanstore.SampleMaxAge / time.Second))
			if got := get(); got.CollectionStatus != "fresh" || got.Review == nil {
				t.Fatal("exact freshness boundary became stale")
			}
			h.f.now.Add(1)
			if got := get(); got.CollectionStatus != "stale" || got.Review != nil {
				t.Fatal("stale source retained live review")
			}
			next := operationalStoreSnapshot(h.f.clock(), "software")
			nextPackages := packageStoreSnapshot(next, true)
			nextPackages.Inventory.Items[0].SourceVersion = "3.0-1"
			nextReceipt, err := h.f.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, packageStoreFrame(t, 2, next, nextPackages, false), h.f.clock())
			if err != nil {
				t.Fatal(err)
			}
			if got := get(); got.Review == nil || len(got.Review.Candidates) != 0 || *got.Sequence != nextReceipt.Sequence || !got.ReceivedAt.Equal(nextReceipt.ReceivedAt) || got.Review.Snapshot.GenerationID != next.GenerationID {
				t.Fatal("latest observation merged with old candidates")
			}
			if _, err := h.f.store.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identity.InvitationID, RequestID: h.f.nextRequest(), ExpectedRevision: identity.Revision, Now: h.f.clock().Unix()}, State: enrollmentstate.Revoked}); err != nil {
				t.Fatal(err)
			}
			if got := get(); got.CollectionStatus != "revoked" || got.Review != nil {
				t.Fatal("revoked identity retained live review")
			}
			// Existing package-mode AI gate must win even when case storage is closed.
			if err := cases.Close(); err != nil {
				t.Fatal(err)
			}
			if code, raw, _ := h.request(t, "/api/cases/conditional-fixture/analyze", []byte(`{"configRevision":"ignored"}`), h.browser(session)); code != 403 || !bytes.Contains(raw, []byte("evidence_export_not_approved")) {
				t.Fatal("review entered case/provider export", code)
			}
			h.auth.Logout(session.Token)
			if code, raw, _ := h.request(t, path, nil, read); code != 401 || bytes.Contains(raw, []byte("fixture-source")) {
				t.Fatal("logged-out session retained review", code)
			}
		})
	}
}

func TestIndependentConditionalReviewHTTPOlderProfilesDisabled(t *testing.T) {
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational} {
		t.Run(profile, func(t *testing.T) {
			h, _ := operationalAPIHTTPFixture(t, true, profile)
			identity := operationalStoreActivate(t, h.f)
			session := h.session(t)
			code, raw, _ := h.request(t, "/api/devices/"+identity.Approval.DeviceID+"/security/review", nil, func(r *http.Request) { h.browser(session)(r); r.Method = http.MethodGet })
			var got conditionalBoundaryHTTPView
			if code != 200 || json.Unmarshal(raw, &got) != nil || got.CollectionStatus != "not_configured" || got.Review != nil {
				t.Fatal("older profile gained conditional source review", code)
			}
		})
	}
}

func TestIndependentConditionalReviewHTTPStorageFailureIsGeneric(t *testing.T) {
	h, _ := operationalAPIHTTPFixture(t, true, enrollmentcrypto.CollectionProfilePackages)
	identity := operationalStoreActivate(t, h.f)
	session := h.session(t)
	if err := h.f.store.Close(); err != nil {
		t.Fatal(err)
	}
	code, raw, _ := h.request(t, "/api/devices/"+identity.Approval.DeviceID+"/security/review", nil, func(r *http.Request) { h.browser(session)(r); r.Method = http.MethodGet })
	if code != 500 || bytes.Contains(raw, []byte(h.f.path)) || bytes.Contains(raw, []byte(enrollmentstore.ErrStorage.Error())) || bytes.Contains(raw, []byte("fixture-source")) {
		t.Fatal("storage failure leaked state or appeared successful", code)
	}
}
