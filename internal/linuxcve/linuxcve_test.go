package linuxcve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 5, 7, 0, 0, 0, time.UTC)

func bundle(t *testing.T, provider, payload string, at time.Time) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		SchemaVersion string          `json:"schemaVersion"`
		Provider      string          `json:"provider"`
		FetchedAt     time.Time       `json:"fetchedAt"`
		Payload       json.RawMessage `json:"payload"`
	}{BundleSchemaVersion, provider, at, json.RawMessage(payload)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func debianPayload(fixed, status string) string {
	return fmt.Sprintf(`{"openssl":{"CVE-2026-1000":{"releases":{"trixie":{"status":%q,"fixed_version":%q},"bookworm":{"status":"resolved","fixed_version":"9.0-1"}}}}}`, status, fixed)
}
func parse(t *testing.T, provider, payload string) *Snapshot {
	t.Helper()
	s, e := Parse(context.Background(), bytes.NewReader(bundle(t, provider, payload, testNow)), testNow)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func row(name, source, version string) linuxpackages.PackageRow {
	return linuxpackages.PackageRow{Name: name, Version: version, Architecture: "amd64", SourcePackage: source, SourceVersion: version, SourceMapping: "source-field", InstallState: "installed"}
}
func inventory(t *testing.T, target linuxpackages.ReleaseTarget, rows []linuxpackages.PackageRow, at time.Time) (fullinventory.Manifest, []linuxpackages.PackageRow) {
	t.Helper()
	id, version, codename := "debian", "13", "trixie"
	if target == linuxpackages.Ubuntu2404 {
		id, version, codename = "ubuntu", "24.04", "noble"
	}
	if target == linuxpackages.Unsupported {
		id, version, codename = "debian", "12", "bookworm"
	}
	m, cs, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: "sample_0123456789abcdef0123456789abcdef", CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: &id, VersionID: &version, VersionCodename: &codename}}, Rows: rows}, nil)
	if e != nil {
		t.Fatal(e)
	}
	ordered := []linuxpackages.PackageRow{}
	for _, c := range cs {
		ordered = append(ordered, c.Items...)
	}
	return m, ordered
}
func evaluate(t *testing.T, s *Snapshot, target linuxpackages.ReleaseTarget, rows ...linuxpackages.PackageRow) Result {
	t.Helper()
	m, rows := inventory(t, target, rows, testNow)
	return Evaluate(context.Background(), s, m, rows, debianversion.Comparator{}, testNow)
}
func hasReason(r Result, code string) bool {
	for _, v := range r.ReasonCodes {
		if v == code {
			return true
		}
	}
	return false
}

func TestDebianPublishedFixUsesMappedSourceAndDeduplicates(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("1:3.0.1-1+deb13u2", "resolved"))
	a := row("libssl3", "openssl", "1:3.0.1-1+deb13u1")
	a.Version = "9:99.0-1" // binary version is deliberately newer
	b := row("openssl", "openssl", a.SourceVersion)
	r := evaluate(t, s, linuxpackages.Debian13, b, a)
	if len(r.Findings) != 1 || len(r.Findings[0].Binaries) != 2 || r.Findings[0].InstalledSourceVersion != a.SourceVersion || r.Findings[0].PublishedFixedVersion != "1:3.0.1-1+deb13u2" || r.Findings[0].Basis != "distribution_package_version_match" {
		t.Fatalf("%+v", r)
	}
	if r.Status != "partial" || r.Feed.Trust != "operator_imported_unverified" || r.Feed.Coverage != "imported_records_only" || !hasReason(r, "installed_origin_unverified") {
		t.Fatalf("%+v", r)
	}
}
func TestNativeDebianOrdering(t *testing.T) {
	if _, err := os.Stat("/usr/bin/dpkg"); err != nil {
		t.Skip("native dpkg unavailable")
	}
	for _, tc := range []struct {
		name, installed, fixed string
		want                   int
	}{
		{"epoch", "1:9.9-1", "2:1.0-1", 1}, {"tilde", "1.0~rc1-1", "1.0-1", 1}, {"revision", "2.0-1+deb13u1", "2.0-1+deb13u2", 1}, {"equal", "2.0-1+deb13u2", "2.0-1+deb13u2", 0}, {"newer", "2.0-1+deb13u3", "2.0-1+deb13u2", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := parse(t, DebianProvider, debianPayload(tc.fixed, "resolved"))
			m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", tc.installed)}, testNow)
			r := Evaluate(context.Background(), s, m, rows, assessment.NativeDebianComparator{}, testNow)
			if len(r.Findings) != tc.want {
				t.Fatalf("%+v", r)
			}
		})
	}
}
func TestDebianNeverConfirmsUnfixedOrNotAffected(t *testing.T) {
	for _, tc := range []struct{ status, fixed, reason string }{{"resolved", "0", ""}, {"open", "", "published_fix_unavailable"}, {"undetermined", "", "vendor_status_undetermined"}, {"resolved", "", "vendor_record_uninterpretable"}, {"open", "2.0-1", "vendor_record_uninterpretable"}} {
		t.Run(tc.status+tc.fixed, func(t *testing.T) {
			r := evaluate(t, parse(t, DebianProvider, debianPayload(tc.fixed, tc.status)), linuxpackages.Debian13, row("openssl", "openssl", "1.0-1"))
			if len(r.Findings) != 0 || tc.reason != "" && !hasReason(r, tc.reason) {
				t.Fatalf("%+v", r)
			}
		})
	}
}
func osvPayload(ecosystem, events string) string {
	return fmt.Sprintf(`[{"schema_version":"1.7.0","id":"UBUNTU-CVE-2026-1000","aliases":[],"upstream":["CVE-2026-1000"],"modified":"2026-10-04T12:00:00Z","affected":[{"package":{"ecosystem":%q,"name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":%s}]}]}]`, ecosystem, events)
}
func TestUbuntuExactEcosystemSourceAndExplicitFix(t *testing.T) {
	s := parse(t, UbuntuProvider, osvPayload("Ubuntu:24.04:LTS", `[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.5"}]`))
	for _, tc := range []struct {
		version string
		want    int
	}{{"3.0.13-0ubuntu3.4", 1}, {"3.0.13-0ubuntu3.5", 0}, {"3.0.13-0ubuntu3.6", 0}} {
		r := evaluate(t, s, linuxpackages.Ubuntu2404, row("libssl3t64", "openssl", tc.version))
		if len(r.Findings) != tc.want {
			t.Fatalf("%+v", r)
		}
	}
	nofix := parse(t, UbuntuProvider, osvPayload("Ubuntu:24.04:LTS", `[{"introduced":"0"}]`))
	r := evaluate(t, nofix, linuxpackages.Ubuntu2404, row("libssl3t64", "openssl", "1.0-1"))
	if len(r.Findings) != 0 || !hasReason(r, "published_fix_unavailable") {
		t.Fatalf("needs-triage became confirmed: %+v", r)
	}
	for _, ecosystem := range []string{"Ubuntu:22.04:LTS", "Ubuntu:Pro:24.04:LTS", "Ubuntu:Pro:FIPS:24.04:LTS", "Ubuntu:24.04"} {
		if _, err := Parse(context.Background(), bytes.NewReader(bundle(t, UbuntuProvider, osvPayload(ecosystem, `[{"introduced":"0"},{"fixed":"2.0-1"}]`), testNow)), testNow); err == nil {
			t.Fatal("other ecosystem accepted", ecosystem)
		}
	}
}
func TestUbuntuIntroducedBoundsAndSafeLinks(t *testing.T) {
	s := parse(t, UbuntuProvider, osvPayload("Ubuntu:24.04:LTS", `[{"introduced":"2.0-1"},{"fixed":"3.0-1"}]`))
	for _, tc := range []struct {
		version string
		want    int
	}{{"1.0-1", 0}, {"2.0-1", 1}, {"2.5-1", 1}, {"3.0-1", 0}} {
		r := evaluate(t, s, linuxpackages.Ubuntu2404, row("openssl", "openssl", tc.version))
		if len(r.Findings) != tc.want {
			t.Fatalf("%+v", r)
		}
		if tc.want > 0 && r.Findings[0].AdvisoryURL != "https://ubuntu.com/security/CVE-2026-1000" {
			t.Fatal(r)
		}
	}
}
func TestExcludedVersionsAndIncompleteRows(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("9.0-1", "resolved"))
	for _, version := range []string{"1.0-1~bpo13+1", "1.0-1+bpo13u1", "1.0-1+local1", "1.0-1~ppa1", "1.0-1+custom1", "1.0-1~rebuild1"} {
		r := evaluate(t, s, linuxpackages.Debian13, row("openssl", "openssl", version))
		if len(r.Findings) != 0 || !hasReason(r, "nonstandard_package_version") || r.SkippedPackageCount != 1 {
			t.Fatalf("%+v", r)
		}
	}
	p := row("openssl", "openssl", "1.0-1")
	p.InstallState = "incomplete"
	r := evaluate(t, s, linuxpackages.Debian13, p)
	if len(r.Findings) != 0 || !hasReason(r, "package_installation_incomplete") {
		t.Fatalf("%+v", r)
	}
}
func TestInventoryMustBeCompleteBoundGeneration(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("2.0-1", "resolved"))
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", "1.0-1")}, testNow)
	for _, bad := range [][]linuxpackages.PackageRow{nil, {}, {row("openssl", "openssl", "1.1-1")}} {
		r := Evaluate(context.Background(), s, m, bad, debianversion.Comparator{}, testNow)
		if r.Status != "unavailable" || len(r.Findings) != 0 {
			t.Fatalf("%+v", r)
		}
	}
	r := Evaluate(context.Background(), s, m, rows, nil, testNow)
	if !hasReason(r, "debian_comparator_unavailable") || len(r.Findings) != 0 {
		t.Fatal(r)
	}
	r = evaluate(t, s, linuxpackages.Unsupported, rows...)
	if r.Status != "unavailable" || !hasReason(r, "release_unsupported") {
		t.Fatal(r)
	}
	r = evaluate(t, nil, linuxpackages.Debian13, rows...)
	if r.Status != "unavailable" || !hasReason(r, "feed_missing") {
		t.Fatal(r)
	}
}
func TestFreshnessIndependentAndHistoricalFindingsRetained(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("2.0-1", "resolved"))
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", "1.0-1")}, testNow)
	for _, age := range []time.Duration{InventoryTTL, FeedTTL, FeedTTL + time.Hour} {
		r := Evaluate(context.Background(), s, m, rows, debianversion.Comparator{}, testNow.Add(age))
		if r.Status != "stale" || len(r.Findings) != 1 || r.InventoryFreshness != "stale" {
			t.Fatal(r)
		}
		if age >= FeedTTL && r.Freshness != "stale" {
			t.Fatal(r)
		}
	}
	m.CollectedAt = testNow.Add(time.Second)
	r := Evaluate(context.Background(), s, m, rows, debianversion.Comparator{}, testNow)
	if r.Status != "unavailable" || len(r.Findings) != 0 {
		t.Fatal(r)
	}
}
func TestRejectMalformedEmptyDuplicateAndInvalidTimes(t *testing.T) {
	good := bundle(t, DebianProvider, debianPayload("2.0-1", "resolved"), testNow)
	for _, raw := range [][]byte{nil, []byte(`{}`), good[:len(good)-1], append(append([]byte{}, good...), []byte(`{}`)...), bytes.Replace(good, []byte(`"provider":`), []byte(`"provider":"debian-security-tracker","provider":`), 1), bundle(t, DebianProvider, `{}`, testNow), bundle(t, DebianProvider, `null`, testNow), bundle(t, UbuntuProvider, `[]`, testNow), bundle(t, DebianProvider, debianPayload("bad version", "resolved"), testNow), bundle(t, DebianProvider, debianPayload("2.0-1", "resolved"), testNow.Add(time.Second)), bytes.Replace(good, []byte(`"fetchedAt":"2026-10-05T07:00:00Z"`), []byte(`"fetchedAt":null`), 1), bundle(t, DebianProvider, `{"openssl":{"CVE-2026-1000":{"releases":{"trixie":{"status":"resolved","status":"open","fixed_version":"2.0-1"}}}}}`, testNow)} {
		if _, e := Parse(context.Background(), bytes.NewReader(raw), testNow); e == nil {
			t.Fatal("invalid bundle accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Parse(ctx, bytes.NewReader(good), testNow); !errors.Is(e, ErrCanceled) {
		t.Fatal(e)
	}
	large := `{"schemaVersion":"` + strings.Repeat("x", (1<<20)+1) + `"}`
	if _, e := Parse(context.Background(), strings.NewReader(large), testNow); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}
func TestStoreLastGoodPerProviderAntiRollbackAndAtomicPersistence(t *testing.T) {
	var store Store
	if store.View(testNow).Outcome != "never_attempted" {
		t.Fatal(store.View(testNow))
	}
	raw := bundle(t, DebianProvider, debianPayload("2.0-1", "resolved"), testNow)
	if _, e := store.Import(context.Background(), bytes.NewReader(raw), testNow); e != nil {
		t.Fatal(e)
	}
	prior := store.Snapshot(linuxpackages.Debian13)
	if _, e := store.Import(context.Background(), strings.NewReader(`{`), testNow.Add(time.Second)); e == nil {
		t.Fatal("bad import accepted")
	}
	if store.Snapshot(linuxpackages.Debian13) != prior || store.View(testNow).Outcome != "failed" {
		t.Fatal("last-good lost")
	}
	ubuntu := parse(t, UbuntuProvider, osvPayload("Ubuntu:24.04:LTS", `[{"introduced":"0"},{"fixed":"2.0-1"}]`))
	if e := store.Replace(ubuntu, testNow); e != nil {
		t.Fatal(e)
	}
	if len(store.View(testNow).Snapshots) != 2 {
		t.Fatal("provider import erased other provider")
	}
	older, e := Parse(context.Background(), bytes.NewReader(bundle(t, DebianProvider, debianPayload("2.0-1", "resolved"), testNow.Add(-time.Hour))), testNow)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Replace(older, testNow); !errors.Is(e, ErrRollback) {
		t.Fatal(e)
	}
	conflict := parse(t, DebianProvider, debianPayload("3.0-1", "resolved"))
	if e = store.Replace(conflict, testNow); !errors.Is(e, ErrRollback) {
		t.Fatal(e)
	}
	newer, e := Parse(context.Background(), bytes.NewReader(bundle(t, DebianProvider, debianPayload("3.0-1", "resolved"), testNow.Add(time.Hour))), testNow.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if e = store.ReplaceWith(newer, testNow.Add(time.Hour), func() error { return errors.New("disk failed") }); e == nil {
		t.Fatal("failed persistence accepted")
	}
	if store.Snapshot(linuxpackages.Debian13) != prior {
		t.Fatal("failed persistence changed snapshot")
	}
	v := store.View(testNow)
	v.Snapshots[0].Provider = "evil"
	*v.LastAttemptAt = time.Time{}
	if store.View(testNow).Snapshots[0].Provider != DebianProvider || store.View(testNow).LastAttemptAt.IsZero() {
		t.Fatal("view mutable")
	}
	store.RecordFailure(testNow, "secret raw error text")
	if store.View(testNow).FailureReason != "import_failed" {
		t.Fatal("unsanitized failure")
	}
}
func TestOfficialTrustCannotBeClaimedByImport(t *testing.T) {
	payload := debianPayload("2.0-1", "resolved")
	s, e := ParseOfficialDebian(context.Background(), strings.NewReader(payload), testNow, testNow)
	if e != nil {
		t.Fatal(e)
	}
	m := s.Metadata(testNow)
	if m.Trust != "https_origin_only" || m.Coverage != "official_feed_records" {
		t.Fatal(m)
	}
	raw := bundle(t, DebianProvider, payload, testNow)
	raw = bytes.Replace(raw, []byte(`"provider":`), []byte(`"trust":"https_origin_only","provider":`), 1)
	if _, e = Parse(context.Background(), bytes.NewReader(raw), testNow); e == nil {
		t.Fatal("bundle claimed official origin")
	}
	r := evaluate(t, s, linuxpackages.Debian13, row("openssl", "openssl", "1.0-1"))
	if hasReason(r, "feed_origin_unverified") || !hasReason(r, "installed_origin_unverified") {
		t.Fatal(r)
	}
}
func TestStoreConcurrentImmutableReads(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("2.0-1", "resolved"))
	var store Store
	if e := store.Replace(s, testNow); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				_ = store.Snapshot(linuxpackages.Debian13).Metadata(testNow)
				_ = store.View(testNow)
				_ = store.Replace(s, testNow)
			}
		}()
	}
	wg.Wait()
}
func TestCapsAndStableDedup(t *testing.T) {
	records := map[string]any{}
	for i := 0; i < MaxFindings+10; i++ {
		records[fmt.Sprintf("CVE-2026-%04d", 1000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": "2.0-1"}}}
	}
	raw, _ := json.Marshal(map[string]any{"openssl": records})
	s := parse(t, DebianProvider, string(raw))
	rows := []linuxpackages.PackageRow{}
	for i := 0; i < 50; i++ {
		rows = append(rows, row(fmt.Sprintf("libssl-test-%03d", i), "openssl", "1.0-1"))
	}
	r := evaluate(t, s, linuxpackages.Debian13, rows...)
	if len(r.Findings) != MaxFindings || !r.Truncated || !hasReason(r, "finding_limit_exceeded") {
		t.Fatal(r)
	}
	total := 0
	for _, f := range r.Findings {
		if len(f.Binaries) == 0 || len(f.Binaries) > MaxBinariesPerFinding {
			t.Fatal(f)
		}
		total += len(f.Binaries)
	}
	if total > MaxBinaryRows || !hasReason(r, "binary_limit_exceeded") {
		t.Fatal(total, r.ReasonCodes)
	}
	encoded, _ := json.Marshal(r)
	if len(encoded) > 230<<10 {
		t.Fatalf("response oversized: %d", len(encoded))
	}
	other := row("openssl-old", "openssl", "0.9-1")
	r = evaluate(t, parse(t, DebianProvider, debianPayload("2.0-1", "resolved")), linuxpackages.Debian13, rows[0], other)
	if len(r.Findings) != 2 || r.Coverage.MatchedFindingCount != 2 || r.Coverage.MatchedWarningCount != 1 || !r.Coverage.EvaluationComplete {
		t.Fatal("distinct installed source versions or unique warning totals collapsed", r)
	}
}
func TestComparisonBudgetAndCancellation(t *testing.T) {
	records := map[string]any{}
	for i := 0; i < MaxComparisons+1; i++ {
		records[fmt.Sprintf("CVE-2026-%04d", 1000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": fmt.Sprintf("1.0-%d", i+1)}}}
	}
	raw, _ := json.Marshal(map[string]any{"openssl": records})
	s := parse(t, DebianProvider, string(raw))
	r := evaluate(t, s, linuxpackages.Debian13, row("openssl", "openssl", "999.0-1"))
	if !r.Truncated || !hasReason(r, "comparison_limit_exceeded") || len(r.Findings) != 0 {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", "1.0-1")}, testNow)
	r = Evaluate(ctx, s, m, rows, debianversion.Comparator{}, testNow)
	if r.Status != "unavailable" || !hasReason(r, "evaluation_canceled_or_timed_out") {
		t.Fatal(r)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestReadFailureNeverParsesPrefix(t *testing.T) {
	input := io.MultiReader(bytes.NewReader(bundle(t, DebianProvider, debianPayload("2.0-1", "resolved"), testNow)), failingReader{})
	if _, e := Parse(context.Background(), input, testNow); e == nil {
		t.Fatal("read failure accepted")
	}
}

func TestByteLimitAndMaximumOutputIdentities(t *testing.T) {
	if _, err := readBounded(context.Background(), strings.NewReader(strings.Repeat("x", 17)), 16); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if b, err := readBounded(context.Background(), strings.NewReader(strings.Repeat("x", 16)), 16); err != nil || len(b) != 16 {
		t.Fatal(err)
	}
	source := "source" + strings.Repeat("a", 250)
	installed, fixed := "1."+strings.Repeat("a", 510), "2."+strings.Repeat("a", 510)
	records := map[string]any{}
	for i := 0; i < MaxFindings; i++ {
		records[fmt.Sprintf("CVE-2026-%04d", 1000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": fixed}}}
	}
	raw, _ := json.Marshal(map[string]any{source: records})
	s := parse(t, DebianProvider, string(raw))
	rows := []linuxpackages.PackageRow{}
	for i := 0; i < MaxBinaryRows; i++ {
		rows = append(rows, row(fmt.Sprintf("binary%03d", i)+strings.Repeat("x", 247), source, installed))
	}
	r := evaluate(t, s, linuxpackages.Debian13, rows...)
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > MaxResultBytes {
		t.Fatalf("maximum-length response oversized: %d %v", len(encoded), err)
	}
	if !r.Truncated || !hasReason(r, "response_byte_limit_exceeded") {
		t.Fatalf("missing explicit byte truncation: %d %+v", len(encoded), r.ReasonCodes)
	}
	if !r.Coverage.EvaluationComplete || r.Coverage.MatchedWarningCount != MaxFindings || r.Coverage.MatchedFindingCount != MaxFindings || r.Coverage.CompletedCheckCount != MaxFindings || len(r.Findings) >= MaxFindings {
		t.Fatalf("byte trimming changed complete assessment totals: %+v", r.Coverage)
	}
}

func TestUbuntuMalformedRangesAndWithdrawnAreNotConfirmed(t *testing.T) {
	for _, events := range []string{`[{"fixed":"2.0-1"}]`, `[{"introduced":"0","fixed":"2.0-1"}]`, `[{"introduced":"0"},{"introduced":"1.0-1"}]`, `[{"introduced":"0"},{"fixed":"0"}]`, `[{"introduced":"0"},{"fixed":"bad version"}]`} {
		if _, err := Parse(context.Background(), bytes.NewReader(bundle(t, UbuntuProvider, osvPayload("Ubuntu:24.04:LTS", events), testNow)), testNow); err == nil {
			t.Fatal("malformed range accepted", events)
		}
	}
	payload := osvPayload("Ubuntu:24.04:LTS", `[{"introduced":"0"},{"last_affected":"2.0-1"}]`)
	r := evaluate(t, parse(t, UbuntuProvider, payload), linuxpackages.Ubuntu2404, row("openssl", "openssl", "1.0-1"))
	if len(r.Findings) != 0 || !hasReason(r, "published_fix_unavailable") {
		t.Fatal(r)
	}
	payload = osvPayload("Ubuntu:24.04:LTS", `[{"introduced":"0"},{"fixed":"2.0-1"}]`)
	payload = strings.Replace(payload, `"aliases":[]`, `"aliases":[],"withdrawn":"2026-10-04T13:00:00Z"`, 1)
	if _, err := Parse(context.Background(), bytes.NewReader(bundle(t, UbuntuProvider, payload, testNow)), testNow); err == nil {
		t.Fatal("withdrawn-only bundle accepted")
	}
}
