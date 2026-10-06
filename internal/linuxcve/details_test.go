package linuxcve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/debianversion"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"reflect"
	"strings"
	"testing"
	"time"
)

func completedDetails(t *testing.T, s *Snapshot, m fullinventory.Manifest, rows []linuxpackages.PackageRow) (Result, []byte) {
	t.Helper()
	var raw []byte
	for i := 0; i < 100; i++ {
		r, next, e := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw)
		if e != nil || len(next) == 0 {
			t.Fatal("assessment", e, r.Continuation)
		}
		raw = next
		if r.Coverage.EvaluationComplete {
			return r, raw
		}
	}
	t.Fatal("assessment failed to finish")
	return Result{}, nil
}
func findingQuery(r Result, from uint64, limit int) FindingsQuery {
	return FindingsQuery{r.Continuation.AssessmentID, r.Continuation.Revision, from, limit}
}
func binaryQuery(r Result, check, from uint64) BinariesQuery {
	return BinariesQuery{r.Continuation.AssessmentID, r.Continuation.Revision, check, from, 20}
}

func TestDetailPagesFullSetStableBackwardAndMixedVersions(t *testing.T) {
	s, m, rows := continuationFixture(t, 145, 3, 5)
	summary, raw := completedDetails(t, s, m, rows)
	original := append([]byte{}, raw...)
	expected := map[string]bool{}
	for c := 5; c < 150; c++ {
		for v := 1; v <= 3; v++ {
			expected[fmt.Sprintf("CVE-2026-%05d/1.0-%d", 10000+c, v)] = true
		}
	}
	from := uint64(0)
	var first FindingsPage
	pages := 0
	for {
		q := findingQuery(summary, from, 13)
		p, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, q)
		if e != nil {
			t.Fatal(e)
		}
		pages++
		if pages == 1 {
			first = p
		}
		if p.NextCheck-p.FromCheck != p.ScannedCheckCount || p.ComparisonCount > MaxComparisons || p.ScannedCheckCount > MaxVisitedChecks {
			t.Fatal("page budgets")
		}
		for _, item := range p.Items {
			key := item.Finding.CVEID + "/" + item.Finding.InstalledSourceVersion
			if !expected[key] {
				t.Fatal("unexpected/duplicate", key)
			}
			delete(expected, key)
			count := 1
			if item.Finding.InstalledSourceVersion == "1.0-1" {
				count = 2
			}
			if item.BinaryCount != count || len(item.Finding.Binaries) != 1 || item.Finding.BinariesTruncated != (count > 1) {
				t.Fatal("binary preview mismatch")
			}
		}
		if p.Exhausted {
			break
		}
		if p.NextCheck <= from {
			t.Fatal("nonadvancing")
		}
		from = p.NextCheck
	}
	if len(expected) != 0 || pages < 30 || summary.Coverage.MatchedWarningCount != 145 || summary.Coverage.MatchedFindingCount != 435 {
		t.Fatal("full set/totals", len(expected), pages)
	}
	again, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow.Add(time.Nanosecond), AssessmentIdentity{}, raw, findingQuery(summary, 0, 13))
	again.ServerNow = first.ServerNow
	if e != nil || !reflect.DeepEqual(first, again) || !bytes.Equal(raw, original) {
		t.Fatal("backward page changed or checkpoint mutated", e)
	}
	terminal, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(summary, summary.Coverage.TotalCheckCount, 100))
	if e != nil || !terminal.Exhausted || terminal.ScannedCheckCount != 0 || len(terminal.Items) != 0 || terminal.StopReason != "exhausted" {
		t.Fatal("terminal suffix", e, terminal)
	}
}
func TestDetailPagesEmptyScanThenLaterFinding(t *testing.T) {
	s, m, rows := continuationFixture(t, 1, 1, MaxVisitedChecks)
	r, raw := completedDetails(t, s, m, rows)
	a, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, 0, 100))
	if e != nil || a.NextCheck != 4000 || len(a.Items) != 0 || a.Exhausted || a.StopReason != "visited_check_limit_exceeded" || a.ComparisonCount != 0 {
		t.Fatal("empty scan", e, a)
	}
	b, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, a.NextCheck, 100))
	if e != nil || len(b.Items) != 1 || b.Items[0].CheckIndex != 4000 || !b.Exhausted {
		t.Fatal("later match", e, b)
	}
}
func TestDetailBinariesExactGroupBeyond128AndExcludedRows(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("3.0-1", "resolved"))
	rows := []linuxpackages.PackageRow{}
	for i := 0; i < 145; i++ {
		rows = append(rows, row(fmt.Sprintf("openssl-bin-%03d", i), "openssl", "1.0-1"))
	}
	multi := rows[0]
	multi.Architecture = "arm64"
	rows = append(rows, multi, row("openssl-other-version", "openssl", "2.0-1"), row("openssl-prefix", "openssl-extra", "1.0-1"), row("openssl-local", "openssl", "1.0-1+local"))
	incomplete := row("openssl-incomplete", "openssl", "1.0-1")
	incomplete.InstallState = "incomplete"
	rows = append(rows, incomplete)
	m, rows := inventory(t, linuxpackages.Debian13, rows, testNow)
	r, raw := completedDetails(t, s, m, rows)
	seen := map[string]bool{}
	from := uint64(0)
	for {
		p, e := QueryBinaries(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, binaryQuery(r, 0, from))
		if e != nil || p.BinaryCount != 146 || len(p.Items) > 20 || p.InstalledSourceVersion != "1.0-1" {
			t.Fatal("binary page", e, p)
		}
		for _, b := range p.Items {
			key := b.Name + "/" + b.Architecture
			if seen[key] || !strings.HasPrefix(b.Name, "openssl-bin-") {
				t.Fatal("wrong/duplicate binary", key)
			}
			seen[key] = true
		}
		if p.Exhausted {
			break
		}
		from = p.NextBinary
	}
	if len(seen) != 146 {
		t.Fatal("missing binaries")
	}
	p, e := QueryBinaries(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, binaryQuery(r, 0, 146))
	if e != nil || !p.Exhausted || len(p.Items) != 0 {
		t.Fatal("terminal binaries", e)
	}
	for _, q := range []BinariesQuery{binaryQuery(r, 0, 147), binaryQuery(r, 2, 0)} {
		if _, e = QueryBinaries(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, q); !errors.Is(e, ErrDetailQuery) {
			t.Fatal("forged binary position", e)
		}
	}
}
func TestDetailMaximumRowsRecoverNoncontiguousPreview(t *testing.T) {
	source := "source" + strings.Repeat("a", 250)
	installed := "1." + strings.Repeat("a", 510)
	records := map[string]any{}
	for i := 0; i < 2000; i++ {
		records[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": fmt.Sprintf("2.%04d", i) + strings.Repeat("a", 506)}}}
	}
	tail := map[string]any{}
	for i := 2000; i < 2017; i++ {
		tail[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": "2.0-1"}}}
	}
	payload, _ := json.Marshal(map[string]any{source: records, "zz": tail})
	s := parse(t, DebianProvider, string(payload))
	p := row(strings.Repeat("b", 256), source, installed)
	p.Architecture = strings.Repeat("a", 64)
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{p, row("zz", "zz", "1.0-1")}, testNow)
	r, raw := completedDetails(t, s, m, rows)
	if !hasReason(r, "response_byte_limit_exceeded") || r.Coverage.MatchedFindingCount != 2017 {
		t.Fatal("byte-trim fixture", len(r.Findings))
	}
	// Preview has a missing middle and later appended records, never a cursor.
	later := false
	for _, f := range r.Findings {
		if f.CVEID >= "CVE-2026-12000" {
			later = true
		}
	}
	if !later {
		t.Fatal("fixture did not retain a noncontiguous preview")
	}
	seen := 0
	from := uint64(0)
	byteStops := 0
	for {
		page, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, from, 100))
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(page)
		if len(encoded) > MaxResultBytes {
			t.Fatal("response over budget")
		}
		for _, item := range page.Items {
			if item.CheckIndex != uint64(seen) || item.Finding.CVEID != fmt.Sprintf("CVE-2026-%05d", 10000+seen) {
				t.Fatal("missing middle", seen, item.CheckIndex)
			}
			single, _ := json.Marshal(item)
			if len(single)+2 > detailDataBudget {
				t.Fatal("max single row does not fit")
			}
			seen++
		}
		if page.StopReason == "response_byte_limit_exceeded" {
			byteStops++
		}
		if page.Exhausted {
			break
		}
		from = page.NextCheck
	}
	if seen != 2017 || byteStops == 0 {
		t.Fatal("lost maximum rows", seen, byteStops)
	}
}
func TestDetailUbuntuInterruptedComparisonCheckAndCancellation(t *testing.T) {
	records := []any{}
	for i := 0; i < 667; i++ {
		introduced, fixed := fmt.Sprintf("0.0-%d", i), fmt.Sprintf("1.0-%d", i)
		if i == 666 {
			introduced, fixed = "1.5-1", "3.0-1"
		}
		records = append(records, map[string]any{"id": fmt.Sprintf("UBUNTU-CVE-2026-%05d", 10000+i), "modified": "2026-10-05T06:00:00Z", "affected": []any{map[string]any{"package": map[string]string{"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"}, "ranges": []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]string{"introduced": introduced}, map[string]string{"fixed": fixed}}}}}}})
	}
	payload, _ := json.Marshal(records)
	s := parse(t, UbuntuProvider, string(payload))
	m, rows := inventory(t, linuxpackages.Ubuntu2404, []linuxpackages.PackageRow{row("openssl", "openssl", "2.0-1")}, testNow)
	r, raw := completedDetails(t, s, m, rows)
	p, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, 0, 100))
	if e != nil || p.ComparisonCount != 2000 || p.NextCheck != 666 || len(p.Items) != 0 || p.StopReason != "comparison_limit_exceeded" {
		t.Fatal("whole check interrupted", e, p)
	}
	p, e = QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, 666, 100))
	if e != nil || !p.Exhausted || p.ComparisonCount != 3 || len(p.Items) != 1 {
		t.Fatal("whole check retry", e, p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, e = QueryFindings(ctx, s, m, rows, &cancelOnCall{target: 2, cancel: cancel}, testNow, AssessmentIdentity{}, raw, findingQuery(r, 666, 100))
	if !errors.Is(e, ErrCanceled) || p.Items != nil {
		t.Fatal("cancellation acknowledged a variable page", e)
	}
}
func TestDetailQueriesRejectMissingIncompleteChangedInvalidCheckpoints(t *testing.T) {
	s, m, rows := continuationFixture(t, 2001, 1, 0)
	r, raw := completedDetails(t, s, m, rows)
	for _, kind := range []string{"missing", "corrupt", "incomplete", "revision", "id", "offset", "limit", "time", "expired", "inventory", "nil-comparator"} {
		t.Run(kind, func(t *testing.T) {
			q := findingQuery(r, 0, 100)
			prior := raw
			now := testNow
			mm := m
			var comparator interface{} = debianversion.Comparator{}
			want := ErrCheckpoint
			switch kind {
			case "missing":
				prior = nil
			case "corrupt":
				prior = []byte(`{}`)
			case "incomplete":
				step, p, e := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, nil)
				if e != nil {
					t.Fatal(e)
				}
				prior = p
				q.AssessmentRevision = step.Continuation.Revision
				want = ErrDetailIncomplete
			case "revision":
				q.AssessmentRevision++
				want = ErrDetailBinding
			case "id":
				q.AssessmentID = strings.Repeat("a", 64)
				want = ErrDetailBinding
			case "offset":
				q.FromCheck = 2002
				want = ErrDetailQuery
			case "limit":
				q.Limit = 101
				want = ErrDetailQuery
			case "time":
				now = now.Add(-time.Second)
				want = ErrDetailUnavailable
			case "expired":
				now = now.Add(InventoryTTL)
				want = ErrDetailUnavailable
			case "inventory":
				mm.RowsSHA256 = strings.Repeat("a", 64)
				want = ErrDetailUnavailable
			case "nil-comparator":
				comparator = nil
				want = ErrDetailUnavailable
			}
			var e error
			if comparator == nil {
				_, e = QueryFindings(context.Background(), s, mm, rows, nil, now, AssessmentIdentity{}, prior, q)
			} else {
				_, e = QueryFindings(context.Background(), s, mm, rows, debianversion.Comparator{}, now, AssessmentIdentity{}, prior, q)
			}
			if !errors.Is(e, want) {
				t.Fatal("invalid query accepted", kind, e, want)
			}
		})
	}
}

func TestDetailPagesPreserveUninterpretableIntervalWithoutBlockingLaterMatches(t *testing.T) {
	payload := `[{"id":"UBUNTU-CVE-2026-1000","modified":"2026-10-05T06:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0-1"},{"fixed":"1.0-1"}]}]}]},{"id":"UBUNTU-CVE-2026-1001","modified":"2026-10-05T06:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0-1"},{"fixed":"3.0-1"}]}]}]}]`
	s := parse(t, UbuntuProvider, payload)
	m, rows := inventory(t, linuxpackages.Ubuntu2404, []linuxpackages.PackageRow{row("openssl", "openssl", "2.0-1")}, testNow)
	r, raw := completedDetails(t, s, m, rows)
	if r.UnassessedRecordCount != 1 || r.Coverage.MatchedFindingCount != 1 {
		t.Fatal("fixture gap")
	}
	p, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, 0, 100))
	if e != nil || !p.Exhausted || len(p.Items) != 1 || p.Items[0].CheckIndex != 1 {
		t.Fatal("deterministic unassessed interval blocked later details", e, p)
	}
	if _, e = QueryBinaries(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, binaryQuery(r, 0, 0)); !errors.Is(e, ErrDetailQuery) {
		t.Fatal("nonfinding binary query accepted", e)
	}
}

func TestDetailPagesPreserveUnsupportedComparatorGapsBeforeLaterWarning(t *testing.T) {
	for _, version := range []string{"2147483648:1.0-1", "1:2:3-1"} {
		t.Run(version, func(t *testing.T) {
			payload := `{"aa":{"CVE-2026-1000":{"releases":{"trixie":{"status":"resolved","fixed_version":"9.0-1"}}}},"zz":{"CVE-2026-1001":{"releases":{"trixie":{"status":"resolved","fixed_version":"2.0-1"}}}}}`
			s := parse(t, DebianProvider, payload)
			m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("aa", "aa", version), row("zz", "zz", "1.0-1")}, testNow)
			r, raw := completedDetails(t, s, m, rows)
			original := append([]byte{}, raw...)
			if r.UnassessedRecordCount != 1 || r.Coverage.MatchedFindingCount != 1 || !hasReason(r, "debian_comparator_unavailable") {
				t.Fatal("fixture gap", r.Coverage, r.ReasonCodes)
			}
			p, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, 0, 100))
			if e != nil || !p.Exhausted || p.ScannedCheckCount != 2 || len(p.Items) != 1 || p.Items[0].CheckIndex != 1 || p.Items[0].Finding.CVEID != "CVE-2026-1001" || !bytes.Equal(raw, original) {
				t.Fatal("unknown check blocked/changed summary", e, p)
			}
			if _, e = QueryBinaries(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, binaryQuery(r, 0, 0)); !errors.Is(e, ErrDetailQuery) {
				t.Fatal("unknown check exposed binaries", e)
			}
			after, _, e := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw)
			if e != nil || after.Status != "partial" || after.UnassessedRecordCount != 1 || after.Coverage.MatchedWarningCount != 1 || after.AssessedAt != r.AssessedAt || after.Continuation.Revision != r.Continuation.Revision {
				t.Fatal("details created a safe verdict or changed authoritative summary", e)
			}
		})
	}
}

func TestDetailMaximumFieldSingleRowAndFixedEnvelopeFit(t *testing.T) {
	source := strings.Repeat("s", 256)
	cve := "CVE-9999-" + strings.Repeat("9", 19)
	installed := "1." + strings.Repeat("a", 510)
	fixed := "2." + strings.Repeat("a", 510)
	payload, _ := json.Marshal(map[string]any{source: map[string]any{cve: map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": fixed}}}}})
	s := parse(t, DebianProvider, string(payload))
	p := row(strings.Repeat("b", 256), source, installed)
	p.Architecture = strings.Repeat("a", 64)
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{p}, testNow)
	r, raw := completedDetails(t, s, m, rows)
	page, e := QueryFindings(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw, findingQuery(r, 0, 1))
	if e != nil || !page.Exhausted || len(page.Items) != 1 {
		t.Fatal("max fields cannot make progress", e)
	}
	page.DeviceID = "agent_" + strings.Repeat("f", 32)
	page.ServerNow = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	page.AssessmentRevision = ^uint64(0)
	page.FromCheck = ^uint64(0)
	page.NextCheck = ^uint64(0)
	page.ScannedCheckCount = 4000
	page.ComparisonCount = 2000
	page.StopReason = "response_byte_limit_exceeded"
	all, _ := json.Marshal(page)
	items, _ := json.Marshal(page.Items)
	if len(all)-len(items) > DetailEnvelopeReserve || len(all) > MaxResultBytes {
		t.Fatal("reserved fixed envelope does not fit", len(all)-len(items))
	}
}
