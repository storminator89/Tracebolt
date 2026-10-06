package linuxcve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/debianversion"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"strings"
	"testing"
	"time"
)

func continuationFixture(t *testing.T, records, versions, gaps int) (*Snapshot, fullinventory.Manifest, []linuxpackages.PackageRow) {
	t.Helper()
	advisories := map[string]any{}
	for i := 0; i < records+gaps; i++ {
		status, fixed := "resolved", fmt.Sprintf("9.0-%d", i+1)
		if i < gaps {
			status, fixed = "open", ""
		}
		advisories[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": status, "fixed_version": fixed}}}
	}
	raw, _ := json.Marshal(map[string]any{"fixture-source": advisories})
	s := parse(t, DebianProvider, string(raw))
	rows := []linuxpackages.PackageRow{}
	for i := 0; i < versions; i++ {
		rows = append(rows, row(fmt.Sprintf("fixture-binary-%04d", i), "fixture-source", fmt.Sprintf("1.0-%d", i+1)))
	}
	multi := rows[0]
	multi.Architecture = "arm64"
	rows = append(rows, multi)
	m, rows := inventory(t, linuxpackages.Debian13, rows, testNow)
	return s, m, rows
}

func TestContinuationFinishesAcrossRestartsWithoutDuplicatingRecords(t *testing.T) {
	s, m, rows := continuationFixture(t, 2011, 3, 5)
	identity := AssessmentIdentity{DeviceID: "fixture-device", Sequence: 7}
	var raw []byte
	var last Result
	for step := 0; step < 10; step++ {
		// Serialized state is the only continuity; no evaluator instance survives.
		r, next, err := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, identity, append([]byte{}, raw...))
		if err != nil {
			t.Fatal(err)
		}
		if r.Coverage.ComparisonCount > MaxComparisons || r.Continuation.AdvancedCheckCount > MaxVisitedChecks {
			t.Fatal("step budget escaped")
		}
		if step == 0 {
			var p checkpoint
			if json.Unmarshal(next, &p) != nil || p.InstalledVersion != 2 || !p.RecordMatched || !p.SourceEvaluated {
				t.Fatal("fixture did not stop mid-record", p)
			}
			if r.Coverage.MatchedWarningCount != 667 || r.UnassessedRecordCount != 5 {
				t.Fatal("partial deduplication", r.Coverage)
			}
		}
		if r.Coverage.CompletedCheckCount < last.Coverage.CompletedCheckCount {
			t.Fatal("progress regressed")
		}
		last = r
		raw = next
		if r.Coverage.EvaluationComplete {
			break
		}
		if r.Continuation.State != "pending" || r.Continuation.AdvancedCheckCount == 0 || len(raw) == 0 {
			t.Fatal("unadvanceable pending result")
		}
	}
	if !last.Coverage.EvaluationComplete || last.Coverage.CompletedCheckCount != 6048 || last.Coverage.TotalCheckCount != 6048 || last.Coverage.MatchedFindingCount != 6033 || last.Coverage.MatchedWarningCount != 2011 || last.UnassessedRecordCount != 5 || last.EvaluatedSourceCount != 1 || len(last.Findings) != MaxFindings {
		t.Fatal("resumption lost or duplicated totals", last.Coverage, last.UnassessedRecordCount)
	}
	if len(last.Coverage.UnassessedReasons) != 1 || last.Coverage.UnassessedReasons[0].Count != 5 || hasReason(last, "comparison_limit_exceeded") {
		t.Fatal("completed reasons were not cumulative/clean")
	}
	r, _, err := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow.Add(time.Minute), identity, raw)
	if err != nil || r.Continuation.State != "complete" || r.Continuation.AdvancedCheckCount != 0 || r.Continuation.Revision != last.Continuation.Revision || r.Coverage.ComparisonCount != 0 || r.AssessedAt != last.AssessedAt {
		t.Fatal("cached read did new work or renewed assessment", err, r.Continuation)
	}
}

func TestContinuationBoundsChecksWithoutComparatorCalls(t *testing.T) {
	s, m, rows := continuationFixture(t, 0, 1, MaxVisitedChecks+1)
	a, raw, e := EvaluateStep(context.Background(), s, m, rows, nil, testNow, AssessmentIdentity{}, nil)
	if e != nil || a.Coverage.CompletedCheckCount != MaxVisitedChecks || a.Coverage.ComparisonCount != 0 || a.Continuation.Reason != "visited_check_limit_exceeded" || a.Continuation.State != "pending" {
		t.Fatal("zero-comparison work unbounded", e, a.Continuation)
	}
	b, _, e := EvaluateStep(context.Background(), s, m, rows, nil, testNow, AssessmentIdentity{}, raw)
	if e != nil || !b.Coverage.EvaluationComplete || b.UnassessedRecordCount != MaxVisitedChecks+1 || b.Continuation.AdvancedCheckCount != 1 || hasReason(b, "visited_check_limit_exceeded") {
		t.Fatal("zero-comparison continuation", e, b.Coverage)
	}
}

func TestContinuationBindingAndCheckpointValidation(t *testing.T) {
	s, m, rows := continuationFixture(t, 2001, 1, 0)
	identity := AssessmentIdentity{"fixture-device", 3}
	_, raw, e := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, identity, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"device", "sequence", "manifest", "release", "feed_hash", "feed_fetch", "feed_expiry", "feed_trust", "feed_coverage", "evaluator", "cursor", "count", "duplicate", "unknown", "oversized", "age", "clock"} {
		t.Run(change, func(t *testing.T) {
			ss := *s
			mm := m
			rr := rows
			ii := identity
			data := append([]byte{}, raw...)
			now := testNow
			switch change {
			case "device":
				ii.DeviceID = "different-device"
			case "sequence":
				ii.Sequence++
			case "manifest":
				mm.CollectedAt = mm.CollectedAt.Add(-time.Second)
			case "release":
				id, version, codename := "ubuntu", "24.04", "noble"
				mm.Release.Fields = linuxpackages.ReleaseFields{ID: &id, VersionID: &version, VersionCodename: &codename}
				ss.metadata.Target = linuxpackages.Ubuntu2404
			case "feed_hash":
				ss.metadata.SHA256 = strings.Repeat("a", 64)
			case "feed_fetch":
				ss.metadata.FetchedAt = ss.metadata.FetchedAt.Add(-time.Second)
			case "feed_expiry":
				ss.metadata.ExpiresAt = ss.metadata.ExpiresAt.Add(-time.Second)
			case "feed_trust":
				ss.metadata.Trust = "https_origin_only"
			case "feed_coverage":
				ss.metadata.Coverage = "official_feed_records"
			case "evaluator":
				data = []byte(strings.Replace(string(data), EvaluatorVersion, "unsupported-evaluator", 1))
			case "cursor":
				var p checkpoint
				_ = json.Unmarshal(data, &p)
				p.InstalledVersion = 100
				data, _ = json.Marshal(p)
			case "count":
				var p checkpoint
				_ = json.Unmarshal(data, &p)
				p.Completed--
				data, _ = json.Marshal(p)
			case "duplicate":
				data = append([]byte(`{"source":0,`), data[1:]...)
			case "unknown":
				data = append([]byte(`{"unexpected":true,`), data[1:]...)
			case "oversized":
				data = []byte(strings.Repeat(" ", MaxCheckpointBytes+1))
			case "age":
				now = now.Add(InventoryTTL)
			case "clock":
				now = now.Add(-time.Second)
			}
			result, _, err := EvaluateStep(context.Background(), &ss, mm, rr, debianversion.Comparator{}, now, ii, data)
			if !errors.Is(err, ErrCheckpoint) && !(change == "clock" && result.Status == "unavailable") {
				t.Fatal("checkpoint survived binding/corruption change", change, err, result.Status)
			}
		})
	}
	// A parser validation timestamp is presentation metadata, not feed identity.
	reload := *s
	reload.metadata.ValidatedAt = testNow.Add(time.Minute)
	r, _, e := EvaluateStep(context.Background(), &reload, m, rows, debianversion.Comparator{}, testNow.Add(time.Minute), identity, raw)
	if e != nil || !r.Coverage.EvaluationComplete || r.Coverage.CompletedCheckCount != 2001 {
		t.Fatal("revalidation invalidated matching restart", e)
	}
}

type cancelOnCall struct {
	calls, target int
	cancel        context.CancelFunc
}

func (c *cancelOnCall) Compare(ctx context.Context, a, b string) (int, error) {
	c.calls++
	if c.calls == c.target {
		c.cancel()
		return 0, context.Canceled
	}
	return (debianversion.Comparator{}).Compare(ctx, a, b)
}
func TestContinuationRetriesInterruptedWholeCheckAndBlocksNoProgress(t *testing.T) {
	payload := `[{"id":"UBUNTU-CVE-2026-1000","modified":"2026-10-05T06:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0-1"},{"fixed":"3.0-1"}]}]}]}]`
	s := parse(t, UbuntuProvider, payload)
	m, rows := inventory(t, linuxpackages.Ubuntu2404, []linuxpackages.PackageRow{row("openssl", "openssl", "2.0-1")}, testNow)
	ctx, cancel := context.WithCancel(context.Background())
	c := &cancelOnCall{target: 2, cancel: cancel}
	r, raw, e := EvaluateStep(ctx, s, m, rows, c, testNow, AssessmentIdentity{}, nil)
	if e != nil || r.Continuation.State != "blocked" || r.Continuation.Revision != 0 || r.Continuation.AdvancedCheckCount != 0 || r.Coverage.CompletedCheckCount != 0 || r.Coverage.ComparisonCount != 2 || r.UnassessedRecordCount != 0 || len(raw) != 0 {
		t.Fatal("interrupted item became progress", e, r.Continuation)
	}
	r, raw, e = EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, nil)
	if e != nil || len(raw) == 0 || !r.Coverage.EvaluationComplete || r.Coverage.CompletedCheckCount != 1 || r.Coverage.MatchedWarningCount != 1 || r.Coverage.ComparisonCount != 3 {
		t.Fatal("whole item retry did not finish", e, r.Coverage)
	}
}

func TestContinuationRejectsContradictoryBoundCheckpoint(t *testing.T) {
	s, m, rows := continuationFixture(t, 2001, 2, 1)
	identity := AssessmentIdentity{"fixture-device", 3}
	_, raw, e := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, identity, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"fixed_endpoint", "future_finding", "binary_flag", "source_count", "warning_count", "gap_explanation", "record_flag", "missing_version", "missing_assessmentId", "missing_source", "missing_completed", "missing_matchedWarnings", "null_findings", "null_reasons", "null_display"} {
		t.Run(kind, func(t *testing.T) {
			var p checkpoint
			if json.Unmarshal(raw, &p) != nil {
				t.Fatal("fixture checkpoint")
			}
			switch kind {
			case "fixed_endpoint":
				p.Findings[0].PublishedFixedVersion = "99.0-99"
			case "future_finding":
				p.Findings[0].CVEID = "CVE-2026-12001"
				p.Findings[0].PublishedFixedVersion = "9.0-2002"
				p.Findings[0].AdvisoryURL = "https://security-tracker.debian.org/tracker/CVE-2026-12001"
			case "binary_flag":
				p.Findings[0].BinariesTruncated = true
			case "source_count":
				p.EvaluatedSources = 0
			case "warning_count":
				p.MatchedWarnings = 0
			case "gap_explanation":
				p.UnassessedReasons = []UnassessedReasonCount{}
			case "record_flag":
				p.RecordMatched = true
				p.SourceEvaluated = false
			case "null_findings":
				p.Findings = nil
			case "null_reasons":
				p.UnassessedReasons = nil
			case "null_display":
				p.DisplayReasons = nil
			}
			changed, _ := json.Marshal(p)
			if strings.HasPrefix(kind, "missing_") {
				var value map[string]json.RawMessage
				_ = json.Unmarshal(changed, &value)
				delete(value, strings.TrimPrefix(kind, "missing_"))
				changed, _ = json.Marshal(value)
			}
			_, _, err := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, identity, changed)
			if !errors.Is(err, ErrCheckpoint) {
				t.Fatal("contradictory checkpoint accepted", kind, err)
			}
		})
	}
}

func TestContinuationDeduplicatesGapWhenCheckBudgetSplitsRecord(t *testing.T) {
	s, m, rows := continuationFixture(t, 0, 3, 2001)
	a, raw, e := EvaluateStep(context.Background(), s, m, rows, nil, testNow, AssessmentIdentity{}, nil)
	var saved checkpoint
	_ = json.Unmarshal(raw, &saved)
	if e != nil || a.Coverage.CompletedCheckCount != 4000 || a.UnassessedRecordCount != 1334 || saved.InstalledVersion != 1 || !saved.RecordUnassessed {
		t.Fatal("fixture did not stop inside a vendor-gap record", e, a.Coverage)
	}
	b, _, e := EvaluateStep(context.Background(), s, m, rows, nil, testNow, AssessmentIdentity{}, raw)
	if e != nil || !b.Coverage.EvaluationComplete || b.Coverage.CompletedCheckCount != 6003 || b.UnassessedRecordCount != 2001 || len(b.Coverage.UnassessedReasons) != 1 || b.Coverage.UnassessedReasons[0].Count != 2001 {
		t.Fatal("mid-gap restart multiplied gap counts", e, b.Coverage)
	}
}

func TestContinuationByteTrimmedFindingsRemainStableOnCachedRead(t *testing.T) {
	source := "source" + strings.Repeat("a", 250)
	installed, fixed := "1."+strings.Repeat("a", 510), "2."+strings.Repeat("a", 510)
	records := map[string]any{}
	for i := 0; i < MaxFindings; i++ {
		records[fmt.Sprintf("CVE-2026-%04d", 1000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": fixed}}}
	}
	payload, _ := json.Marshal(map[string]any{source: records})
	s := parse(t, DebianProvider, string(payload))
	rows := []linuxpackages.PackageRow{}
	for i := 0; i < MaxBinaryRows; i++ {
		rows = append(rows, row(fmt.Sprintf("binary%03d", i)+strings.Repeat("x", 247), source, installed))
	}
	m, rows := inventory(t, linuxpackages.Debian13, rows, testNow)
	a, raw, e := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, nil)
	if e != nil || len(a.Findings) >= MaxFindings {
		t.Fatal("byte bound fixture", e)
	}
	b, _, e := EvaluateStep(context.Background(), s, m, rows, debianversion.Comparator{}, testNow, AssessmentIdentity{}, raw)
	left, _ := json.Marshal(a.Findings)
	right, _ := json.Marshal(b.Findings)
	if e != nil || string(left) != string(right) || b.Coverage.MatchedWarningCount != MaxFindings || b.Continuation.AdvancedCheckCount != 0 {
		t.Fatal("unchanged checkpoint lost retained findings", e, len(a.Findings), len(b.Findings))
	}
}
