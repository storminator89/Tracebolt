package linuxcve

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/debianversion"
	"localrmm/internal/linuxpackages"
	"testing"
)

// This fixture reproduces the screenshot's shape without using any endpoint
// inventory or real CVE payload: six warnings, 627 vendor gaps, 1,396 dpkg rows.
// The old single truncation flag made this completed evaluation look interrupted.
func TestCompleteAssessmentWith1396PackagesAnd627VendorGaps(t *testing.T) {
	records := map[string]any{}
	for i := 0; i < 633; i++ {
		status, fixed := "open", ""
		if i < 6 {
			status, fixed = "resolved", "2.0-1+deb13u2"
		}
		records[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": status, "fixed_version": fixed}}}
	}
	raw, _ := json.Marshal(map[string]any{"fixture-office": records})
	rows := make([]linuxpackages.PackageRow, 1396)
	for i := range rows {
		rows[i] = row(fmt.Sprintf("fixture-binary-%04d", i), "fixture-office", "2.0-1+deb13u1")
	}
	r := evaluate(t, parse(t, DebianProvider, string(raw)), linuxpackages.Debian13, rows...)
	c := r.Coverage
	if !c.EvaluationComplete || c.TotalCheckCount != 633 || c.CompletedCheckCount != 633 || c.ComparisonCount != 1 || c.MatchedFindingCount != 6 || c.MatchedWarningCount != 6 || r.UnassessedRecordCount != 627 || len(r.Findings) != 6 {
		t.Fatalf("completed processing and vendor gaps were conflated: %+v", r)
	}
	if !r.Truncated || !hasReason(r, "binary_limit_exceeded") || hasReason(r, "comparison_limit_exceeded") || r.SkippedPackageCount != 0 {
		t.Fatalf("display-only bounds affected assessment coverage: %+v", r)
	}
	if len(c.UnassessedReasons) != 1 || c.UnassessedReasons[0] != (UnassessedReasonCount{Reason: "published_fix_unavailable", Count: 627}) {
		t.Fatalf("vendor gap causes: %+v", c.UnassessedReasons)
	}
}

func TestFindingDisplayLimitDoesNotStopCoverageOrTotals(t *testing.T) {
	records := map[string]any{}
	for i := 0; i < MaxFindings+11; i++ {
		status, fixed := "resolved", "2.0-1"
		if i == MaxFindings+10 {
			status, fixed = "undetermined", ""
		}
		records[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": status, "fixed_version": fixed}}}
	}
	raw, _ := json.Marshal(map[string]any{"openssl": records})
	r := evaluate(t, parse(t, DebianProvider, string(raw)), linuxpackages.Debian13, row("openssl", "openssl", "1.0-1"))
	if len(r.Findings) != MaxFindings || r.Coverage.MatchedFindingCount != MaxFindings+10 || r.Coverage.MatchedWarningCount != MaxFindings+10 || !r.Coverage.EvaluationComplete || r.Coverage.CompletedCheckCount != MaxFindings+11 || r.UnassessedRecordCount != 1 {
		t.Fatalf("display cap stopped or changed totals: %+v", r)
	}
	if !hasReason(r, "finding_limit_exceeded") || !hasReason(r, "vendor_status_undetermined") || !r.Truncated {
		t.Fatalf("display/gap reasons missing: %+v", r)
	}
}

func TestProcessingLimitReportsExactPendingChecksNotVendorGaps(t *testing.T) {
	records := map[string]any{}
	for i := 0; i < MaxComparisons+17; i++ {
		records[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": fmt.Sprintf("1.0-%d", i+1)}}}
	}
	raw, _ := json.Marshal(map[string]any{"openssl": records})
	r := evaluate(t, parse(t, DebianProvider, string(raw)), linuxpackages.Debian13, row("openssl", "openssl", "999.0-1"))
	if r.Coverage.EvaluationComplete || r.Coverage.TotalCheckCount != MaxComparisons+17 || r.Coverage.CompletedCheckCount != MaxComparisons || r.Coverage.ComparisonCount != MaxComparisons || r.UnassessedRecordCount != 0 || len(r.Coverage.UnassessedReasons) != 0 || !hasReason(r, "comparison_limit_exceeded") {
		t.Fatalf("processing cutoff mislabeled as unknown vendor data: %+v", r)
	}
}

func TestCoverageSeparatesPackageGapsAndDeduplicatesVendorReasons(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("v1.2-3", "resolved"))
	a, b := row("libssl-one", "openssl", "1.0-1"), row("libssl-two", "openssl", "2.0-1")
	incomplete := row("incomplete", "openssl", "1.0-1")
	incomplete.InstallState = "incomplete"
	r := evaluate(t, s, linuxpackages.Debian13, a, b, incomplete, row("backport", "openssl", "1.0-1~bpo13+1"), row("missing", "no-feed-record", "1.0-1"))
	if r.SkippedPackageCount != 3 || r.Coverage.PackageGaps != (PackageGapCounts{InstallationIncomplete: 1, NonstandardVersion: 1, SourceMissing: 1}) || r.UnassessedRecordCount != 1 || r.Coverage.TotalCheckCount != 2 || r.Coverage.CompletedCheckCount != 2 || !r.Coverage.EvaluationComplete {
		t.Fatalf("distinct package and record gaps conflated: %+v", r)
	}
	if len(r.Coverage.UnassessedReasons) != 1 || r.Coverage.UnassessedReasons[0].Count != 1 {
		t.Fatalf("same advisory multiplied by installed versions: %+v", r.Coverage.UnassessedReasons)
	}
}

type cancelCoverageComparator struct{ cancel context.CancelFunc }

func (c cancelCoverageComparator) Compare(context.Context, string, string) (int, error) {
	c.cancel()
	return 0, context.Canceled
}

func TestInterruptedCheckRemainsPending(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("2.0-1", "resolved"))
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", "1.0-1")}, testNow)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Evaluate(ctx, s, m, rows, cancelCoverageComparator{cancel}, testNow)
	if r.Coverage.EvaluationComplete || r.Coverage.TotalCheckCount != 1 || r.Coverage.CompletedCheckCount != 0 || r.UnassessedRecordCount != 0 || !hasReason(r, "evaluation_canceled_or_timed_out") {
		t.Fatalf("interrupted check became completed: %+v", r)
	}
	// A later clean evaluation of the same immutable input must remain possible.
	r = Evaluate(context.Background(), s, m, rows, debianversion.Comparator{}, testNow)
	if !r.Coverage.EvaluationComplete || r.Coverage.CompletedCheckCount != 1 || len(r.Findings) != 1 {
		t.Fatal("interruption mutated immutable source", r)
	}
}

type cancelAfterComparison struct{ cancel context.CancelFunc }

func (c cancelAfterComparison) Compare(ctx context.Context, a, b string) (int, error) {
	order, err := (debianversion.Comparator{}).Compare(ctx, a, b)
	c.cancel()
	return order, err
}

func TestCancellationAfterLastCompletedCheckDoesNotInventPendingWork(t *testing.T) {
	s := parse(t, DebianProvider, debianPayload("2.0-1", "resolved"))
	m, rows := inventory(t, linuxpackages.Debian13, []linuxpackages.PackageRow{row("openssl", "openssl", "1.0-1"), row("zzz", "zzz-no-record", "1.0-1")}, testNow)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Evaluate(ctx, s, m, rows, cancelAfterComparison{cancel}, testNow)
	if !r.Coverage.EvaluationComplete || r.Coverage.CompletedCheckCount != 1 || r.Coverage.PackageGaps.SourceMissing != 1 || hasReason(r, "evaluation_canceled_or_timed_out") || r.Truncated {
		t.Fatalf("finished checks became contradictory incomplete work: %+v", r)
	}
}
