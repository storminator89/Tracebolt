package journalview

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func browseFixture() (Query, time.Time) {
	q, now := fixtureQuery()
	q.BrowseMode = BrowseMode
	q.Start = time.Unix(0, 0).UTC()
	return q, now
}
func browseLine(q Query, n int, message string) string {
	b, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprintf("s=fixture;i=%x", n), "__REALTIME_TIMESTAMP": fmt.Sprint(q.End.Add(-time.Duration(n) * time.Second).UnixMicro()), "_SYSTEMD_UNIT": q.Unit, "PRIORITY": "6", "MESSAGE": message})
	return string(b) + "\n"
}

func TestRetainedBrowsePagesBeyondLegacyLimits(t *testing.T) {
	q, now := browseFixture()
	seen := 0
	for start := 0; start < 1201; {
		var input strings.Builder
		if start > 0 {
			input.WriteString(browseLine(q, start-1, "retained message"))
		}
		for i := start; i < 1201; i++ {
			input.WriteString(browseLine(q, i, "retained message"))
		}
		s, e := Parse(context.Background(), q, now, strings.NewReader(input.String()))
		if e != nil {
			t.Fatal(e)
		}
		if _, e := Encode(s); e != nil {
			t.Fatalf("invalid page %d: %v", start, e)
		}
		seen += len(s.Rows)
		start += len(s.Rows)
		if start < 1201 {
			if s.Exhausted || s.Coverage != Partial || s.NextCursor == "" || len(s.Rows) != 500 {
				t.Fatal("silently exhausted bounded page")
			}
			q.Cursor = s.NextCursor
		} else if !s.Exhausted || s.NextCursor != "" || s.Coverage != Complete {
			t.Fatal("terminal page inconsistent")
		}
	}
	if seen != 1201 {
		t.Fatal("lost rows")
	}
	legacy := q
	legacy.BrowseMode = ""
	legacy.Cursor = ""
	if ValidateQuery(legacy, now) == nil {
		t.Fatal("legacy range silently widened")
	}
}
func TestRetainedBrowseSparseLiteralSearchProgress(t *testing.T) {
	q, now := browseFixture()
	q.Search = "Needle"
	var input strings.Builder
	for i := 0; i < MaxScannedRows+2; i++ {
		input.WriteString(browseLine(q, i, "haystack"))
	}
	s, e := Parse(context.Background(), q, now, strings.NewReader(input.String()))
	if e != nil || s.Coverage != Partial || s.NextCursor == "" || s.Exhausted || len(s.Rows) != 0 {
		t.Fatal("sparse scan must continue honestly")
	}
	q.Cursor = s.NextCursor
	input.Reset()
	input.WriteString(browseLine(q, MaxScannedRows-1, "haystack"))
	input.WriteString(browseLine(q, MaxScannedRows, "a nEeDlE in older retained data"))
	s, e = Parse(context.Background(), q, now, strings.NewReader(input.String()))
	if e != nil || len(s.Rows) != 1 || !s.Exhausted {
		t.Fatal("literal search did not reach later page")
	}
}
func TestRetainedCursorLossFailsClosed(t *testing.T) {
	q, now := browseFixture()
	q.Cursor = "s=fixture;i=7"
	for _, input := range []string{"", browseLine(q, 8, "must not appear")} {
		s, e := Parse(context.Background(), q, now, strings.NewReader(input))
		if e != nil || s.Reason != ReasonCursorUnavailable || s.Coverage != Failed || s.Exhausted || len(s.Rows) != 0 || s.NextCursor != "" {
			t.Fatal("lost source anchor became successful resume")
		}
	}
}
func TestRetainedCursorAndSearchBounds(t *testing.T) {
	q, now := browseFixture()
	for _, cursor := range []string{"--directory=/private", "s=x\n--system", strings.Repeat("a", MaxCursorBytes+1)} {
		q.Cursor = cursor
		if ValidateQuery(q, now) == nil {
			t.Fatal("invalid cursor admitted")
		}
	}
	q.Cursor = ""
	q.Search = strings.Repeat("x", MaxSearchBytes+1)
	if ValidateQuery(q, now) == nil {
		t.Fatal("oversized search admitted")
	}
}

func TestRetainedOversizedEntryIsAnExplicitGapWithBoundedProgress(t *testing.T) {
	q, now := browseFixture()
	s, e := Parse(context.Background(), q, now, strings.NewReader(browseLine(q, 1, strings.Repeat("x", MaxMessageBytes+1))+browseLine(q, 2, "older readable message")))
	if e != nil || s.Coverage != Partial || s.Reason != ReasonByteLimit || s.NextCursor == "" || s.Exhausted || len(s.Rows) != 0 {
		t.Fatal("oversized entry silently disappeared or blocked older browsing")
	}
	q.Cursor = s.NextCursor
	s, e = Parse(context.Background(), q, now, strings.NewReader(browseLine(q, 1, strings.Repeat("x", MaxMessageBytes+1))+browseLine(q, 2, "older readable message")))
	if e != nil || !s.Exhausted || len(s.Rows) != 1 {
		t.Fatal("source locator did not continue beyond explicit projection gap")
	}
}

func TestRetainedMaskExpansionIsAnExplicitGapAndOlderRowsRemainReachable(t *testing.T) {
	q, now := browseFixture()
	message := strings.Repeat("token=x ", 512)
	masked, _ := redact(message)
	if len(message) != MaxMessageBytes || len(masked) <= MaxMessageBytes {
		t.Fatal("invalid expansion fixture")
	}
	s, e := Parse(context.Background(), q, now, strings.NewReader(browseLine(q, 1, message)+browseLine(q, 2, "older readable message")))
	if e != nil || s.Coverage != Partial || s.Reason != ReasonByteLimit || s.NextCursor != "s=fixture;i=1" || s.Exhausted || len(s.Rows) != 0 {
		t.Fatal("mask expansion blocked continuation or silently lost its gap")
	}
	if _, e := Encode(s); e != nil {
		t.Fatal("invalid explicit gap snapshot", e)
	}
	q.Cursor = s.NextCursor
	s, e = Parse(context.Background(), q, now, strings.NewReader(browseLine(q, 1, message)+browseLine(q, 2, "older readable message")))
	if e != nil || !s.Exhausted || len(s.Rows) != 1 || s.Rows[0].Message != "older readable message" {
		t.Fatal("older entry remains inaccessible after mask expansion")
	}
}

func TestRetainedPageCapacityRetriesTheUnretainedRow(t *testing.T) {
	q, now := browseFixture()
	var input strings.Builder
	message := strings.Repeat("q", 4000)
	for i := 0; i < 180; i++ {
		input.WriteString(browseLine(q, i, message))
	}
	s, e := Parse(context.Background(), q, now, strings.NewReader(input.String()))
	if e != nil || s.Coverage != Partial || s.Reason != ReasonByteLimit || len(s.Rows) == 0 || len(s.Rows) >= 180 {
		t.Fatal("fixture did not hit per-page capacity")
	}
	retained := len(s.Rows)
	if s.NextCursor != fmt.Sprintf("s=fixture;i=%x", retained-1) {
		t.Fatal("ordinary page capacity skipped the first row needing a fresh page")
	}
	q.Cursor = s.NextCursor
	input.Reset()
	for i := retained - 1; i < 180; i++ {
		input.WriteString(browseLine(q, i, message))
	}
	next, e := Parse(context.Background(), q, now, strings.NewReader(input.String()))
	if e != nil || !next.Exhausted || len(next.Rows)+retained != 180 || next.Rows[0].Timestamp != q.End.Add(-time.Duration(retained)*time.Second) {
		t.Fatal("capacity continuation lost or duplicated rows")
	}
}

func TestRetainedNullAndBinaryMessagesAreExplicitTraversableGaps(t *testing.T) {
	q, now := browseFixture()
	for _, message := range []any{nil, []int{0, 255, 10}} {
		raw, e := json.Marshal(map[string]any{"__CURSOR": "s=fixture;i=1", "__REALTIME_TIMESTAMP": fmt.Sprint(q.End.Add(-time.Second).UnixMicro()), "_SYSTEMD_UNIT": q.Unit, "PRIORITY": "6", "MESSAGE": message})
		if e != nil {
			t.Fatal(e)
		}
		input := string(raw) + "\n" + browseLine(q, 2, "older readable message")
		first, e := Parse(context.Background(), q, now, strings.NewReader(input))
		if e != nil || first.Coverage != Partial || first.Reason != ReasonInvalidSource || first.NextCursor != "s=fixture;i=1" || first.Exhausted || len(first.Rows) != 0 {
			t.Fatal("null/binary message was silently projected or blocked older rows")
		}
		if _, e := Encode(first); e != nil {
			t.Fatal("gap result cannot be encoded", e)
		}
		nextQuery := q
		nextQuery.Cursor = first.NextCursor
		next, e := Parse(context.Background(), nextQuery, now, strings.NewReader(input))
		if e != nil || !next.Exhausted || len(next.Rows) != 1 || next.Rows[0].Message != "older readable message" {
			t.Fatal("null/binary gap did not advance exactly")
		}
	}
}
