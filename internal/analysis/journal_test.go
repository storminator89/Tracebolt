package analysis

import (
	"context"
	"localrmm/internal/health"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/proactivejournal"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func journalAnalysisFixture() (health.Incident, health.Check, journalcache.Page) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	x := health.Incident{ID: "health_0000000000000001", Key: "service:fixture.service", Kind: "service", Target: "fixture.service", OpenedAt: at, LastObservedAt: at}
	check := health.Check{Key: x.Key, Kind: x.Kind, Target: x.Target, State: "open", ObservedAt: &at}
	page := journalcache.Page{SchemaVersion: "tracebolt.journal-page.v1", MatchedRows: 1, Scope: journalview.Scope, Query: journalview.Query{Unit: x.Target, Start: at.Add(-5 * time.Minute), End: at, MaxPriority: 4}, ObservedAt: at, ExpiresAt: at.Add(5 * time.Minute), Coverage: journalview.Complete, Reason: journalview.ReasonNone, SearchScope: "captured_snapshot_only", RedactionWarning: journalview.RedactionWarning, TotalCapturedRows: 1, CountExact: true, Rows: []journalview.Row{{Unit: x.Target, Timestamp: at.Add(-time.Second), Priority: 3, Message: "synthetic fixture error"}}, Identity: journalrequest.Identity{QueryDigest: "sha256:" + strings.Repeat("a", 64)}, SnapshotDigest: "sha256:" + strings.Repeat("b", 64)}
	return x, check, page
}
func TestAnalyzeJournalBoundsAndUTF8Clipping(t *testing.T) {
	x, c, page := journalAnalysisFixture()
	page.Rows[0].Message = strings.Repeat("界", 400)
	result, err := NewService(nil).AnalyzeJournal(context.Background(), x, c, page)
	if err != nil || result.Packet.DataScope != proactivejournal.DataScope {
		t.Fatal(err)
	}
	row := result.Packet.Evidence[len(result.Packet.Evidence)-1]
	if len(row.Detail) > MaxJournalMessageBytes || !utf8.ValidString(row.Detail) || !strings.HasPrefix(row.ID, "journal-row-") {
		t.Fatal("invalid bounded evidence")
	}
	for _, mutate := range []func(*journalcache.Page){
		func(p *journalcache.Page) { p.Rows[0].Unit = "other.service" },
		func(p *journalcache.Page) { p.Rows[0].Timestamp = p.Query.Start.Add(-time.Second) },
		func(p *journalcache.Page) { p.Rows[0].Priority = 5 },
		func(p *journalcache.Page) { p.Rows[0].Message = string([]byte{0xff}) },
		func(p *journalcache.Page) { p.Rows = make([]journalview.Row, proactivejournal.MaxRows+1) },
		func(p *journalcache.Page) { p.Search = "model-chosen-query" },
		func(p *journalcache.Page) { p.Query.Search = "retained-search" },
		func(p *journalcache.Page) { p.Query.Cursor = "s=fixture;i=1" },
		func(p *journalcache.Page) { p.NextCursor = "s=fixture;i=1" },
		func(p *journalcache.Page) { p.Exhausted = true },
		func(p *journalcache.Page) { p.Query.Start = p.Query.End.Add(-time.Hour) },
		func(p *journalcache.Page) {
			p.Query.End = p.Query.End.Add(-time.Second)
			p.Query.Start = p.Query.Start.Add(-time.Second)
		},
		func(p *journalcache.Page) { p.SchemaVersion = "tracebolt.journal-page.v2" },
		func(p *journalcache.Page) { p.Scope = "unapproved-scope" },
		// Even a forged legacy searchScope cannot smuggle the new local retained
		// range into an existing separately approved provider packet.
		func(p *journalcache.Page) {
			p.Query.BrowseMode = journalview.BrowseMode
			p.Query.Start = time.Unix(0, 0).UTC()
			p.Query.Cursor = "s=fixture;i=1"
		},
	} {
		_, _, bad := journalAnalysisFixture()
		mutate(&bad)
		if _, err := NewService(nil).AnalyzeJournal(context.Background(), x, c, bad); err == nil {
			t.Fatal("unbounded or substituted source accepted")
		}
	}
}
