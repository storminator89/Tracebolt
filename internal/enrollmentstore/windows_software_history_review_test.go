package enrollmentstore

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/windowsfullsoftware"
	ledger "localrmm/internal/windowsfullsoftwareledger"
)

func reviewedHistoryLongFixture(t *testing.T) fullSoftwareFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStoreTTL(t, "tls", 9*24*time.Hour)
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsFullSoftware(context.Background()); e != nil {
		t.Fatal(e)
	}
	c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: windowsfullsoftware.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at, HistoryScope: windowsfullsoftware.HistoryScope}
	out := fullSoftwareFixture{f, s, path, snap, cert, at, c}
	out.grant(t)
	return out
}

func TestSoftwareHistoryReviewSevenDayPrunePreservesFloor(t *testing.T) {
	f := reviewedHistoryLongFixture(t)
	defer func() { f.s.Close() }()
	firstAt := f.at
	f.capture(t, 1, []windowsfullsoftware.Row{})
	f.at = f.at.Add(time.Minute)
	f.capture(t, 2, []windowsfullsoftware.Row{softwareRow(1, softwareText("Private old registration"), nil, nil, "64")})
	f.at = firstAt.Add(windowsfullsoftware.HistoryRetention - time.Nanosecond)
	p := historyPage(t, f)
	if p.RetainedCount != 1 || p.ExpiredChanges != 0 {
		t.Fatal("history expired before original deadline", p)
	}
	f.at = firstAt.Add(windowsfullsoftware.HistoryRetention)
	if e := f.s.MaintainWindowsFullSoftware(context.Background(), f.at); e != nil {
		t.Fatal(e)
	}
	p = historyPage(t, f)
	if p.RetainedCount != 0 || p.ExpiredChanges != 1 || p.Comparison != nil || len(p.Rows) != 0 {
		t.Fatal("original seven-day boundary failed", p)
	}
	if e := f.s.transact(context.Background(), func(tx *transaction) error {
		r, e := ledger.LoadRecord(context.Background(), tx.conn, f.snap.Approval.DeviceID)
		if e != nil {
			return e
		}
		if r.Floor != 2 {
			t.Fatal("expiry reset capture floor", r.Floor)
		}
		h, e := ledger.LoadHistory(context.Background(), tx.conn, f.snap.Approval.DeviceID, f.consent)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(h)
		if strings.Contains(string(raw), "Private old registration") {
			t.Fatal("expired private row persisted in history")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	if p = historyPage(t, f); p.RetainedCount != 0 || p.ExpiredChanges != 1 {
		t.Fatal("restart revived expired history")
	}
}

func TestSoftwareHistoryReviewExpiredAndResetBaselinesNeverRemove(t *testing.T) {
	for _, reset := range []bool{false, true} {
		name := "expired"
		if reset {
			name = "reset"
		}
		t.Run(name, func(t *testing.T) {
			f := reviewedHistoryLongFixture(t)
			defer f.s.Close()
			f.capture(t, 1, []windowsfullsoftware.Row{softwareRow(1, softwareText("Old baseline"), nil, nil, "64")})
			if reset {
				f.at = f.at.Add(time.Minute)
				f.consent.ChangedAt = f.at
				f.consent.Revision++
				f.consent.GrantID = strings.Repeat("c", 32)
				f.grant(t)
			} else {
				f.at = f.at.Add(windowsfullsoftware.Retention)
			}
			f.capture(t, 2, []windowsfullsoftware.Row{})
			p := historyPage(t, f)
			if p.RetainedCount != 0 || p.Comparison == nil || p.Comparison.Status != "baseline" || p.Comparison.Reason != "no_baseline" {
				t.Fatal("unusable baseline fabricated removals", p)
			}
		})
	}
}

func TestSoftwareHistoryReviewByteQuotaAndByteShortPages(t *testing.T) {
	for _, count := range []int{60, 120} {
		name := "byte-short-page"
		if count == 120 {
			name = "byte-quota-whole-gap"
		}
		t.Run(name, func(t *testing.T) {
			f := newHistoryFixture(t)
			defer f.s.Close()
			f.capture(t, 1, []windowsfullsoftware.Row{})
			f.at = f.at.Add(time.Minute)
			value := strings.Repeat("<", windowsfullsoftware.MaxFieldUTF16)
			rows := make([]windowsfullsoftware.Row, count)
			for i := range rows {
				rows[i] = softwareRow(i+1, &value, &value, &value, "64")
			}
			f.capture(t, 2, rows)
			p := historyPage(t, f)
			if count == 120 {
				if p.RetainedCount != 0 || p.OmittedChanges != uint64(count) || p.Comparison == nil || p.Comparison.Reason != "resource_limit" {
					t.Fatal("byte quota retained a prefix", p)
				}
				current := f.page(t, softwareQuery(), f.at)
				if current.MatchingCount != count {
					t.Fatal("history byte quota blocked inventory")
				}
				return
			}
			q := historyQuery()
			seen := map[string]bool{}
			offset := 0
			for {
				p, e := f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := json.Marshal(p)
				if len(raw) > windowsfullsoftware.MaxPageBytes || len(p.Rows) == 0 || len(p.Rows) >= count || p.Offset != offset {
					t.Fatal("invalid byte-short page", len(raw), len(p.Rows), p.Offset)
				}
				for _, r := range p.Rows {
					if seen[r.ID] {
						t.Fatal("duplicate byte-short row")
					}
					seen[r.ID] = true
				}
				offset += len(p.Rows)
				if p.NextCursor == "" {
					break
				}
				q.Cursor = p.NextCursor
			}
			if len(seen) != count {
				t.Fatal("byte-short paging lost changes", len(seen))
			}
		})
	}
}

func TestSoftwareHistoryReviewOriginalDeadlineAfterConnectionWait(t *testing.T) {
	for _, kind := range []string{"cursor", "retention", "session"} {
		t.Run(kind, func(t *testing.T) {
			f := reviewedHistoryLongFixture(t)
			defer f.s.Close()
			firstAt := f.at
			f.capture(t, 1, []windowsfullsoftware.Row{})
			f.at = f.at.Add(time.Minute)
			f.capture(t, 2, []windowsfullsoftware.Row{softwareRow(1, nil, nil, nil, "64")})
			if kind == "retention" {
				f.at = firstAt.Add(windowsfullsoftware.HistoryRetention - time.Second)
			}
			sessionUntil := f.at.Add(time.Hour)
			if kind == "session" {
				sessionUntil = f.at.Add(time.Second)
			}
			base := WithWindowsFullSoftwareSession(context.Background(), "reviewer", sessionUntil, func() bool { return true })
			p, e := f.s.WindowsSoftwareHistoryPage(base, f.snap.Approval.DeviceID, historyQuery(), f.at)
			if e != nil {
				t.Fatal(e)
			}
			if p.CursorExpiresAt == nil {
				t.Fatal("missing original deadline")
			}
			held, e := f.s.db.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer held.Close()
			waits := f.s.db.Stats().WaitCount
			var now atomic.Int64
			now.Store(f.at.UnixNano())
			ctx := WithWindowsFullSoftwareClock(base, func() time.Time { return time.Unix(0, now.Load()).UTC() })
			done := make(chan error, 1)
			go func() { done <- f.s.RecheckWindowsSoftwareHistoryPage(ctx, p, f.at) }()
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			poll := time.NewTicker(time.Millisecond)
			defer poll.Stop()
			for f.s.db.Stats().WaitCount == waits {
				select {
				case <-poll.C:
				case <-deadline.C:
					t.Fatal("final guard did not wait")
				}
			}
			now.Store(p.CursorExpiresAt.UnixNano())
			if e = held.Close(); e != nil {
				t.Fatal(e)
			}
			select {
			case e = <-done:
				if e == nil {
					t.Fatal("original deadline survived connection wait")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("guard stalled")
			}
		})
	}
}

func TestSoftwareHistoryReviewIncomparableEarlierCaptureDoesNotBlockInventory(t *testing.T) {
	f := newHistoryFixture(t)
	defer f.s.Close()
	grantAt := f.at
	f.at = f.at.Add(2 * time.Minute)
	f.capture(t, 1, []windowsfullsoftware.Row{softwareRow(1, nil, nil, nil, "64")})
	f.at = f.at.Add(time.Minute)
	messages, e := windowsfullsoftware.Build(f.snap.Approval.DeviceID, f.consent, 2, windowsfullsoftware.Capture{StartedAt: grantAt.Add(time.Minute), FinishedAt: grantAt.Add(time.Minute), Rows: []windowsfullsoftware.Row{}, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		if _, e = f.apply(t, m, f.at); e != nil {
			t.Fatal("incomparable capture blocked otherwise valid complete inventory", e)
		}
	}
	p := historyPage(t, f)
	if p.RetainedCount != 0 || p.Comparison == nil || p.Comparison.Status != "gap" || p.Comparison.Reason != "incomparable" {
		t.Fatal("incomparable capture was not explicit gap", p)
	}
	current := f.page(t, softwareQuery(), f.at)
	if current.Complete == nil || current.Complete.Manifest.Sequence != 2 || current.MatchingCount != 0 {
		t.Fatal("inventory did not advance")
	}
}
