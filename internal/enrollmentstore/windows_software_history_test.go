package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/windowsfullsoftware"
	ledger "localrmm/internal/windowsfullsoftwareledger"
	"strings"
	"testing"
	"time"
)

func historyQuery() windowsfullsoftware.Query {
	return windowsfullsoftware.Query{Sort: "observed-desc", Limit: 100}
}
func historyPage(t *testing.T, f fullSoftwareFixture) windowsfullsoftware.HistoryPage {
	t.Helper()
	p, e := f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, historyQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func newHistoryFixture(t *testing.T) fullSoftwareFixture {
	f := newFullSoftwareFixture(t, "tls")
	f.consent.HistoryScope = windowsfullsoftware.HistoryScope
	f.grant(t)
	return f
}
func TestSoftwareHistoryConsentBaselineChangesSearchPagingAndRetry(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer func() { f.s.Close() }()
	f.grant(t)
	f.capture(t, 1, []windowsfullsoftware.Row{softwareRow(1, softwareText("pregrant"), softwareText("1"), nil, "64")})
	if p := historyPage(t, f); p.Status != "not_configured" || len(p.Rows) != 0 {
		t.Fatal("legacy grant promoted")
	}
	f.at = f.at.Add(time.Minute)
	f.consent.HistoryScope = windowsfullsoftware.HistoryScope
	f.consent.GrantID = strings.Repeat("c", 32)
	f.consent.Revision++
	f.consent.ChangedAt = f.at
	f.grant(t)
	old := []windowsfullsoftware.Row{softwareRow(1, softwareText("Same 東京"), softwareText("1"), nil, "64"), softwareRow(2, softwareText("Same 東京"), softwareText("1"), nil, "32"), softwareRow(3, nil, nil, nil, "64")}
	f.capture(t, 2, old)
	if p := historyPage(t, f); p.Comparison == nil || p.Comparison.Status != "baseline" || len(p.Rows) != 0 {
		t.Fatal("pregrant baseline reused")
	}
	before := f.at
	f.at = f.at.Add(time.Minute)
	newRows := []windowsfullsoftware.Row{softwareRow(1, softwareText("Same 東京"), softwareText("0.9"), nil, "64"), softwareRow(3, nil, softwareText("known now"), nil, "64"), softwareRow(4, softwareText("added"), nil, nil, "64")}
	messages := f.capture(t, 3, newRows)
	p := historyPage(t, f)
	if p.Status != "ready" || p.Comparison.Status != "compared" || p.MatchingCount != 3 || p.RetainedCount != 3 {
		t.Fatal("diff", p)
	}
	for _, row := range p.Rows {
		if !row.ExpiresAt.Equal(before.Add(windowsfullsoftware.HistoryRetention)) {
			t.Fatal("retention refreshed")
		}
	}
	raw, _ := json.Marshal(p)
	if _, e := f.apply(t, messages[len(messages)-1], f.at); e != nil {
		t.Fatal(e)
	}
	retry, _ := json.Marshal(historyPage(t, f))
	if string(raw) != string(retry) {
		t.Fatal("retry duplicated or retimed history")
	}
	q := historyQuery()
	q.Limit = 1
	first, e := f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
	if e != nil || first.NextCursor == "" {
		t.Fatal("cursor", e)
	}
	q.Cursor = first.NextCursor
	next, e := f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
	if e != nil || next.Offset != 1 {
		t.Fatal("page", e)
	}
	q.Cursor = ""
	q.Search = "東京"
	found, e := f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
	if e != nil || found.MatchingCount != 2 {
		t.Fatal("literal full search", e)
	}
	q.Cursor = first.NextCursor
	if _, e = f.s.WindowsSoftwareHistoryPage(context.Background(), f.snap.Approval.DeviceID, q, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("changed query cursor", e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	if p = historyPage(t, f); p.RetainedCount != 3 {
		t.Fatal("restart lost history")
	}
	f.at = f.at.Add(time.Minute)
	f.consent.Revision++
	f.consent.Enabled = false
	f.consent.HistoryScope = ""
	f.consent.ChangedAt = f.at
	f.grant(t)
	if e = f.s.RecheckWindowsSoftwareHistoryPage(context.Background(), p, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("revoked history disclosed", e)
	}
}
func TestSoftwareHistoryFailedPartialAndMissingBaselineNeverRemove(t *testing.T) {
	f := newHistoryFixture(t)
	defer func() { f.s.Close() }()
	rows := []windowsfullsoftware.Row{softwareRow(1, softwareText("retained"), nil, nil, "64")}
	f.capture(t, 1, rows)
	f.at = f.at.Add(time.Minute)
	at := f.at
	failure := windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 2, AttemptedAt: &at, Reason: "access_denied"}
	if _, e := f.apply(t, failure, f.at); e != nil {
		t.Fatal(e)
	}
	if p := historyPage(t, f); len(p.Rows) != 0 || p.LatestAttempt.Status != "source_failed" {
		t.Fatal("failure fabricated removal")
	}
	f.at = f.at.Add(time.Minute)
	f.capture(t, 3, []windowsfullsoftware.Row{})
	p := historyPage(t, f)
	if len(p.Rows) != 0 || p.Comparison.Status != "gap" || p.Comparison.Reason != "source_gap" || p.GapCount != 1 {
		t.Fatal("failure bridged", p)
	}
	f.at = f.at.Add(time.Minute)
	messages := f.messages(t, 4, 150, f.at)
	if _, e := f.apply(t, messages[0], f.at); e != nil {
		t.Fatal(e)
	}
	if p = historyPage(t, f); len(p.Rows) != 0 || p.Comparison.Reason != "source_gap" {
		t.Fatal("partial promoted")
	}
}
func TestSoftwareHistoryQuotaRejectsWholeDiffWithoutBlockingInventory(t *testing.T) {
	f := newHistoryFixture(t)
	defer func() { f.s.Close() }()
	f.capture(t, 1, []windowsfullsoftware.Row{})
	f.at = f.at.Add(time.Minute)
	rows := make([]windowsfullsoftware.Row, 1025)
	for i := range rows {
		rows[i] = softwareRow(i+1, nil, nil, nil, "64")
	}
	f.capture(t, 2, rows)
	p := historyPage(t, f)
	if len(p.Rows) != 0 || p.OmittedChanges != 1025 || p.Comparison.Reason != "resource_limit" || p.GapCount != 1 {
		t.Fatal("quota prefix", p)
	}
	current := f.page(t, softwareQuery(), f.at)
	if current.Status != "ready" || current.MatchingCount != 1025 {
		t.Fatal("history blocked current inventory")
	}
	f.at = f.at.Add(time.Minute)
	f.capture(t, 3, rows)
	p = historyPage(t, f)
	if p.Comparison.Status != "compared" || p.Comparison.ObservedChanges != 0 || p.OmittedChanges != 1025 {
		t.Fatal("next baseline missing")
	}
	ctx := context.Background()
	if e := f.s.transact(ctx, func(tx *transaction) error {
		var historyCount int64
		if e := tx.conn.QueryRowContext(ctx, `SELECT count(*) FROM wfw_history`).Scan(&historyCount); e != nil {
			return e
		}
		if historyCount != 1 {
			return fmt.Errorf("history reservation missing")
		}
		var held int64
		if e := tx.conn.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0) FROM wfw_generations`).Scan(&held); e != nil {
			return e
		}
		if e := ledger.Budgets(ctx, tx.conn, ledger.MaxGlobalBytes-held-windowsfullsoftware.MaxHistoryBytes); e != nil {
			return e
		}
		if e := ledger.Budgets(ctx, tx.conn, ledger.MaxGlobalBytes-held-windowsfullsoftware.MaxHistoryBytes+1); !errors.Is(e, windowsfullsoftware.ErrBudget) {
			return fmt.Errorf("history not inside global budget: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestSoftwareHistorySessionAndResponseExpiryFence(t *testing.T) {
	f := newHistoryFixture(t)
	defer func() { f.s.Close() }()
	f.capture(t, 1, []windowsfullsoftware.Row{})
	f.at = f.at.Add(time.Minute)
	f.capture(t, 2, []windowsfullsoftware.Row{softwareRow(1, nil, nil, nil, "64"), softwareRow(2, nil, nil, nil, "64")})
	active := true
	ctx := WithWindowsFullSoftwareSession(context.Background(), "owner-a", f.at.Add(time.Hour), func() bool { return active })
	q := historyQuery()
	q.Limit = 1
	p, e := f.s.WindowsSoftwareHistoryPage(ctx, f.snap.Approval.DeviceID, q, f.at)
	if e != nil {
		t.Fatal(e)
	}
	other := WithWindowsFullSoftwareSession(context.Background(), "owner-b", f.at.Add(time.Hour), func() bool { return true })
	q.Cursor = p.NextCursor
	if _, e = f.s.WindowsSoftwareHistoryPage(other, f.snap.Approval.DeviceID, q, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("cross-session cursor", e)
	}
	active = false
	if e = f.s.RecheckWindowsSoftwareHistoryPage(ctx, p, f.at); e == nil {
		t.Fatal("logout disclosed")
	}
	if e = ValidateWindowsSoftwareHistoryPageAt(p, *p.CursorExpiresAt); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("deadline renewed", e)
	}
}
