package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullsoftware"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fleetHistoryFixture(t *testing.T, n int) fullSoftwareFixture {
	t.Helper()
	f := newHistoryFixture(t)
	f.capture(t, 1, []windowsfullsoftware.Row{})
	f.at = f.at.Add(time.Minute)
	f.capture(t, 2, fleetSoftwareRows(n))
	return f
}
func fleetHistoryQuery() windowsfullsoftware.FleetQuery {
	return windowsfullsoftware.FleetQuery{View: "history"}
}

func TestWindowsFleetSoftwareHistoryPagingAndNoGrantPromotion(t *testing.T) {
	f := fleetHistoryFixture(t, 24)
	defer f.s.Close()
	for k := 2; k <= 7; k++ {
		v := additionalSoftwareIdentity(t, f, k)
		if k == 2 {
			v.consent.HistoryScope = ""
		}
		v.grant(t)
		if k == 3 {
			v.consent.Enabled = false
			v.consent.Revision++
			v.grant(t)
		}
	}
	q := fleetHistoryQuery()
	ctx := fleetSoftwareContext(f.at)
	p, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, q, f.at)
	if e != nil {
		t.Fatal(e)
	}
	if p.TotalDevices != 7 || len(p.Items) != 5 || p.NextCursor == "" || p.Items[0].History.MatchingCount != 24 || len(p.Items[0].History.Rows) != 3 {
		t.Fatalf("bounded fleet %#v %v", p, e)
	}
	if p.Items[1].History.Status != "not_configured" || p.Items[2].History.Status != "disabled" || p.Items[3].History.Status != "awaiting" {
		t.Fatal("scope promotion", p.Items)
	}
	q.Cursor = p.NextCursor
	next, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, q, f.at)
	if e != nil || next.Offset != 5 || len(next.Items) != 2 || next.NextCursor != "" {
		t.Fatal("fleet page", next, e)
	}
	q.Cursor = p.Items[0].DetailCursor
	detail, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, q, f.at)
	if e != nil || detail.Mode != "device" || detail.Items[0].Identity != p.Items[0].Identity || len(detail.Items[0].History.Rows) != 20 || detail.NextCursor == "" {
		t.Fatal("exact detail", detail, e)
	}
	q.Cursor = detail.NextCursor
	last, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, q, f.at)
	if e != nil || last.Offset != 20 || len(last.Items[0].History.Rows) != 4 || last.NextCursor != "" {
		t.Fatal("detail page", last, e)
	}
	for _, item := range []windowsfullsoftware.FleetHistoryItem{p.Items[0], detail.Items[0], last.Items[0]} {
		for _, row := range item.History.Rows {
			if !row.ExpiresAt.Equal(f.at.Add(-time.Minute).Add(windowsfullsoftware.HistoryRetention)) {
				t.Fatal("original expiry extended")
			}
		}
	}
}
func TestWindowsFleetSoftwareHistoryCursorIsolationAndFinalAuthority(t *testing.T) {
	f := fleetHistoryFixture(t, 24)
	defer f.s.Close()
	ctx := fleetSoftwareContext(f.at)
	q := fleetHistoryQuery()
	p, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, q, f.at)
	if e != nil {
		t.Fatal(e)
	}
	q.Cursor = p.Items[0].DetailCursor
	bad := q
	bad.Name = "other"
	if _, e = f.s.WindowsFleetSoftwareHistoryPage(ctx, bad, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("query splice", e)
	}
	other := WithWindowsFullSoftwareSession(context.Background(), "different-session", f.at.Add(time.Hour), func() bool { return true })
	if _, e = f.s.WindowsFleetSoftwareHistoryPage(other, q, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("session splice", e)
	}
	old, e := f.s.WindowsFleetSoftwarePage(ctx, windowsfullsoftware.FleetQuery{Name: "Invented"}, f.at)
	if e != nil {
		t.Fatal(e)
	}
	bad = q
	bad.Cursor = old.Items[0].DetailCursor
	if _, e = f.s.WindowsFleetSoftwareHistoryPage(ctx, bad, f.at); e == nil {
		t.Fatal("inventory cursor accepted as history")
	}
	if _, e = f.s.WindowsFleetSoftwarePage(ctx, windowsfullsoftware.FleetQuery{Name: "Invented", Cursor: q.Cursor}, f.at); e == nil {
		t.Fatal("history cursor accepted as inventory")
	}
	if _, e = f.s.WindowsFleetSoftwarePage(ctx, q, f.at); e == nil {
		t.Fatal("legacy typed API admitted history")
	}
	if e = f.s.RecheckWindowsFleetSoftwareHistoryPage(ctx, p, *p.CursorExpiresAt); e == nil {
		t.Fatal("expired review accepted")
	}
	// A source-generation change invalidates even a same-identity review.
	f.at = f.at.Add(time.Minute)
	f.capture(t, 3, []windowsfullsoftware.Row{})
	if e = f.s.RecheckWindowsFleetSoftwareHistoryPage(fleetSoftwareContext(f.at), p, f.at); e == nil {
		t.Fatal("changed source released")
	}
}
func TestWindowsFleetSoftwareHistoryReadDoesNotSavePruning(t *testing.T) {
	var before []byte
	long := reviewedHistoryLongFixture(t)
	defer long.s.Close()
	long.capture(t, 1, []windowsfullsoftware.Row{})
	long.at = long.at.Add(time.Minute)
	long.capture(t, 2, fleetSoftwareRows(2))
	if e := long.s.transact(context.Background(), func(tx *transaction) error {
		return tx.conn.QueryRowContext(context.Background(), `SELECT body FROM wfw_history WHERE device=?`, long.snap.Approval.DeviceID).Scan(&before)
	}); e != nil {
		t.Fatal(e)
	}
	now := long.at.Add(windowsfullsoftware.HistoryRetention)
	p, e := long.s.WindowsFleetSoftwareHistoryPage(fleetSoftwareContext(now), fleetHistoryQuery(), now)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Items) != 1 || len(p.Items[0].History.Rows) != 0 || p.Items[0].History.ExpiredChanges != 2 {
		t.Fatal("virtual expiry", p)
	}
	var after []byte
	if e := long.s.transact(context.Background(), func(tx *transaction) error {
		return tx.conn.QueryRowContext(context.Background(), `SELECT body FROM wfw_history WHERE device=?`, long.snap.Approval.DeviceID).Scan(&after)
	}); e != nil {
		t.Fatal(e)
	}
	if string(before) != string(after) {
		t.Fatal("fleet read changed durable history")
	}
}
func TestWindowsFleetSoftwareHistoryGrantDisableAndRevocation(t *testing.T) {
	f := fleetHistoryFixture(t, 2)
	defer f.s.Close()
	ctx := fleetSoftwareContext(f.at)
	p, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, fleetHistoryQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	f.consent.Enabled = false
	f.consent.Revision++
	f.grant(t)
	if e = f.s.RecheckWindowsFleetSoftwareHistoryPage(ctx, p, f.at); e == nil {
		t.Fatal("disabled history released")
	}
	now := f.at
	snap, e := f.s.Get(context.Background(), f.snap.InvitationID)
	if e != nil {
		t.Fatal(e)
	}
	ctl := f.f.control(snap, 40)
	ctl.Now = now.Unix()
	if _, e = f.s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	fresh, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, fleetHistoryQuery(), now)
	if e != nil && !errors.Is(e, enrollmentstate.ErrExpired) {
		t.Fatal(e)
	}
	if e == nil && len(fresh.Items) != 0 {
		t.Fatal("revoked identity visible")
	}
}
func TestWindowsFleetSoftwareHistoryGoFixture(t *testing.T) {
	destination := os.Getenv("TRACEBOLT_FLEET_HISTORY_FIXTURE")
	if destination == "" {
		t.Skip("explicit fixture output path not selected")
	}
	f := fleetHistoryFixture(t, 24)
	defer f.s.Close()
	p, e := f.s.WindowsFleetSoftwareHistoryPage(fleetSoftwareContext(f.at), fleetHistoryQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Clean(destination), append(raw, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestWindowsFleetSoftwareHistoryFinalRosterTimeRecheck(t *testing.T) {
	f := fleetHistoryFixture(t, 2)
	defer f.s.Close()
	p, e := f.s.WindowsFleetSoftwareHistoryPage(fleetSoftwareContext(f.at), fleetHistoryQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	ctx := WithWindowsFullSoftwareClock(fleetSoftwareContext(f.at), func() time.Time {
		if calls.Add(1) >= 4 {
			return *p.CursorExpiresAt
		}
		return f.at
	})
	if e = f.s.RecheckWindowsFleetSoftwareHistoryPage(ctx, p, f.at); e == nil {
		t.Fatal("last roster validation released expired history")
	}
	if calls.Load() < 4 {
		t.Fatal("final trusted clock was not sampled after roster", calls.Load())
	}
}
func TestWindowsFleetSoftwareHistoryEscapedByteShortPages(t *testing.T) {
	f := newHistoryFixture(t)
	defer f.s.Close()
	before, after := fleetSoftwareRows(3), fleetSoftwareRows(3)
	a, b := strings.Repeat("<", 512), strings.Repeat(">", 512)
	for i := range before {
		before[i].Name, before[i].Version, before[i].Publisher = &a, &a, &a
		after[i].Name, after[i].Version, after[i].Publisher = &b, &b, &b
		before[i].PublisherQuality, after[i].PublisherQuality = "observed", "observed"
	}
	fixtures := []fullSoftwareFixture{f}
	for k := 2; k <= 6; k++ {
		v := additionalSoftwareIdentity(t, f, k)
		v.grant(t)
		fixtures = append(fixtures, v)
	}
	for _, v := range fixtures {
		v.capture(t, 1, before)
	}
	for _, v := range fixtures {
		v.at = v.at.Add(time.Minute)
		v.capture(t, 2, after)
	}
	now := f.at.Add(time.Minute)
	ctx := fleetSoftwareContext(now)
	q := fleetHistoryQuery()
	first, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, q, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(first)
	if len(first.Items) < 1 || len(first.Items) >= 5 || len(raw) > windowsfullsoftware.MaxPageBytes || first.NextCursor == "" {
		t.Fatalf("escaped byte bound: devices=%d bytes=%d", len(first.Items), len(raw))
	}
	q.Cursor = first.NextCursor
	second, e := f.s.WindowsFleetSoftwareHistoryPage(ctx, q, now)
	if e != nil {
		t.Fatal(e)
	}
	if second.Offset != len(first.Items) || len(first.Items)+len(second.Items) != 6 || second.NextCursor != "" {
		t.Fatal("byte-short paging lost devices", first.Offset, second.Offset, len(second.Items))
	}
	for _, p := range []windowsfullsoftware.FleetHistoryPage{first, second} {
		for _, item := range p.Items {
			if len(item.History.Rows) != 3 || item.History.MatchingCount != 3 || item.History.NextCursor != "" {
				t.Fatal("lost changes or alternate cursor")
			}
		}
	}
}
