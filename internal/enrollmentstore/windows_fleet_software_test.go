package enrollmentstore

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullsoftware"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fleetSoftwareContext(at time.Time) context.Context {
	return WithWindowsFullSoftwareSession(context.Background(), "synthetic-fleet-reader", at.Add(time.Hour), func() bool { return true })
}
func fleetSoftwarePublish(t *testing.T, f fullSoftwareFixture, seq uint64, rows []windowsfullsoftware.Row, at time.Time) {
	t.Helper()
	messages, e := windowsfullsoftware.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsfullsoftware.Capture{StartedAt: at, FinishedAt: at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		if _, e = f.apply(t, m, at); e != nil {
			t.Fatal(e)
		}
	}
}
func fleetSoftwareRows(n int) []windowsfullsoftware.Row {
	rows := make([]windowsfullsoftware.Row, n)
	for i := range rows {
		name, version := "Invented App 東京", fmt.Sprintf("1.%02d", i)
		rows[i] = windowsfullsoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), RegistryView: "64", Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", PublisherQuality: "unavailable"}
	}
	return rows
}

func TestWindowsFleetSoftwareCoveragePagingAndExactDetail(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	rows := fleetSoftwareRows(24)
	rows[23].Version = nil
	rows[23].VersionQuality = "unavailable"
	fleetSoftwarePublish(t, f, 1, rows, f.at)
	fixtures := []fullSoftwareFixture{f}
	for k := 2; k <= 7; k++ {
		fixtures = append(fixtures, additionalSoftwareIdentity(t, f, k))
	}
	// One unconfigured, one disabled, one awaiting, one failed, one complete
	// empty and one real nonmatch. None is silently removed from the roster.
	for _, i := range []int{2, 3, 4, 5, 6} {
		fixtures[i].grant(t)
	}
	fail := fixtures[4].scope()
	fail.Operation = "failure"
	fail.Sequence = 1
	fail.AttemptedAt = &f.at
	fail.Reason = "access_denied"
	if _, e := fixtures[4].apply(t, fail, f.at); e != nil {
		t.Fatal(e)
	}
	fleetSoftwarePublish(t, fixtures[5], 1, []windowsfullsoftware.Row{}, f.at)
	other := fleetSoftwareRows(1)
	name := "Other Product"
	other[0].Name = &name
	fleetSoftwarePublish(t, fixtures[6], 1, other, f.at)
	disabled := fixtures[2]
	disabled.consent.Enabled = false
	disabled.consent.Revision++
	disabled.consent.ChangedAt = f.at.Add(time.Second)
	if _, e := disabled.apply(t, disabled.scope(), f.at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	ctx := fleetSoftwareContext(f.at)
	q := windowsfullsoftware.FleetQuery{Name: "invented app", Version: "1."}
	p, e := f.s.WindowsFleetSoftwarePage(ctx, q, f.at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if p.TotalDevices != 7 || len(p.Items) != 5 || p.NextCursor == "" || p.Mode != "fleet" || p.Offset != 0 {
		t.Fatal("fleet bounds", p)
	}
	first := p.Items[0]
	if first.DeviceID != f.snap.Approval.DeviceID || first.MatchingCount != 23 || first.UnknownCount != 1 || len(first.Rows) != 3 || first.DetailCursor == "" || len(first.Identity) != 64 {
		t.Fatal("matching/unknown coverage", first)
	}
	for i, want := range []string{"ready", "not_configured", "disabled", "awaiting", "unavailable"} {
		if p.Items[i].Status != want {
			t.Fatalf("status %d = %s", i, p.Items[i].Status)
		}
	}
	next := q
	next.Cursor = p.NextCursor
	second, e := f.s.WindowsFleetSoftwarePage(ctx, next, f.at.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if second.Offset != 5 || len(second.Items) != 2 || second.NextCursor != "" || !second.CursorExpiresAt.Equal(*p.CursorExpiresAt) {
		t.Fatal("device continuation", second)
	}
	for _, item := range second.Items {
		if item.Status != "ready" || item.Complete == nil || item.MatchingCount != 0 || len(item.Rows) != 0 {
			t.Fatal("nonmatch distinct from unavailable", item)
		}
	}
	detail := q
	detail.Cursor = first.DetailCursor
	d, e := f.s.WindowsFleetSoftwarePage(ctx, detail, f.at.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if d.Mode != "device" || d.TotalDevices != 7 || len(d.Items) != 1 || len(d.Items[0].Rows) != 20 || d.NextCursor == "" || d.Items[0].Identity != first.Identity || !reflect.DeepEqual(d.Items[0].Complete, first.Complete) {
		t.Fatal("exact detail", d)
	}
	detail.Cursor = d.NextCursor
	last, e := f.s.WindowsFleetSoftwarePage(ctx, detail, f.at.Add(4*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if last.Offset != 20 || len(last.Items[0].Rows) != 3 || last.NextCursor != "" || !last.CursorExpiresAt.Equal(*p.CursorExpiresAt) {
		t.Fatal("detail continuation", last)
	}
	// Empty is observed; nil is unavailable. Unicode matching remains literal.
	q = windowsfullsoftware.FleetQuery{Name: "東京", Version: "1.22"}
	exact, e := f.s.WindowsFleetSoftwarePage(ctx, q, f.at.Add(4*time.Second))
	if e != nil || exact.Items[0].MatchingCount != 1 || exact.Items[0].UnknownCount != 1 {
		t.Fatal("Unicode/version", e, exact)
	}
}

func TestWindowsFleetSoftwareCursorAuthorityAndReadOnly(t *testing.T) {
	for _, kind := range []string{"query", "session", "logout", "expiry", "generation", "disable", "revoke", "tamper", "storage"} {
		t.Run(kind, func(t *testing.T) {
			f := newFullSoftwareFixture(t, "tls")
			defer f.s.Close()
			f.grant(t)
			fleetSoftwarePublish(t, f, 1, fleetSoftwareRows(4), f.at)
			ctx := fleetSoftwareContext(f.at)
			q := windowsfullsoftware.FleetQuery{Name: "App"}
			before, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, softwareQuery(), f.at)
			if e != nil {
				t.Fatal(e)
			}
			p, e := f.s.WindowsFleetSoftwarePage(ctx, q, f.at)
			if e != nil {
				t.Fatal(e)
			}
			after, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, softwareQuery(), f.at)
			if e != nil || !reflect.DeepEqual(before.Complete, after.Complete) || !reflect.DeepEqual(before.LatestAttempt, after.LatestAttempt) {
				t.Fatal("lookup changed source", e)
			}
			q.Cursor = p.Items[0].DetailCursor
			at := f.at.Add(time.Second)
			switch kind {
			case "query":
				q.Version = "1."
			case "session":
				ctx = WithWindowsFullSoftwareSession(context.Background(), "different-reader", f.at.Add(time.Hour), func() bool { return true })
			case "logout":
				ctx = WithWindowsFullSoftwareSession(context.Background(), "synthetic-fleet-reader", f.at.Add(time.Hour), func() bool { return false })
			case "expiry":
				at = *p.CursorExpiresAt
			case "generation":
				fleetSoftwarePublish(t, f, 2, fleetSoftwareRows(4), at)
			case "disable":
				f.consent.Enabled = false
				f.consent.Revision++
				f.consent.ChangedAt = at
				if _, e = f.apply(t, f.scope(), at); e != nil {
					t.Fatal(e)
				}
			case "revoke":
				ctl := f.f.control(f.snap, 20)
				ctl.Now = at.Unix()
				if _, e = f.s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); e != nil {
					t.Fatal(e)
				}
			case "tamper":
				q.Cursor = strings.Repeat("a", len(q.Cursor))
			case "storage":
				if _, e = f.s.db.Exec(`UPDATE wfw_rows SET search=''`); e != nil {
					t.Fatal(e)
				}
			}
			out, e := f.s.WindowsFleetSoftwarePage(ctx, q, at)
			if e == nil || !reflect.DeepEqual(out, windowsfullsoftware.FleetPage{}) {
				t.Fatal("stale authority or corrupt data disclosed", e, out)
			}
			if kind != "query" && kind != "tamper" && kind != "storage" {
				if e = f.s.RecheckWindowsFleetSoftwarePage(ctx, p, at); e == nil {
					t.Fatal("final response guard accepted old authority")
				}
			}
		})
	}
}

func TestWindowsFleetSoftwareFinalWaitResamplesExpiry(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	fleetSoftwarePublish(t, f, 1, fleetSoftwareRows(1), f.at)
	ctx := fleetSoftwareContext(f.at)
	p, e := f.s.WindowsFleetSoftwarePage(ctx, windowsfullsoftware.FleetQuery{Name: "App"}, f.at)
	if e != nil {
		t.Fatal(e)
	}
	held, e := f.s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	waits := f.s.db.Stats().WaitCount
	var now atomic.Int64
	now.Store(f.at.Unix())
	ctx = WithWindowsFullSoftwareClock(ctx, func() time.Time { return time.Unix(now.Load(), 0).UTC() })
	done := make(chan error, 1)
	go func() { done <- f.s.RecheckWindowsFleetSoftwarePage(ctx, p, f.at) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for f.s.db.Stats().WaitCount == waits {
		select {
		case <-poll.C:
		case <-deadline.C:
			t.Fatal("guard did not wait")
		}
	}
	now.Store(p.CursorExpiresAt.Unix())
	if e = held.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if !errors.Is(e, windowsfullsoftware.ErrConflict) {
			t.Fatal("guard used old clock", e)
		}
	case <-deadline.C:
		t.Fatal("guard stuck")
	}
}

func TestWindowsFleetSoftwareAbsentSchemaAndSessionCannotGrant(t *testing.T) {
	_, s, _, _, _ := activeWindowsStore(t, "tls")
	defer s.Close()
	at := time.Unix(testNow+10, 0).UTC()
	q := windowsfullsoftware.FleetQuery{Name: "App"}
	ctx := fleetSoftwareContext(at)
	p, e := s.WindowsFleetSoftwarePage(ctx, q, at)
	if e != nil || p.Status != "not_configured" || len(p.Items) != 0 || p.TotalDevices != 0 || p.CursorExpiresAt != nil {
		t.Fatal("missing schema not explicit", e, p)
	}
	if _, e = s.WindowsFleetSoftwarePage(context.Background(), q, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("sessionless fleet read", e)
	}
	if e = s.InitializeWindowsFullSoftware(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = s.RecheckWindowsFleetSoftwarePage(ctx, p, at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("schema changed after prepare", e)
	}
	for _, bad := range []windowsfullsoftware.FleetQuery{{}, {Name: strings.Repeat("a", 257)}, {Version: "\x00"}} {
		if _, e = s.WindowsFleetSoftwarePage(ctx, bad, at); !errors.Is(e, windowsfullsoftware.ErrInvalid) {
			t.Fatal("invalid query accepted", e)
		}
	}
}

func TestWindowsFleetSoftwareMaximumEscapedQueryKeepsBoundedCursor(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	fleetSoftwarePublish(t, f, 1, fleetSoftwareRows(1), f.at)
	ctx := fleetSoftwareContext(f.at)
	for _, escaped := range []string{"<", "\u0001"} {
		q := windowsfullsoftware.FleetQuery{Name: strings.Repeat(escaped, 256), Version: strings.Repeat(escaped, 256)}
		p, err := f.s.WindowsFleetSoftwarePage(ctx, q, f.at)
		if err != nil || len(p.Items) != 1 || len(p.Items[0].DetailCursor) == 0 || len(p.Items[0].DetailCursor) > windowsfullsoftware.MaxCursorBytes {
			t.Fatal("valid escaped filter inflated cursor", err)
		}
		q.Cursor = p.Items[0].DetailCursor
		detail, err := f.s.WindowsFleetSoftwarePage(ctx, q, f.at)
		if err != nil || detail.Mode != "device" || detail.Items[0].MatchingCount != 0 {
			t.Fatal("bounded digest did not bind exact filters", err)
		}
	}
}
