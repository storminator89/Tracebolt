package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/alarmdelivery"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func seriesOperation(at time.Time, n int) string {
	return fmt.Sprintf("wms_%d_%032x", at.UnixMilli(), n)
}
func seriesDates(at time.Time, n int) []WindowsMaintenanceSeriesDates {
	out := []WindowsMaintenanceSeriesDates{}
	for i := 0; i < n; i++ {
		start := at.Add(time.Hour + time.Duration(i)*7*24*time.Hour)
		out = append(out, WindowsMaintenanceSeriesDates{start, start.Add(time.Hour)})
	}
	return out
}
func createSeries(t *testing.T, s *Store, target WindowsMaintenanceTarget, revision uint64, at time.Time, n int) WindowsMaintenanceSeriesReceipt {
	t.Helper()
	r, e := s.ChangeWindowsMaintenanceSeries(context.Background(), target, revision, "create", 0, seriesDates(at, n), "planned-work", seriesOperation(at, int(revision+1)), at.Truncate(time.Millisecond), at.Add(time.Minute), func() time.Time { return at }, maintenanceGuard)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func changeSeries(t *testing.T, s *Store, target WindowsMaintenanceTarget, revision uint64, action string, id uint64, at time.Time) WindowsMaintenanceSeriesReceipt {
	t.Helper()
	r, e := s.ChangeWindowsMaintenanceSeries(context.Background(), target, revision, action, id, nil, "", seriesOperation(at, int(revision+1)), at.Truncate(time.Millisecond), at.Add(time.Minute), func() time.Time { return at }, maintenanceGuard)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestWindowsMaintenanceSeriesAtomicLifecycleAndLegacyCompatibility(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "series.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	target := maintenanceFixtureTarget(1, "disk")
	now := contactAt
	var tables, version int
	s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'windows_maintenance_series%'`).Scan(&tables)
	if tables != 0 {
		t.Fatal("opening opted into series")
	}
	r := createSeries(t, s, target, 0, now, 4)
	if len(r.OccurrenceIDs) != 4 || r.Revision != 1 {
		t.Fatal(r)
	}
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 3 {
		t.Fatal(version)
	}
	actual, found, e := s.WindowsMaintenanceSeriesReceipt(ctx, r.OperationID)
	if e != nil || !found || !reflect.DeepEqual(r, actual) {
		t.Fatal(actual, found, e)
	}
	// Arbitrary sibling cancellation is independent of chronological history.
	changeSeries(t, s, target, 1, "cancel", 3, now.Add(time.Second))
	changeSeries(t, s, target, 2, "cancel", 2, now.Add(2*time.Second))
	state, e := s.WindowsMaintenanceSeries(ctx, func() time.Time { return now.Add(time.Hour) })
	if e != nil || len(state) != 1 || len(state[0].Occurrences) != 4 || state[0].Occurrences[1].CancelledAt == nil || state[0].Occurrences[2].CancelledAt == nil {
		t.Fatal(state, e)
	}
	changeSeries(t, s, target, 3, "end", 1, now.Add(time.Hour+time.Nanosecond))
	state, e = s.WindowsMaintenanceSeries(ctx, func() time.Time { return now.Add(time.Hour + time.Second) })
	if e != nil || !state[0].Occurrences[0].EndsAt.Equal(now.Add(2*time.Hour)) {
		t.Fatal(state, e)
	}
	// A different domain's legacy mutation must never reset the compatibility marker.
	later := now.Add(2 * time.Hour)
	scheduleWindows(t, s, maintenanceFixtureTarget(1, "cpu"), 0, later, later.Add(time.Hour), later.Add(2*time.Hour))
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 3 {
		t.Fatal("legacy downgraded", version)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	state, e = s.WindowsMaintenanceSeries(ctx, func() time.Time { return later })
	if e != nil || state[0].Revision != 4 || state[0].LastOccurrenceID != 4 {
		t.Fatal(state, e)
	}
	replacement := target
	replacement.InvitationID = "invite_" + strings.Repeat("e", 32)
	replacement.CertificateHash = strings.Repeat("f", 64)
	createSeries(t, s, replacement, 0, later, 2)
	state, e = s.WindowsMaintenanceSeries(ctx, func() time.Time { return later })
	if e != nil || len(state) != 2 {
		t.Fatal("replacement inherited or erased", state, e)
	}
}
func TestWindowsMaintenanceSeriesReservationsAndAtomicFailure(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	at := contactAt
	target := maintenanceFixtureTarget(1, "disk")
	createSeries(t, s, target, 0, at, 2)
	// Reservations continue through gaps; unrelated notification domains remain free.
	gap := at.Add(3 * 24 * time.Hour)
	for _, domain := range []string{"all", "disk"} {
		other := maintenanceFixtureTarget(1, domain)
		if _, e := s.ChangeWindowsMaintenance(ctx, other, 0, gap.Add(time.Hour), "other", 0, func() time.Time { return gap }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
			t.Fatal(domain, e)
		}
		if _, e := s.ChangeWindowsMaintenanceSchedule(ctx, other, 0, "schedule", 0, gap.Add(time.Hour), gap.Add(2*time.Hour), "other", func() time.Time { return gap }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
			t.Fatal(domain, e)
		}
	}
	maintenanceStart(t, s, maintenanceFixtureTarget(1, "cpu"), 0, gap)
	var before string
	s.db.QueryRow(`SELECT body FROM windows_maintenance_series`).Scan(&before)
	_, e := s.ChangeWindowsMaintenanceSeries(ctx, target, 1, "cancel", 2, nil, "", seriesOperation(gap, 99), gap, gap.Add(time.Minute), func() time.Time { return gap }, func(time.Time, time.Time) error { return ErrWindowsMaintenanceConflict })
	if !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal(e)
	}
	var after string
	s.db.QueryRow(`SELECT body FROM windows_maintenance_series`).Scan(&after)
	if before != after {
		t.Fatal("failed guard changed ledger")
	}
	_, found, e := s.WindowsMaintenanceSeriesReceipt(ctx, seriesOperation(gap, 99))
	if e != nil || found {
		t.Fatal("failed operation receipt", found, e)
	}
}
func TestWindowsMaintenanceSeriesStrictBoundsAndFirstCommitRollback(t *testing.T) {
	cases := []struct {
		name string
		edit func([]WindowsMaintenanceSeriesDates) []WindowsMaintenanceSeriesDates
	}{
		{"one", func(d []WindowsMaintenanceSeriesDates) []WindowsMaintenanceSeriesDates { return d[:1] }},
		{"five", func(d []WindowsMaintenanceSeriesDates) []WindowsMaintenanceSeriesDates {
			return append(d, d[0], d[0], d[0])
		}},
		{"weekly", func(d []WindowsMaintenanceSeriesDates) []WindowsMaintenanceSeriesDates {
			d[1].StartsAt = d[1].StartsAt.Add(time.Nanosecond)
			return d
		}},
		{"duration", func(d []WindowsMaintenanceSeriesDates) []WindowsMaintenanceSeriesDates {
			d[1].EndsAt = d[1].EndsAt.Add(time.Minute)
			return d
		}},
		{"too soon", func(d []WindowsMaintenanceSeriesDates) []WindowsMaintenanceSeriesDates {
			for i := range d {
				d[i].StartsAt = d[i].StartsAt.Add(-time.Hour)
				d[i].EndsAt = d[i].EndsAt.Add(-time.Hour)
			}
			return d
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := contactStore(t)
			at := contactAt
			_, e := s.ChangeWindowsMaintenanceSeries(context.Background(), maintenanceFixtureTarget(1, "all"), 0, "create", 0, tc.edit(seriesDates(at, 2)), "other", seriesOperation(at, 1), at, at.Add(time.Minute), func() time.Time { return at }, maintenanceGuard)
			if e == nil {
				t.Fatal("accepted invalid series")
			}
			var v, n int
			s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
			s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'windows_maintenance_series%'`).Scan(&n)
			if v != 1 || n != 0 {
				t.Fatal("partial first commit", v, n)
			}
		})
	}
	s := contactStore(t)
	at := contactAt
	calls := 0
	_, e := s.ChangeWindowsMaintenanceSeries(context.Background(), maintenanceFixtureTarget(1, "all"), 0, "create", 0, seriesDates(at, 2), "other", seriesOperation(at, 1), at, at.Add(time.Minute), func() time.Time { return at }, func(time.Time, time.Time) error {
		calls++
		if calls == 2 {
			at = at.Add(2 * time.Minute)
		}
		return nil
	})
	if !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("expired final review", e)
	}
	var v, n int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'windows_maintenance_series%'`).Scan(&n)
	if v != 1 || n != 0 {
		t.Fatal("partial failed final commit", v, n)
	}
}
func TestWindowsMaintenanceSeriesStartupRejectsMissingOrMalformedUsedState(t *testing.T) {
	for _, q := range []string{`DROP TABLE windows_maintenance_series_used`, `DROP TABLE windows_maintenance_series`, `DROP TABLE windows_maintenance_series_receipts`, `DELETE FROM windows_maintenance_series_used`, `DELETE FROM windows_maintenance_series`, `UPDATE windows_maintenance_series SET body='{}'`, `PRAGMA user_version=2`} {
		t.Run(q, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "broken.db")
			s, e := Open(path)
			if e != nil {
				t.Fatal(e)
			}
			createSeries(t, s, maintenanceFixtureTarget(1, "all"), 0, contactAt, 2)
			if _, e = s.db.Exec(q); e != nil {
				t.Fatal(e)
			}
			s.Close()
			if reopened, e := Open(path); e == nil {
				reopened.Close()
				t.Fatal("repaired/adopted missing used state")
			}
		})
	}
}
func TestWindowsMaintenanceSeriesCombinedRetentionAndSafeReceiptExpiry(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "disk")
	at := contactAt
	revision := uint64(0)
	for batch := 0; batch < 4; batch++ {
		r := createSeries(t, s, target, revision, at, 4)
		revision = r.Revision
		for _, id := range r.OccurrenceIDs {
			at = at.Add(time.Second)
			r = changeSeries(t, s, target, revision, "cancel", id, at)
			revision = r.Revision
		}
	}
	_, e := s.ChangeWindowsMaintenanceSchedule(ctx, target, 0, "schedule", 0, at.Add(time.Hour), at.Add(2*time.Hour), "other", func() time.Time { return at }, maintenanceGuard)
	if !errors.Is(e, ErrLimit) {
		t.Fatal("legacy ignored series slots", e)
	}
	at = at.Add(30 * 24 * time.Hour)
	states, e := s.WindowsMaintenanceSeries(ctx, func() time.Time { return at })
	if e != nil || len(states[0].Occurrences) != 4 || states[0].RetiredOccurrences != 12 || states[0].LastOccurrenceID != 16 {
		t.Fatal(states, e)
	}
	r := createSeries(t, s, target, revision, at, 2)
	if r.OccurrenceIDs[0] != 17 {
		t.Fatal("ID reused", r)
	}
	_, found, e := s.WindowsMaintenanceSeriesReceipt(ctx, seriesOperation(contactAt, 1))
	if e != nil || found {
		t.Fatal("receipt not safely retired", found, e)
	}
	_, e = s.ChangeWindowsMaintenanceSeries(ctx, target, r.Revision, "cancel", 17, nil, "", seriesOperation(contactAt, 1), contactAt, contactAt.Add(time.Minute), func() time.Time { return at }, maintenanceGuard)
	if !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("expired operation reused", e)
	}
	// A canonical but malformed independent ledger is rejected, not serial-v1 repaired.
	raw, _ := json.Marshal(states[0])
	var invalid map[string]any
	json.Unmarshal(raw, &invalid)
	invalid["lastOccurrenceId"] = float64(15)
	bad, _ := json.Marshal(invalid)
	s.db.Exec(`UPDATE windows_maintenance_series SET body=?`, bad)
	if _, e = s.WindowsMaintenanceSeries(ctx, func() time.Time { return at }); e == nil {
		t.Fatal("malformed floor accepted")
	}
}
func TestWindowsMaintenanceSeriesNotificationAdmissionMissedWindowsAndFinalGuard(t *testing.T) {
	for _, mode := range []string{"source", "missed", "final"} {
		t.Run(mode, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			configureAlarm(t, s, &alarmBinding)
			notificationEnable(t, s, "disk")
			at := contactAt
			dates := seriesDates(at, 2)
			dates[0] = WindowsMaintenanceSeriesDates{at.Add(time.Minute), at.Add(5 * time.Minute)}
			dates[1] = WindowsMaintenanceSeriesDates{dates[0].StartsAt.Add(7 * 24 * time.Hour), dates[0].EndsAt.Add(7 * 24 * time.Hour)}
			if mode != "source" {
				capacityOpen(t, s)
			}
			if mode == "final" {
				dates[0].StartsAt = at.Add(2 * time.Minute)
				dates[1].StartsAt = dates[0].StartsAt.Add(7 * 24 * time.Hour)
			}
			if _, e := s.ChangeWindowsMaintenanceSeries(ctx, maintenanceFixtureTarget(1, "disk"), 0, "create", 0, dates, "other", seriesOperation(at, 1), at, at.Add(time.Minute), func() time.Time { return at }, maintenanceGuard); e != nil {
				t.Fatal(e)
			}
			if mode == "source" {
				state := capacityOpen(t, s)
				if len(state.Incidents) == 0 || notificationCounts(t, s).Suppressed != 1 {
					t.Fatal("source/evidence changed")
				}
				if _, e := s.WindowsMaintenanceSeries(ctx, func() time.Time { return at.Add(30 * time.Second) }); !errors.Is(e, ErrWindowsMaintenanceConflict) {
					t.Fatal("source lost floor", e)
				}
				return
			}
			if mode == "missed" {
				if _, e := s.WindowsMaintenanceSeries(ctx, func() time.Time { return at.Add(time.Hour) }); e != nil {
					t.Fatal(e)
				}
				if notificationCounts(t, s).Suppressed != 1 {
					t.Fatal("backlog escaped")
				}
				return
			}
			now := at.Add(2*time.Minute - time.Millisecond)
			candidate, e := s.NextWindowsNotification(ctx, alarmBinding, now)
			if e != nil || candidate == nil {
				t.Fatal(candidate, e)
			}
			calls := 0
			attempt, e := s.ClaimWindowsNotification(ctx, alarmBinding, *candidate, capacityInput(1, 60, 95), contactAt, func() time.Time { return now }, func(time.Time) error {
				calls++
				if calls == 3 {
					now = at.Add(2 * time.Minute)
				}
				return nil
			})
			if attempt != nil {
				t.Fatal("dispatch crossed start", e)
			}
		})
	}
}
func TestWindowsMaintenanceSeriesCompleteInflightTruth(t *testing.T) {
	for _, outcome := range []alarmdelivery.Outcome{alarmdelivery.Accepted, alarmdelivery.Uncertain, alarmdelivery.Retryable} {
		t.Run(string(outcome), func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			configureAlarm(t, s, &alarmBinding)
			in := completeNotificationConfigure(t, s, "FixtureService")
			completeNotificationEnable(t, s, in)
			completeNotificationOpen(t, s, &in)
			at := contactAt.Add(180 * time.Second)
			attempt := completeNotificationClaim(t, s, in, at)
			if attempt == nil {
				t.Fatal("missing attempt")
			}
			createSeries(t, s, maintenanceFixtureTarget(1, "service"), 0, at, 2)
			later := at.Add(3 * time.Hour)
			if _, e := s.WindowsMaintenanceSeries(ctx, func() time.Time { return later }); e != nil {
				t.Fatal(e)
			}
			notificationComplete(t, s, attempt, outcome, later)
			state, _, _ := completeNotificationRow(t, s, attempt.Payload.EventID)
			want := string(outcome)
			if outcome == alarmdelivery.Retryable {
				want = "suppressed"
			}
			if state != want {
				t.Fatal(state, want)
			}
		})
	}
}

func TestWindowsMaintenanceSeriesRejectsMissingPendingPrefixAndRetainsNominalHorizon(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "disk")
	at := contactAt
	createSeries(t, s, target, 0, at, 4)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	states, e := readWindowsMaintenanceSeries(ctx, tx)
	tx.Rollback()
	if e != nil {
		t.Fatal(e)
	}
	original := states[0]
	missing := original
	missing.Occurrences = missing.Occurrences[1:]
	missing.ActionRevisions = missing.ActionRevisions[1:]
	missing.RetiredOccurrences = 1
	if missing.valid() {
		t.Fatal("missing pending prefix became retired")
	}
	revision := uint64(1)
	for _, id := range []uint64{4, 2, 3, 1} {
		at = at.Add(time.Second)
		changeSeries(t, s, target, revision, "cancel", id, at)
		revision++
	}
	r := createSeries(t, s, target, revision, at, 4)
	revision = r.Revision
	for _, id := range r.OccurrenceIDs {
		at = at.Add(time.Second)
		changeSeries(t, s, target, revision, "cancel", id, at)
		revision++
	}
	states, e = s.WindowsMaintenanceSeries(ctx, func() time.Time { return at.Add(25 * time.Hour) })
	if e != nil || len(states[0].Occurrences) != 8 || states[0].RetiredOccurrences != 0 {
		t.Fatal("cancelled future dates reclaimed before nominal horizon", states, e)
	}
	states, e = s.WindowsMaintenanceSeries(ctx, func() time.Time { return at.Add(30 * 24 * time.Hour) })
	if e != nil || len(states[0].Occurrences) != 4 || states[0].RetiredOccurrences != 4 || states[0].RetiredThroughAt == nil || !states[0].RetiredThroughAt.Equal(original.Occurrences[3].EndsAt) {
		t.Fatal("retirement proof", states, e)
	}
	// An arbitrary middle deletion cannot be made contiguous by adjusting count.
	missing = states[0]
	missing.Occurrences = append(append([]WindowsMaintenanceSeriesOccurrence{}, missing.Occurrences[:1]...), missing.Occurrences[2:]...)
	missing.ActionRevisions = append(append([]uint64{}, missing.ActionRevisions[:1]...), missing.ActionRevisions[2:]...)
	missing.RetiredOccurrences++
	if missing.valid() {
		t.Fatal("middle missing member accepted")
	}
}
func TestWindowsMaintenanceSeriesReceiptRejectsUnrelatedCanonicalOutcome(t *testing.T) {
	for _, mutation := range []string{"future IDs", "different create revision", "wrong action"} {
		t.Run(mutation, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			r := createSeries(t, s, maintenanceFixtureTarget(1, "all"), 0, contactAt, 2)
			switch mutation {
			case "future IDs":
				r.OccurrenceIDs = []uint64{3, 4}
			case "different create revision":
				r.Revision = 2
			case "wrong action":
				r.Action = "cancel"
				r.OccurrenceIDs = r.OccurrenceIDs[:1]
			}
			raw, _ := json.Marshal(r)
			if _, e := s.db.Exec(`UPDATE windows_maintenance_series_receipts SET body=? WHERE operation=?`, raw, r.OperationID); e != nil {
				t.Fatal(e)
			}
			if _, _, e := s.WindowsMaintenanceSeriesReceipt(ctx, r.OperationID); e == nil {
				t.Fatal("canonical unrelated receipt accepted")
			}
		})
	}
}
func TestWindowsMaintenanceSeriesCapacityCountsDistinctLegacyAndSeriesTargets(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	at := contactAt
	for n := 1; n <= 150; n++ {
		scheduleWindows(t, s, maintenanceFixtureTarget(n, "disk"), 0, at, at.Add(time.Minute), at.Add(2*time.Minute))
	}
	later := at.Add(3 * time.Minute)
	// Existing exact target counts once, even when present in both ledgers.
	createSeries(t, s, maintenanceFixtureTarget(1, "disk"), 0, later, 2)
	_, e := s.ChangeWindowsMaintenanceSeries(ctx, maintenanceFixtureTarget(151, "disk"), 0, "create", 0, seriesDates(later, 2), "other", seriesOperation(later, 999), later, later.Add(time.Minute), func() time.Time { return later }, maintenanceGuard)
	if !errors.Is(e, ErrLimit) {
		t.Fatal("distinct target cap", e)
	}
}
func TestWindowsMaintenanceSeriesCapacityIncludesLegacyOccurrences(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	at := contactAt
	target := maintenanceFixtureTarget(1, "disk")
	for i := uint64(0); i < 15; i++ {
		scheduleWindows(t, s, target, i, at, at.Add(time.Minute), at.Add(2*time.Minute))
		at = at.Add(3 * time.Minute)
	}
	_, e := s.ChangeWindowsMaintenanceSeries(ctx, target, 0, "create", 0, seriesDates(at, 2), "other", seriesOperation(at, 1), at, at.Add(time.Minute), func() time.Time { return at }, maintenanceGuard)
	if !errors.Is(e, ErrLimit) {
		t.Fatal("series ignored legacy occurrence slots", e)
	}
	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 2 {
		t.Fatal("failed capacity advanced compatibility", version)
	}
}

func TestWindowsMaintenanceSeriesReadRetainsLegacyClockFloor(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "disk")
	at := contactAt
	scheduleWindows(t, s, target, 0, at, at.Add(time.Minute), at.Add(time.Hour))
	if _, e := s.WindowsMaintenanceSeries(ctx, func() time.Time { return at.Add(2 * time.Minute) }); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ChangeWindowsMaintenanceSchedule(ctx, target, 1, "cancel", 1, time.Time{}, time.Time{}, "", func() time.Time { return at.Add(30 * time.Second) }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("unified read forgot old observed floor", e)
	}
}

func TestWindowsMaintenancePlanningSnapshotKeepsUnrelatedLegacyControls(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	at := contactAt
	createSeries(t, s, maintenanceFixtureTarget(1, "all"), 0, at, 2)
	other := maintenanceFixtureTarget(2, "disk")
	scheduleWindows(t, s, other, 0, at, at.Add(time.Hour), at.Add(2*time.Hour))
	legacy, series, immediate, e := s.ReadWindowsMaintenancePlanning(ctx, func() time.Time { return at })
	if e != nil || len(legacy) != 1 || len(series) != 1 || len(immediate) != 0 || legacy[0].Target != other || legacy[0].Revision != 1 {
		t.Fatal(legacy, series, immediate, e)
	}
	if _, e = s.ChangeWindowsMaintenanceSchedule(ctx, other, 1, "cancel", 1, time.Time{}, time.Time{}, "", func() time.Time { return at }, maintenanceGuard); e != nil {
		t.Fatal("unrelated cancellation blocked", e)
	}
	later := at.Add(time.Minute)
	scheduleWindows(t, s, other, 2, later, later.Add(time.Minute), later.Add(time.Hour))
	active := later.Add(2 * time.Minute)
	if _, e = s.ChangeWindowsMaintenanceSchedule(ctx, other, 3, "end", 3, time.Time{}, time.Time{}, "", func() time.Time { return active }, maintenanceGuard); e != nil {
		t.Fatal("unrelated active end blocked", e)
	}
	// Same device different domain remains independent too.
	third := maintenanceFixtureTarget(3, "cpu")
	createSeries(t, s, third, 0, active, 2)
	scheduleWindows(t, s, maintenanceFixtureTarget(3, "disk"), 0, active, active.Add(time.Hour), active.Add(2*time.Hour))
	legacy, series, _, e = s.ReadWindowsMaintenancePlanning(ctx, func() time.Time { return active })
	if e != nil || len(legacy) != 2 || len(series) != 2 {
		t.Fatal("combined snapshot lost target", legacy, series, e)
	}
}
