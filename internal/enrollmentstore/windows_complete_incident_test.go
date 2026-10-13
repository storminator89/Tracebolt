package enrollmentstore

import (
	"context"
	"localrmm/internal/windowsservicehealth"
	"strings"
	"testing"
	"time"
)

func TestCompleteIncidentLeasePinsPresentAbsentAndCurrentLeaf(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	f.grant(t)
	for _, m := range f.messages(t, 1, 1, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	ctx := windowsservicehealth.WithCompleteSelections(context.Background(), map[string][]string{f.snap.Approval.DeviceID: {}})
	rows, e := f.s.WindowsCapacityInputs(ctx, f.at)
	if e != nil {
		t.Fatal(e)
	}
	in := windowsservicehealth.Input{Input: rows[0].Input, Sample: rows[0].Services, Complete: true, CurrentLeaf: rows[0].CurrentLeaf}
	p := in.Sample.Complete.Source
	in.Selection = &p
	now := f.at
	run := func(expected windowsservicehealth.Input, advance time.Duration) error {
		return f.s.WithWindowsCompleteIncidentAuthority(ctx, expected, func() time.Time { return now }, func(guard func(time.Time) error) error { now = now.Add(advance); return guard(now) })
	}
	if e = run(in, time.Second); e != nil {
		t.Fatal("valid short wait", e)
	}
	wrongLeaf := in
	wrongLeaf.CurrentLeaf = strings.Repeat("d", 64)
	if e = run(wrongLeaf, 0); e == nil {
		t.Fatal("changed leaf with unchanged original anchor/expiry")
	}
	absent := in
	absent.Selection = nil
	if e = run(absent, 0); e == nil {
		t.Fatal("present source admitted as absent")
	}
	now = f.at.Add(299 * time.Second)
	if e = run(in, 2*time.Second); e == nil {
		t.Fatal("stale final source survived lease")
	}
	now = f.at.Add(302 * time.Second)
	if e = run(absent, 0); e != nil {
		t.Fatal("stale explicit absence rejected", e)
	}
	f.consent.Enabled = false
	f.consent.Revision++
	f.consent.ChangedAt = now
	if _, e = f.apply(t, f.scope(), now); e != nil {
		t.Fatal(e)
	}
	if e = run(absent, 0); e != nil {
		t.Fatal("disabled grant blocked historical acknowledgement", e)
	}
	if e = run(in, 0); e == nil {
		t.Fatal("revoked source admitted as present")
	}
	// A lost used source remains storage failure, not fabricated absence.
	if _, e = f.s.db.ExecContext(ctx, `DELETE FROM wfs_authority`); e != nil {
		t.Fatal(e)
	}
	if e = run(absent, 0); e == nil {
		t.Fatal("source data loss admitted as absence")
	}
}

func TestCompleteIncidentLeaseRejectsTimeBasedSourceReturn(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	f.grant(t)
	for _, m := range f.messages(t, 1, 1, f.at) {
		if _, e := f.apply(t, m, f.at.Add(2*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	ctx := windowsservicehealth.WithCompleteSelections(context.Background(), map[string][]string{f.snap.Approval.DeviceID: {}})
	rows, e := f.s.WindowsCapacityInputs(ctx, f.at.Add(3*time.Second))
	if e != nil || rows[0].Services.Complete == nil {
		t.Fatal(e)
	}
	// Model a backwards clock adjustment before the request. Capture is past,
	// immutable manager receipt is briefly future; it becomes eligible mid-lease.
	in := windowsservicehealth.Input{Input: rows[0].Input, Complete: true, CurrentLeaf: rows[0].CurrentLeaf}
	now := f.at.Add(time.Second)
	unknown, e := f.s.WindowsCapacityInputs(ctx, now)
	if e != nil || unknown[0].Services.Complete != nil {
		t.Fatal("ordinary read fabricated future freshness", e)
	}
	called := false
	e = f.s.WithWindowsCompleteIncidentAuthority(ctx, in, func() time.Time { return now }, func(guard func(time.Time) error) error {
		called = true
		now = now.Add(2 * time.Second)
		return guard(now)
	})
	if called || e == nil {
		t.Fatal("future-dated absent source admitted a transaction", called, e)
	}
	now = f.at.Add(3 * time.Second)
	p := rows[0].Services.Complete.Source
	in.Selection = &p
	if e = f.s.WithWindowsCompleteIncidentAuthority(ctx, in, func() time.Time { return now }, func(guard func(time.Time) error) error { return guard(now) }); e != nil {
		t.Fatal("current positive source rejected", e)
	}
}
