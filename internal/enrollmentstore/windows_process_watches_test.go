package enrollmentstore

import (
	"context"
	"localrmm/internal/windowsfullprocesses"
	watch "localrmm/internal/windowsprocesswatch"
	"testing"
	"time"
)

func TestWindowsProcessWatchCompleteAuthorityAndUnknownSources(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 2051, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	now := f.at
	read := func(names []string) (watch.Input, error) {
		var got watch.Input
		e := f.s.WithWindowsProcessWatchAuthority(context.Background(), f.snap.Approval.DeviceID, names, func() time.Time { return now }, func(in watch.Input, guard func(time.Time) error) error { got = in; return guard(now) })
		return got, e
	}
	got, e := read([]string{"InventedProcess02049", "inventedprocess02049", "absent.exe"})
	if e != nil || got.Complete == nil || got.Counts["InventedProcess02049"] != 1 || got.Counts["inventedprocess02049"] != 0 || got.Counts["absent.exe"] != 0 {
		t.Fatal(got, e)
	}
	got, e = read([]string{})
	if e != nil || got.Complete != nil {
		t.Fatal("disabled read examined source", e)
	}
	now = f.at.Add(5 * time.Minute)
	got, e = read([]string{"absent.exe"})
	if e != nil || got.Complete != nil {
		t.Fatal("stale source", e)
	}
	now = f.at.Add(6 * time.Minute)
	messages := f.messages(t, 2, 2051, now)
	if _, e = f.apply(t, messages[0], now); e != nil {
		t.Fatal(e)
	}
	got, e = read([]string{"absent.exe"})
	if e != nil || got.Complete != nil {
		t.Fatal("pending prefix or old snapshot", e)
	}
	for _, m := range messages[1:] {
		if _, e = f.apply(t, m, now); e != nil {
			t.Fatal(e)
		}
	}
	got, e = read([]string{"InventedProcess02049"})
	if e != nil || got.Complete == nil || got.Complete.Manifest.Sequence != 2 {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	attempt := now
	failed := windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 3, AttemptedAt: &attempt, Reason: "access_denied"}
	if _, e = f.apply(t, failed, now); e != nil {
		t.Fatal(e)
	}
	got, e = read([]string{"InventedProcess02049"})
	if e != nil || got.Complete != nil {
		t.Fatal("latest failed attempt borrowed old source", e)
	}
}
func TestWindowsProcessWatchUnknownNameCoverageAndFinalExpiry(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	name := "target.exe"
	rows := []windowsfullprocesses.Row{{PID: 0, Name: &name, NameQuality: "observed"}, {PID: 1, NameQuality: "unavailable"}, {PID: 2, Name: &name, NameQuality: "observed"}}
	messages, e := windowsfullprocesses.Build(f.snap.Approval.DeviceID, f.consent, 1, windowsfullprocesses.Capture{StartedAt: f.at, FinishedAt: f.at, Complete: true, Rows: rows})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		if _, e = f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	now := f.at
	e = f.s.WithWindowsProcessWatchAuthority(context.Background(), f.snap.Approval.DeviceID, []string{name, "missing.exe"}, func() time.Time { return now }, func(in watch.Input, guard func(time.Time) error) error {
		if in.UnavailableNames != 1 || in.Counts[name] != 2 || in.Counts["missing.exe"] != 0 {
			t.Fatal(in)
		}
		now = now.Add(5 * time.Minute)
		return guard(now)
	})
	if e == nil {
		t.Fatal("source expired through operator wait")
	}
	// Corruption must not become a zero-match result.
	if _, e = f.s.db.Exec(`UPDATE wfp_rows SET name='spoofed.exe' WHERE pid=0`); e != nil {
		t.Fatal(e)
	}
	now = f.at
	if e = f.s.WithWindowsProcessWatchAuthority(context.Background(), f.snap.Approval.DeviceID, []string{name}, func() time.Time { return now }, func(watch.Input, func(time.Time) error) error { return nil }); e == nil {
		t.Fatal("corrupt index accepted")
	}
}

func TestWindowsProcessWatchClockRollbackCannotResurrectSnapshot(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 1, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	now := f.at.Add(6 * time.Minute)
	read := func() error {
		return f.s.WithWindowsProcessWatchAuthority(context.Background(), f.snap.Approval.DeviceID, []string{"InventedProcess00000"}, func() time.Time { return now }, func(in watch.Input, guard func(time.Time) error) error {
			if in.Complete != nil {
				t.Fatal("stale source admitted")
			}
			return guard(now)
		})
	}
	if e := read(); e != nil {
		t.Fatal(e)
	}
	now = f.at.Add(4 * time.Minute)
	if e := read(); e == nil {
		t.Fatal("clock rollback resurrected source")
	}
}
