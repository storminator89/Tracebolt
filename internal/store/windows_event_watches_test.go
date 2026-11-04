package store

import (
	"context"
	"errors"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventwatch"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func eventWatchFixture() (windowseventwatch.Input, time.Time) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	in := windowseventwatch.Input{Source: windowscontact.Input{DeviceID: "agent_" + strings.Repeat("a", 32), InvitationID: "invite_" + strings.Repeat("b", 32), CertificateHash: strings.Repeat("c", 64), Authorized: true, AuthorityUntil: at.Add(30 * 24 * time.Hour), ReceivedAt: at, Sequence: 1}, Events: &windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("d", 32), GenerationID: "sample_" + strings.Repeat("e", 32), CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "10", EventID: 42, Level: 2, Provider: "Fixture", Timestamp: at}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}}
	return in, at
}
func eventWatchCommand(in windowseventwatch.Input) WindowsEventWatchCommand {
	return WindowsEventWatchCommand{RequestID: "eventrequest_" + strings.Repeat("f", 32), SourceToken: windowseventwatch.SourceToken(in), Operation: "policy", Enabled: true, Selectors: []windowseventwatch.Selector{{Channel: "Application", Provider: "Fixture", EventID: 42, Level: 2}}, RetentionAcknowledged: true}
}
func TestWindowsEventWatchDefaultOffAndGuards(t *testing.T) {
	for _, stop := range []int{0, 1, 2, 3} {
		t.Run(string(rune('0'+stop)), func(t *testing.T) {
			s, e := Open(filepath.Join(t.TempDir(), "state.db"))
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			ctx := context.Background()
			in, at := eventWatchFixture()
			clock := func() time.Time { return at }
			v, e := s.WindowsEventWatchRecord(ctx, in.Source.DeviceID)
			if e != nil || v.State.Policy.Enabled {
				t.Fatal(e, v)
			}
			if _, e = s.UpdateWindowsEventWatch(ctx, in, nil, true, clock, func(time.Time) error { return nil }); e != nil {
				t.Fatal(e)
			}
			records, e := s.WindowsEventWatchRecords(ctx)
			if e != nil || len(records) != 0 {
				t.Fatal("default off mutated", e, records)
			}
			c := eventWatchCommand(in)
			calls := 0
			denied := errors.New("session/source expired")
			v, e = s.UpdateWindowsEventWatch(ctx, in, &c, false, clock, func(time.Time) error {
				calls++
				if calls == stop {
					return denied
				}
				return nil
			})
			if stop > 0 {
				if !errors.Is(e, denied) {
					t.Fatal(e)
				}
				records, e = s.WindowsEventWatchRecords(ctx)
				if e != nil || len(records) != 0 {
					t.Fatal("guard wrote", e, records)
				}
			} else {
				if e != nil || v.Revision != 1 || !v.State.Policy.Enabled || v.State.Sequence != 1 || len(v.State.Incidents) != 0 {
					t.Fatal("enable baseline", e, v)
				}
			}
		})
	}
}
func TestWindowsEventWatchConsentReplayGrantAndRetention(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	in, at := eventWatchFixture()
	clock := func() time.Time { return at }
	guard := func(time.Time) error { return nil }
	c := eventWatchCommand(in)
	c.RetentionAcknowledged = false
	if _, e = s.UpdateWindowsEventWatch(ctx, in, &c, false, clock, guard); e == nil {
		t.Fatal("retention implicit")
	}
	c.RetentionAcknowledged = true
	v, e := s.UpdateWindowsEventWatch(ctx, in, &c, false, clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.UpdateWindowsEventWatch(ctx, in, &c, false, clock, guard); !errors.Is(e, ErrWindowsEventWatchConflict) {
		t.Fatal("replayed request", e)
	}
	at = at.Add(time.Minute)
	in.Source.Sequence++
	in.Source.ReceivedAt = at
	in.Events.CollectedAt = at
	in.Events.GenerationID = "sample_" + strings.Repeat("f", 32)
	in.Events.Channels[0].Rows[0].RecordID = "11"
	in.Events.Channels[0].Rows[0].Timestamp = at
	v, e = s.UpdateWindowsEventWatch(ctx, in, nil, true, clock, guard)
	if e != nil || len(v.State.Incidents) != 1 {
		t.Fatal(e, v)
	}
	c.ExpectedRevision = v.Revision
	c.RequestID = "eventrequest_" + strings.Repeat("1", 32)
	c.Selectors[0].Provider = "Unobserved"
	if _, e = s.UpdateWindowsEventWatch(ctx, in, &c, false, clock, guard); e == nil {
		t.Fatal("unobserved selector accepted")
	}
	in.Events.GrantID = strings.Repeat("2", 32)
	c.SourceToken = windowseventwatch.SourceToken(in)
	c.Selectors[0].Provider = "Fixture"
	if _, e = s.UpdateWindowsEventWatch(ctx, in, &c, false, clock, guard); e == nil {
		t.Fatal("replaced grant rearmed old state")
	}
	at = at.Add(windowseventwatch.Retention + time.Second)
	if e = s.PruneWindowsEventWatch(ctx, in.Source.DeviceID, clock); e != nil {
		t.Fatal(e)
	}
	v, e = s.WindowsEventWatchRecord(ctx, in.Source.DeviceID)
	if e != nil || len(v.State.Incidents) != 0 {
		t.Fatal("source-independent expiry", e, v)
	}
}
func TestWindowsEventWatchMissingUsedLedgerFailsClosed(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	in, at := eventWatchFixture()
	c := eventWatchCommand(in)
	if _, e = s.UpdateWindowsEventWatch(context.Background(), in, &c, false, func() time.Time { return at }, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`DELETE FROM windows_event_watches`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WindowsEventWatchRecords(context.Background()); !errors.Is(e, ErrWindowsEventWatchUnavailable) {
		t.Fatal(e)
	}
	if _, e = s.WindowsEventWatchRecord(context.Background(), in.Source.DeviceID); !errors.Is(e, ErrWindowsEventWatchUnavailable) {
		t.Fatal(e)
	}
}
