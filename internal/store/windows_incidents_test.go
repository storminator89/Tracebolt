package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/windowsresource"
)

func inboxTarget(t *testing.T, s *Store, domain string) WindowsIncidentTarget {
	t.Helper()
	v, e := s.WindowsIncidentSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, target := range v.Targets() {
		if target.Domain == domain {
			return target
		}
	}
	t.Fatalf("missing %s", domain)
	return WindowsIncidentTarget{}
}
func TestWindowsIncidentAcknowledgementCollisionDurabilityAndIsolation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "inbox.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	capacityOpen(t, s)
	resourceOpen(t, s, windowsresource.CPU)
	resourceOpen(t, s, windowsresource.Memory)
	serviceHealthOpen(t, s)
	in := contactInput(1)
	for sec := 0; sec <= 210; sec += 30 {
		contactEvaluate(t, s, in, contactAt.Add(time.Duration(sec)*time.Second))
	}
	before, e := s.WindowsIncidentSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	disk, cpu, ram := inboxTarget(t, s, "disk"), inboxTarget(t, s, "cpu"), inboxTarget(t, s, "memory")
	if disk.IncidentID != cpu.IncidentID || cpu.IncidentID != ram.IncidentID || disk.Key() == cpu.Key() || cpu.Key() == ram.Key() {
		t.Fatal("fixture must prove equal engine IDs remain independently keyed")
	}
	first := contactAt.Add(240 * time.Second)
	ack, e := s.AcknowledgeWindowsIncident(ctx, cpu, func() time.Time { return first }, func(time.Time) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.AcknowledgeWindowsIncident(ctx, cpu, func() time.Time { return first.Add(time.Second) }, func(time.Time) error { return nil })
	if e != nil || again != ack {
		t.Fatal("idempotent acknowledgement rewrote timestamp", e)
	}
	after, e := s.WindowsIncidentSnapshot(ctx)
	if e != nil || len(after.Acknowledgements) != 1 || after.Acknowledgements[cpu.Key()].AcknowledgedAt != first {
		t.Fatal("ack isolation", e)
	}
	after.Acknowledgements = before.Acknowledgements
	if !reflect.DeepEqual(before, after) {
		t.Fatal("acknowledgement changed assessment/history")
	}
	for _, table := range []string{"health_devices", "health_analyses", "alarm_outbox"} {
		var n int
		if e = s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != 0 {
			t.Fatal("Windows acknowledgement entered Linux domain", table, e)
		}
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := s.WindowsIncidentSnapshot(ctx)
	if e != nil || loaded.Acknowledgements[cpu.Key()] != ack {
		t.Fatal("ack lost across restart", e)
	}
	// Exact target binding prevents a sibling metric or replacement enrollment inheriting it.
	for _, change := range []func(*WindowsIncidentTarget){func(v *WindowsIncidentTarget) { v.CertificateHash = strings.Repeat("4", 64) }, func(v *WindowsIncidentTarget) { v.InvitationID = "invite_" + strings.Repeat("4", 32) }, func(v *WindowsIncidentTarget) { v.IncidentID = "wcapacity_0000000000000002" }, func(v *WindowsIncidentTarget) { v.OpenedAt = v.OpenedAt.Add(time.Second) }} {
		wrong := cpu
		change(&wrong)
		if _, e = s.AcknowledgeWindowsIncident(ctx, wrong, func() time.Time { return first }, func(time.Time) error { return nil }); !errors.Is(e, ErrWindowsIncident) {
			t.Fatal("wrong target accepted", e)
		}
	}
}
func TestWindowsIncidentAcknowledgementDoesNotFollowNewEpisode(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	capacityOpen(t, s)
	target := inboxTarget(t, s, "disk")
	at := contactAt.Add(70 * time.Second)
	if _, e := s.AcknowledgeWindowsIncident(ctx, target, func() time.Time { return at }, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ConfigureWindowsCapacity(ctx, capacityInput(1, 70, 95), false, 90, 1, at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ConfigureWindowsCapacity(ctx, capacityInput(1, 80, 95), true, 90, 2, contactAt.Add(80*time.Second)); e != nil {
		t.Fatal(e)
	}
	for _, sec := range []int{80, 110, 140} {
		in := capacityInput(1, sec, 95)
		if _, e := s.EvaluateWindowsCapacity(ctx, in, in.ReceivedAt, contactEpoch); e != nil {
			t.Fatal(e)
		}
	}
	v, e := s.WindowsIncidentSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	st := v.Capacities[target.DeviceID]
	if len(st.Incidents) != 2 || st.Incidents[0].ResolvedAt != nil || st.Incidents[1].ClosedReason != "policy-changed" {
		t.Fatal("lifecycle changed")
	}
	newTarget := target
	newTarget.IncidentID = st.Incidents[0].ID
	newTarget.OpenedAt = st.Incidents[0].OpenedAt
	if _, exists := v.Acknowledgements[newTarget.Key()]; exists || len(v.Acknowledgements) != 1 {
		t.Fatal("new episode silently acknowledged")
	}
}
func TestWindowsIncidentReadOnlyOrphanRetentionAndCorruption(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	capacityOpen(t, s)
	target := inboxTarget(t, s, "disk")
	at := contactAt.Add(time.Minute)
	orphan := target
	orphan.IncidentID = "wcapacity_0000000000000002"
	a := WindowsIncidentAcknowledgement{1, orphan, at}
	raw, _ := json.Marshal(a)
	if _, e := s.db.Exec("INSERT INTO windows_incident_acknowledgements(key,body) VALUES(?,?)", orphan.Key(), raw); e != nil {
		t.Fatal(e)
	}
	v, e := s.WindowsIncidentSnapshot(ctx)
	if e != nil || len(v.Acknowledgements) != 1 {
		t.Fatal(e)
	}
	var got []byte
	s.db.QueryRow("SELECT body FROM windows_incident_acknowledgements WHERE key=?", orphan.Key()).Scan(&got)
	if !bytes.Equal(got, raw) {
		t.Fatal("read pruned/repaired ack")
	}
	if _, e = s.AcknowledgeWindowsIncident(ctx, target, func() time.Time { return at }, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	v, e = s.WindowsIncidentSnapshot(ctx)
	if e != nil || len(v.Acknowledgements) != 1 || v.Acknowledgements[target.Key()].Target != target {
		t.Fatal("bounded orphan housekeeping", e)
	}
	if _, e = s.db.Exec("UPDATE windows_incident_acknowledgements SET body=body||' '"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WindowsIncidentSnapshot(ctx); !errors.Is(e, ErrWindowsIncident) {
		t.Fatal("noncanonical ack accepted", e)
	}
	if _, e = s.AcknowledgeWindowsIncident(ctx, target, func() time.Time { return at }, func(time.Time) error { return nil }); !errors.Is(e, ErrWindowsIncident) {
		t.Fatal("corrupt ack overwritten", e)
	}
}
func TestWindowsIncidentAcknowledgementExpiryAfterSQLWaitAndFinalGuard(t *testing.T) {
	for _, phase := range []string{"after-sql-wait", "before-commit"} {
		t.Run(phase, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			capacityOpen(t, s)
			target := inboxTarget(t, s, "disk")
			before := capacityRaw(t, s, target.DeviceID)
			at := contactAt.Add(time.Minute)
			var expired atomic.Bool
			calls := 0
			guard := func(time.Time) error {
				calls++
				if phase == "before-commit" && calls == 2 {
					expired.Store(true)
				}
				if expired.Load() {
					return ErrWindowsIncident
				}
				return nil
			}
			var err error
			if phase == "after-sql-wait" {
				conn, e := s.db.Conn(ctx)
				if e != nil {
					t.Fatal(e)
				}
				waiting := s.db.Stats().WaitCount
				result := make(chan error, 1)
				go func() {
					_, e := s.AcknowledgeWindowsIncident(ctx, target, func() time.Time { return at }, guard)
					result <- e
				}()
				deadline := time.Now().Add(5 * time.Second)
				for s.db.Stats().WaitCount == waiting && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if s.db.Stats().WaitCount == waiting {
					conn.Close()
					t.Fatal("ack did not wait for SQLite")
				}
				expired.Store(true)
				conn.Close()
				err = <-result
			} else {
				_, err = s.AcknowledgeWindowsIncident(ctx, target, func() time.Time { return at }, guard)
			}
			if !errors.Is(err, ErrWindowsIncident) {
				t.Fatal("expired acknowledgement committed", err)
			}
			v, e := s.WindowsIncidentSnapshot(ctx)
			if e != nil || len(v.Acknowledgements) != 0 || !bytes.Equal(before, capacityRaw(t, s, target.DeviceID)) {
				t.Fatal("failed guard changed durable state", e)
			}
		})
	}
}

func TestWindowsIncidentAcknowledgementRejectsClockRollbackAfterStamp(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	capacityOpen(t, s)
	target := inboxTarget(t, s, "disk")
	now := contactAt.Add(64 * time.Second)
	samples := 0
	clock := func() time.Time {
		samples++
		if samples == 3 {
			return contactAt.Add(61 * time.Second)
		}
		return now
	}
	guard := func(time.Time) error { return nil }
	if _, err := s.AcknowledgeWindowsIncident(ctx, target, clock, guard); !errors.Is(err, ErrWindowsIncident) {
		t.Fatal("future-dated acknowledgement committed", err)
	}
	snapshot, err := s.WindowsIncidentSnapshot(ctx)
	if err != nil || len(snapshot.Acknowledgements) != 0 {
		t.Fatal("rollback persisted acknowledgement", err)
	}
}

func TestWindowsIncidentAcknowledgementFinalSampleExpiry(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	capacityOpen(t, s)
	target := inboxTarget(t, s, "disk")
	start := contactAt.Add(64 * time.Second)
	expiry := start.Add(time.Second)
	samples := 0
	clock := func() time.Time {
		samples++
		if samples >= 3 {
			return expiry
		}
		return start
	}
	guard := func(at time.Time) error {
		if !at.Before(expiry) {
			return ErrWindowsIncident
		}
		return nil
	}
	if _, err := s.AcknowledgeWindowsIncident(ctx, target, clock, guard); !errors.Is(err, ErrWindowsIncident) {
		t.Fatal("expiry on final sampled clock committed", err)
	}
	snapshot, err := s.WindowsIncidentSnapshot(ctx)
	if err != nil || len(snapshot.Acknowledgements) != 0 {
		t.Fatal("final sample expiry changed state", err)
	}
}
