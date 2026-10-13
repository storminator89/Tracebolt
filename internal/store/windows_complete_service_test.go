package store

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func completeStoredInput() windowsservicehealth.Input {
	in := serviceHealthInput(1, 0, "stopped")
	in.Complete = true
	p := windowsservicehealth.Provenance{Kind: windowsservicehealth.CompleteSourceKind, GrantID: strings.Repeat("a", 32), GrantRevision: 1, ManifestSHA256: strings.Repeat("b", 64), Sequence: 1, CapturedAt: contactAt, CaptureFinishedAt: contactAt, ReceivedAt: contactAt, ExpiresAt: contactAt.Add(24 * time.Hour), RowCount: 2000}
	p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
	state := "stopped"
	in.Sample.Complete = &windowsservicehealth.CompleteSample{Source: p, Rows: []windowsfullservices.Row{{Name: "FixtureService", DisplayNameQuality: "unavailable", State: &state, StateQuality: "observed", PIDQuality: "unavailable"}}}
	in.Selection = &p
	return in
}
func TestCompleteServiceDurableSourceAndIsolation(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in := completeStoredInput()
	if _, e := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 0, contactAt); e != nil {
		t.Fatal(e)
	}
	for i := 0; i <= 6; i++ {
		now := contactAt.Add(time.Duration(i) * 30 * time.Second)
		if i == 6 {
			p := &in.Sample.Complete.Source
			p.Sequence++
			p.CapturedAt = now
			p.CaptureFinishedAt = now
			p.ReceivedAt = now
			p.ExpiresAt = now.Add(24 * time.Hour)
			p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
		}
		if _, e := s.EvaluateWindowsService(ctx, in, now, contactEpoch); e != nil {
			t.Fatal(e)
		}
	}
	state, e := s.WindowsServiceState(ctx, in.DeviceID)
	if e != nil || len(state.Incidents) != 1 || state.SourceFloor == nil {
		t.Fatal(e, state)
	}
	if len(serviceNotificationEpisodes(state)) != 0 {
		t.Fatal("v2 silently entered old recipient scope")
	}
	snapshot, e := s.WindowsIncidentSnapshot(ctx)
	if e != nil || len(snapshot.Targets()) != 0 {
		t.Fatal("v2 silently entered old v1 incident/control target", e)
	}
	raw := serviceHealthRaw(t, s, in.DeviceID)
	if _, e = s.ConfigureWindowsService(ctx, serviceHealthInput(1, 180, "stopped"), false, []string{}, 1, contactAt.Add(180*time.Second)); e == nil {
		t.Fatal("v1 writer changed v2")
	}
	if !bytes.Equal(raw, serviceHealthRaw(t, s, in.DeviceID)) {
		t.Fatal("failed write lost source")
	}
	var bad map[string]json.RawMessage
	if e = json.Unmarshal(raw, &bad); e != nil {
		t.Fatal(e)
	}
	delete(bad, "sourceFloor")
	corrupt, _ := json.Marshal(bad)
	if _, e = s.db.Exec(`UPDATE windows_service_devices SET body=? WHERE id=?`, corrupt, in.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WindowsServiceState(ctx, in.DeviceID); e == nil {
		t.Fatal("lost source floor reconstructed")
	}
	if _, e = s.EvaluateWindowsService(ctx, in, contactAt.Add(210*time.Second), contactEpoch); e == nil {
		t.Fatal("used source state reset")
	}
	if !bytes.Equal(corrupt, serviceHealthRaw(t, s, in.DeviceID)) {
		t.Fatal("corrupt bytes repaired")
	}
}
func TestCompleteServiceFinalSourceExpiryRollsBack(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in := completeStoredInput()
	now := contactAt.Add(299 * time.Second)
	guards := 0
	_, e := s.ConfigureWindowsServiceGuarded(ctx, in, true, []string{"FixtureService"}, 0, func() time.Time { return now }, func(time.Time) error {
		guards++
		if guards == 3 {
			now = contactAt.Add(301 * time.Second)
		}
		return nil
	})
	if e == nil {
		t.Fatal("expired complete source committed")
	}
	states, e := s.WindowsServiceStates(ctx)
	if e != nil || len(states) != 0 {
		t.Fatal("failed final source guard wrote policy", e)
	}
}

func TestCompleteServiceEvaluatorSQLWaitAndFinalGuards(t *testing.T) {
	for _, mode := range []string{"valid-wait", "source-expiry", "final-authority", "final-recovery"} {
		t.Run(mode, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			in := completeStoredInput()
			if _, e := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 0, contactAt); e != nil {
				t.Fatal(e)
			}
			for _, sec := range []int{0, 30, 60, 90} {
				if _, e := s.EvaluateWindowsService(ctx, in, contactAt.Add(time.Duration(sec)*time.Second), contactEpoch); e != nil {
					t.Fatal(e)
				}
			}
			p := &in.Sample.Complete.Source
			p.Sequence = 2
			p.CapturedAt = contactAt.Add(120 * time.Second)
			p.CaptureFinishedAt = p.CapturedAt
			p.ReceivedAt = p.CapturedAt
			p.ExpiresAt = p.CapturedAt.Add(24 * time.Hour)
			p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
			now := p.ReceivedAt
			if mode == "final-recovery" {
				if _, e := s.EvaluateWindowsService(ctx, in, now, contactEpoch); e != nil {
					t.Fatal(e)
				}
				running := "running"
				in.Sample.Complete.Rows[0].State = &running
				p.Sequence++
				p.CapturedAt = now.Add(60 * time.Second)
				p.CaptureFinishedAt = p.CapturedAt
				p.ReceivedAt = p.CapturedAt
				p.ExpiresAt = p.CapturedAt.Add(24 * time.Hour)
				p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
				now = p.ReceivedAt
				if _, e := s.EvaluateWindowsService(ctx, in, now, contactEpoch); e != nil {
					t.Fatal(e)
				}
				if _, e := s.EvaluateWindowsService(ctx, in, now.Add(30*time.Second), contactEpoch); e != nil {
					t.Fatal(e)
				}
				p.Sequence++
				p.CapturedAt = now.Add(60 * time.Second)
				p.CaptureFinishedAt = p.CapturedAt
				p.ReceivedAt = p.CapturedAt
				p.ExpiresAt = p.CapturedAt.Add(24 * time.Hour)
				p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
				now = p.ReceivedAt
			}
			original := serviceHealthRaw(t, s, in.DeviceID)
			guards := 0
			clock := func() time.Time { return now }
			guard := func(at time.Time) error {
				guards++
				if guards == 3 {
					if mode == "source-expiry" {
						now = in.Sample.Complete.Source.CapturedAt.Add(301 * time.Second)
					}
					if mode == "final-authority" || mode == "final-recovery" {
						return windowsservicehealth.ErrInvalid
					}
				}
				return nil
			}
			if mode == "valid-wait" {
				// Hold the sole operator SQLite connection; apply time must be sampled only
				// after the connection wait has actually completed.
				conn, e := s.db.Conn(ctx)
				if e != nil {
					t.Fatal(e)
				}
				waits := s.db.Stats().WaitCount
				var shifted atomic.Bool
				clock = func() time.Time {
					if shifted.Load() {
						return now.Add(time.Second)
					}
					return now
				}
				done := make(chan error, 1)
				go func() {
					_, e := s.EvaluateWindowsCompleteServiceGuarded(ctx, in, clock, contactEpoch, guard)
					done <- e
				}()
				until := time.Now().Add(5 * time.Second)
				for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
					time.Sleep(time.Millisecond)
				}
				if s.db.Stats().WaitCount == waits {
					conn.Close()
					t.Fatal("did not reach SQLite wait")
				}
				shifted.Store(true)
				conn.Close()
				if e := <-done; e != nil {
					t.Fatal(e)
				}
				state, e := s.WindowsServiceState(ctx, in.DeviceID)
				if e != nil || len(state.Incidents) != 1 || !state.Incidents[0].OpenedAt.Equal(now.Add(time.Second)) {
					t.Fatal("pre-wait evaluation time", e, state)
				}
				return
			}
			if _, e := s.EvaluateWindowsCompleteServiceGuarded(ctx, in, clock, contactEpoch, guard); e == nil {
				t.Fatal("unsafe transition committed", mode)
			}
			if !bytes.Equal(original, serviceHealthRaw(t, s, in.DeviceID)) {
				t.Fatal("opening/recovery changed after failed guard", mode)
			}
		})
	}
}
