package store

import (
	"context"
	"errors"
	"localrmm/internal/health"
	"localrmm/internal/model"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestHealthDurableHistoryAndAtomicMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	at := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	value := 95.0
	for i := 0; i <= 4; i++ {
		now := at.Add(time.Duration(i) * 30 * time.Second)
		_, e = s.UpdateHealth(ctx, "agent_a", func(state *health.State) error {
			state.Evaluate(health.Input{Authorized: true, ReceivedAt: now, Disk: model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: now}}, now)
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	before, e := s.HealthState(ctx, "agent_a")
	if e != nil || len(before.Incidents) != 1 {
		t.Fatal(e, before)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	loaded, e := s.HealthState(ctx, "agent_a")
	if e != nil || !reflect.DeepEqual(before, loaded) {
		t.Fatal("history lost on restart", e)
	}
	want := errors.New("abort")
	_, e = s.UpdateHealth(ctx, "agent_a", func(state *health.State) error { state.Incidents = nil; return want })
	if !errors.Is(e, want) {
		t.Fatal(e)
	}
	loaded, _ = s.HealthState(ctx, "agent_a")
	if !reflect.DeepEqual(before, loaded) {
		t.Fatal("failed mutation changed state")
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.UpdateHealth(ctx, "agent_a", func(state *health.State) error {
				return state.Acknowledge(before.Incidents[0].ID, at.Add(3*time.Minute))
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	loaded, _ = s.HealthState(ctx, "agent_a")
	if loaded.Incidents[0].AcknowledgedAt == nil || len(loaded.Incidents) != 1 {
		t.Fatal("concurrent acknowledgements lost state")
	}
	missing, e := s.HealthState(ctx, "other")
	if e != nil || len(missing.Incidents) != 0 {
		t.Fatal("cross device history")
	}
}
func TestHealthStateCorruptionIsNotEmptySuccess(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, e = s.db.Exec("INSERT INTO health_devices(id,body) VALUES('bad',?)", []byte(`{"version":1}`))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.HealthState(context.Background(), "bad"); e == nil {
		t.Fatal("corruption became empty healthy state")
	}
}
