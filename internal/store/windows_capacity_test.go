package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"localrmm/internal/model"
	"localrmm/internal/windowscapacity"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func capacityInput(n, sec int, value float64) windowscapacity.Input {
	in := contactInput(n)
	in.ReceivedAt = contactAt.Add(time.Duration(sec) * time.Second)
	in.Sequence = uint64(sec + 1)
	return windowscapacity.Input{Input: in, Disk: model.Metric{Value: &value, Quality: "healthy", Unit: "%", Source: "fixture quota-aware system volume", CollectedAt: in.ReceivedAt}}
}
func capacityRaw(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var raw []byte
	if e := s.db.QueryRow("SELECT body FROM windows_capacity_devices WHERE id=?", id).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	return raw
}
func capacityOpen(t *testing.T, s *Store) windowscapacity.State {
	t.Helper()
	in := capacityInput(1, 0, 95)
	ctx := context.Background()
	state, e := s.ConfigureWindowsCapacity(ctx, in, true, 90, 0, contactAt)
	if e != nil {
		t.Fatal(e)
	}
	for _, sec := range []int{0, 30, 60} {
		in = capacityInput(1, sec, 95)
		state, e = s.EvaluateWindowsCapacity(ctx, in, in.ReceivedAt, contactEpoch)
		if e != nil {
			t.Fatal(e)
		}
	}
	return state
}
func TestWindowsCapacityPersistenceReadOnlyAndDefaultOff(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "capacity.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	states, e := s.WindowsCapacityStates(ctx)
	if e != nil || len(states) != 0 {
		t.Fatal("fresh schema enabled policy", e)
	}
	unknown, e := s.WindowsCapacityState(ctx, contactInput(1).DeviceID)
	if e != nil || unknown.Policy.Enabled || unknown.Status != "disabled" {
		t.Fatal(unknown, e)
	}
	before := capacityOpen(t, s)
	raw := capacityRaw(t, s, before.DeviceID)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	state, e := s.WindowsCapacityState(ctx, before.DeviceID)
	if e != nil || !reflect.DeepEqual(state, before) {
		t.Fatal("restart changed policy/history", e)
	}
	if state.View(capacityInput(1, 60, 95), contactAt.Add(time.Minute), contactEpochNext).Status != "unknown" {
		t.Fatal("restart trusted old evaluation")
	}
	if _, e = s.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = s.WindowsCapacityState(ctx, before.DeviceID); e != nil {
			t.Fatal("read writes", e)
		}
		if _, e = s.WindowsCapacityStates(ctx); e != nil {
			t.Fatal(e)
		}
	}
	if !bytes.Equal(raw, capacityRaw(t, s, before.DeviceID)) {
		t.Fatal("read refreshed state")
	}
}
func TestWindowsCapacityFailedWritesAndCorruptionPreserveState(t *testing.T) {
	s := contactStore(t)
	state := capacityOpen(t, s)
	raw := capacityRaw(t, s, state.DeviceID)
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := s.ConfigureWindowsCapacity(canceled, capacityInput(1, 90, 95), false, 90, 1, contactAt.Add(90*time.Second)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := s.ConfigureWindowsCapacity(ctx, capacityInput(1, 90, 95), false, 90, 0, contactAt.Add(90*time.Second)); e == nil {
		t.Fatal("stale revision changed state")
	}
	changed := capacityInput(1, 90, 95)
	changed.CertificateHash = strings.Repeat("5", 64)
	if _, e := s.ConfigureWindowsCapacity(ctx, changed, false, 90, 1, changed.ReceivedAt); e == nil {
		t.Fatal("new identity adopted policy")
	}
	if _, e := s.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ConfigureWindowsCapacity(ctx, capacityInput(1, 90, 95), false, 90, 1, contactAt.Add(90*time.Second)); e == nil {
		t.Fatal("read-only disk succeeded")
	}
	if _, e := s.db.Exec("PRAGMA query_only=OFF"); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, capacityRaw(t, s, state.DeviceID)) {
		t.Fatal("failed write changed policy")
	}
	bad := bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1)
	if _, e := s.db.Exec("UPDATE windows_capacity_devices SET body=? WHERE id=?", bad, state.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.WindowsCapacityState(ctx, state.DeviceID); e == nil {
		t.Fatal("corrupt state readable")
	}
	if _, e := s.EvaluateWindowsCapacity(ctx, capacityInput(1, 90, 95), contactAt.Add(90*time.Second), contactEpoch); e == nil {
		t.Fatal("corrupt state replaced")
	}
	if !bytes.Equal(bad, capacityRaw(t, s, state.DeviceID)) {
		t.Fatal("corrupt bytes changed")
	}
}
func TestWindowsCapacityConcurrentPolicyRevisionAndIsolation(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in := capacityInput(1, 0, 95)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, threshold := range []int{90, 91} {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			_, e := s.ConfigureWindowsCapacity(ctx, in, true, v, 0, contactAt)
			results <- e
		}(threshold)
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("lost update", success)
	}
	state, e := s.WindowsCapacityState(ctx, in.DeviceID)
	if e != nil || state.Policy.Revision != 1 {
		t.Fatal(state, e)
	}
	for _, table := range []string{"health_devices", "windows_contact_devices"} {
		var n int
		if e := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil {
			t.Fatal(e)
		}
		if n != 0 {
			t.Fatal("cross-contract write", table)
		}
	}
}
func TestWindowsCapacityStorageBoundAndInvalidIdentity(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	for n := 1; n <= 25; n++ {
		in := capacityInput(n, 0, 95)
		if _, e := s.ConfigureWindowsCapacity(ctx, in, true, 90, 0, contactAt); e != nil {
			t.Fatal(n, e)
		}
	}
	if _, e := s.ConfigureWindowsCapacity(ctx, capacityInput(26, 0, 95), true, 90, 0, contactAt); e == nil {
		t.Fatal("unbounded state")
	}
	for _, id := range []string{"", fmt.Sprintf("agent_%032x", 0), "linux-device"} {
		if _, e := s.WindowsCapacityState(ctx, id); e == nil {
			t.Fatal("invalid id")
		}
	}
}

func TestWindowsCapacityNeverTouchesHealthAnalysisOrAlarms(t *testing.T) {
	s := contactStore(t)
	state := capacityOpen(t, s)
	ctx := context.Background()
	for _, sec := range []int{90, 120, 150} {
		in := capacityInput(1, sec, 80)
		var e error
		state, e = s.EvaluateWindowsCapacity(ctx, in, in.ReceivedAt, contactEpoch)
		if e != nil {
			t.Fatal(e)
		}
	}
	if state.Status != "within-policy" || state.Incidents[0].ClosedReason != "within-policy" {
		t.Fatal("isolation fixture did not recover")
	}
	for _, table := range []string{"health_devices", "health_analyses", "alarm_outbox", "windows_contact_devices"} {
		var n int
		if e := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil {
			t.Fatal("isolation target missing", table, e)
		}
		if n != 0 {
			t.Fatal("capacity wrote outside its private ledger", table)
		}
	}
}
