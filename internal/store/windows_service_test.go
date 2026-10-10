package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservicehealth"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func serviceHealthInput(n, sec int, state string) windowsservicehealth.Input {
	in := contactInput(n)
	in.ReceivedAt = contactAt.Add(time.Duration(sec) * time.Second)
	in.Sequence = uint64(sec + 1)
	return windowsservicehealth.Input{Input: in, Sample: windowsservicehealth.Sample{CollectedAt: in.ReceivedAt, Services: windowsmanaged.Section[windowsmanaged.Service]{Quality: "healthy", Complete: true, CountExact: true, ObservedCount: 1, Rows: []windowsmanaged.Service{{Name: "FixtureService", State: state}}}}}
}
func serviceHealthRaw(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var raw []byte
	if e := s.db.QueryRow("SELECT body FROM windows_service_devices WHERE id=?", id).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	return raw
}
func serviceHealthOpen(t *testing.T, s *Store) windowsservicehealth.State {
	t.Helper()
	in := serviceHealthInput(1, 0, "stopped")
	ctx := context.Background()
	state, e := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 0, contactAt)
	if e != nil {
		t.Fatal(e)
	}
	for _, sec := range []int{0, 30, 60, 90, 120} {
		in = serviceHealthInput(1, sec, "stopped")
		state, e = s.EvaluateWindowsService(ctx, in, in.ReceivedAt, contactEpoch)
		if e != nil {
			t.Fatal(e)
		}
	}
	return state
}
func TestWindowsServicePersistenceReadOnlyAndDefaultOff(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "serviceHealth.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	states, e := s.WindowsServiceStates(ctx)
	if e != nil || len(states) != 0 {
		t.Fatal("fresh schema enabled policy", e)
	}
	unknown, e := s.WindowsServiceState(ctx, contactInput(1).DeviceID)
	if e != nil || unknown.Policy.Enabled || len(unknown.Checks) != 0 {
		t.Fatal(unknown, e)
	}
	before := serviceHealthOpen(t, s)
	raw := serviceHealthRaw(t, s, before.DeviceID)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	state, e := s.WindowsServiceState(ctx, before.DeviceID)
	if e != nil || !reflect.DeepEqual(state, before) {
		t.Fatal("restart changed policy/history", e)
	}
	if state.View(serviceHealthInput(1, 120, "stopped"), contactAt.Add(2*time.Minute), contactEpochNext).Status != "unknown" {
		t.Fatal("restart trusted old evaluation")
	}
	if _, e = s.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = s.WindowsServiceState(ctx, before.DeviceID); e != nil {
			t.Fatal("read writes", e)
		}
		if _, e = s.WindowsServiceStates(ctx); e != nil {
			t.Fatal(e)
		}
	}
	if !bytes.Equal(raw, serviceHealthRaw(t, s, before.DeviceID)) {
		t.Fatal("read refreshed state")
	}
}
func TestWindowsServiceFailedWritesAndCorruptionPreserveState(t *testing.T) {
	s := contactStore(t)
	state := serviceHealthOpen(t, s)
	raw := serviceHealthRaw(t, s, state.DeviceID)
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := s.ConfigureWindowsService(canceled, serviceHealthInput(1, 150, "stopped"), false, []string{"FixtureService"}, 1, contactAt.Add(150*time.Second)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := s.ConfigureWindowsService(ctx, serviceHealthInput(1, 150, "stopped"), false, []string{"FixtureService"}, 0, contactAt.Add(150*time.Second)); e == nil {
		t.Fatal("stale revision changed state")
	}
	changed := serviceHealthInput(1, 150, "stopped")
	changed.CertificateHash = strings.Repeat("5", 64)
	if _, e := s.ConfigureWindowsService(ctx, changed, false, []string{"FixtureService"}, 1, changed.ReceivedAt); e == nil {
		t.Fatal("new identity adopted policy")
	}
	if _, e := s.db.Exec("PRAGMA query_only=ON"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ConfigureWindowsService(ctx, serviceHealthInput(1, 150, "stopped"), false, []string{"FixtureService"}, 1, contactAt.Add(150*time.Second)); e == nil {
		t.Fatal("read-only disk succeeded")
	}
	if _, e := s.db.Exec("PRAGMA query_only=OFF"); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, serviceHealthRaw(t, s, state.DeviceID)) {
		t.Fatal("failed write changed policy")
	}
	bad := bytes.Replace(raw, []byte(`tracebolt.windows-service-state.v1`), []byte(`tracebolt.windows-service-state.v2`), 1)
	if _, e := s.db.Exec("UPDATE windows_service_devices SET body=? WHERE id=?", bad, state.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.WindowsServiceState(ctx, state.DeviceID); e == nil {
		t.Fatal("corrupt state readable")
	}
	if _, e := s.EvaluateWindowsService(ctx, serviceHealthInput(1, 150, "stopped"), contactAt.Add(150*time.Second), contactEpoch); e == nil {
		t.Fatal("corrupt state replaced")
	}
	if !bytes.Equal(bad, serviceHealthRaw(t, s, state.DeviceID)) {
		t.Fatal("corrupt bytes changed")
	}
}
func TestWindowsServiceConcurrentPolicyRevisionAndIsolation(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in := serviceHealthInput(1, 0, "stopped")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, threshold := range []int{90, 91} {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			_, e := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 0, contactAt)
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
	state, e := s.WindowsServiceState(ctx, in.DeviceID)
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
func TestWindowsServiceStorageBoundAndInvalidIdentity(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	for n := 1; n <= 25; n++ {
		in := serviceHealthInput(n, 0, "stopped")
		if _, e := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 0, contactAt); e != nil {
			t.Fatal(n, e)
		}
	}
	if _, e := s.ConfigureWindowsService(ctx, serviceHealthInput(26, 0, "stopped"), true, []string{"FixtureService"}, 0, contactAt); e == nil {
		t.Fatal("unbounded state")
	}
	for _, id := range []string{"", fmt.Sprintf("agent_%032x", 0), "linux-device"} {
		if _, e := s.WindowsServiceState(ctx, id); e == nil {
			t.Fatal("invalid id")
		}
	}
}

func TestWindowsServiceNeverTouchesHealthAnalysisOrAlarms(t *testing.T) {
	s := contactStore(t)
	state := serviceHealthOpen(t, s)
	ctx := context.Background()
	for _, sec := range []int{150, 180, 210} {
		in := serviceHealthInput(1, sec, "running")
		var e error
		state, e = s.EvaluateWindowsService(ctx, in, in.ReceivedAt, contactEpoch)
		if e != nil {
			t.Fatal(e)
		}
	}
	if state.Checks[0].Status != "running" || state.Incidents[0].ClosedReason != "running" {
		t.Fatal("isolation fixture did not recover")
	}
	for _, table := range []string{"health_devices", "health_analyses", "alarm_outbox", "windows_contact_devices", "windows_capacity_devices", "windows_resource_devices"} {
		var n int
		if e := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil {
			t.Fatal("isolation target missing", table, e)
		}
		if n != 0 {
			t.Fatal("serviceHealth wrote outside its private ledger", table)
		}
	}
}
