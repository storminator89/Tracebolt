package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsresource"
)

func resourceInput(n, sec int, cpu, memory float64) windowscapacity.Input {
	in := capacityInput(n, sec, 12)
	in.CPU = in.Disk
	in.Memory = in.Disk
	in.CPU.Value = &cpu
	in.Memory.Value = &memory
	return in
}
func resourceRaw(t *testing.T, s *Store, id string, kind windowsresource.Kind) []byte {
	t.Helper()
	var raw []byte
	if err := s.db.QueryRow("SELECT body FROM windows_resource_devices WHERE id=? AND metric=?", id, kind).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
func resourceOpen(t *testing.T, s *Store, kind windowsresource.Kind) windowsresource.State {
	t.Helper()
	ctx := context.Background()
	in := resourceInput(1, 0, 95, 95)
	state, err := s.ConfigureWindowsResource(ctx, in, kind, true, 90, 0, contactAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range []int{0, 30, 60} {
		in = resourceInput(1, sec, 95, 95)
		state, err = s.EvaluateWindowsResource(ctx, in, kind, in.ReceivedAt, contactEpoch)
		if err != nil {
			t.Fatal(err)
		}
	}
	return state
}
func TestWindowsResourceIndependentPoliciesPersistWithoutDiskMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "resources.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := capacityOpen(t, s)
	diskRaw := capacityRaw(t, s, disk.DeviceID)
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		state, err := s.WindowsResourceState(ctx, disk.DeviceID, kind)
		if err != nil || state.Assessment.Policy.Enabled || state.Assessment.Policy.Revision != 0 {
			t.Fatal("disk migrated", state, err)
		}
	}
	before := resourceOpen(t, s, windowsresource.CPU)
	memory, err := s.WindowsResourceState(ctx, disk.DeviceID, windowsresource.Memory)
	if err != nil || memory.Assessment.Policy.Enabled {
		t.Fatal("CPU implied memory", err)
	}
	if !bytes.Equal(diskRaw, capacityRaw(t, s, disk.DeviceID)) {
		t.Fatal("CPU changed disk bytes")
	}
	raw := resourceRaw(t, s, disk.DeviceID, windowsresource.CPU)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, err := s.WindowsResourceState(ctx, disk.DeviceID, windowsresource.CPU)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("restart lost evidence", err)
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WindowsResourceStates(ctx); err != nil {
		t.Fatal("list writes", err)
	}
	if _, err = s.WindowsResourceState(ctx, disk.DeviceID, windowsresource.CPU); err != nil {
		t.Fatal("GET writes", err)
	}
	if !bytes.Equal(raw, resourceRaw(t, s, disk.DeviceID, windowsresource.CPU)) {
		t.Fatal("read changed bytes")
	}
}
func TestWindowsResourceFailedWritesAndTagCorruptionRemainIntact(t *testing.T) {
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		t.Run(string(kind), func(t *testing.T) {
			s := contactStore(t)
			state := resourceOpen(t, s, kind)
			id := state.Assessment.DeviceID
			raw := resourceRaw(t, s, id, kind)
			ctx := context.Background()
			in := resourceInput(1, 90, 95, 95)
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := s.ConfigureWindowsResource(canceled, in, kind, false, 90, 1, in.ReceivedAt); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if _, err := s.ConfigureWindowsResource(ctx, in, kind, false, 90, 0, in.ReceivedAt); err == nil {
				t.Fatal("stale policy saved")
			}
			if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ConfigureWindowsResource(ctx, in, kind, false, 90, 1, in.ReceivedAt); err == nil {
				t.Fatal("failed disk saved")
			}
			if _, err := s.db.Exec("PRAGMA query_only=OFF"); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, resourceRaw(t, s, id, kind)) {
				t.Fatal("failure changed retained state")
			}
			other := windowsresource.CPU
			if kind == other {
				other = windowsresource.Memory
			}
			bad := bytes.Replace(raw, []byte(`"metric":"`+string(kind)+`"`), []byte(`"metric":"`+string(other)+`"`), 1)
			if _, err := s.db.Exec("UPDATE windows_resource_devices SET body=? WHERE id=? AND metric=?", bad, id, kind); err != nil {
				t.Fatal(err)
			}
			if _, err := s.WindowsResourceState(ctx, id, kind); err == nil {
				t.Fatal("wrong envelope tag read")
			}
			if _, err := s.EvaluateWindowsResource(ctx, in, kind, in.ReceivedAt, contactEpoch); err == nil {
				t.Fatal("wrong envelope replaced")
			}
			if !bytes.Equal(bad, resourceRaw(t, s, id, kind)) {
				t.Fatal("corruption repaired silently")
			}
		})
	}
}
func TestWindowsResourceOptimisticRacesAndIndependentFloors(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in := resourceInput(1, 0, 95, 95)
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, threshold := range []int{90, 91} {
			wg.Add(1)
			go func(threshold int) {
				defer wg.Done()
				_, err := s.ConfigureWindowsResource(ctx, in, kind, true, threshold, 0, contactAt)
				results <- err
			}(threshold)
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatal("lost revision", kind, success)
		}
	}
	in = resourceInput(1, 60, 95, 95)
	in.Memory.CollectedAt = contactAt.Add(30 * time.Second)
	cpu, err := s.EvaluateWindowsResource(ctx, in, windowsresource.CPU, in.ReceivedAt, contactEpoch)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := s.EvaluateWindowsResource(ctx, in, windowsresource.Memory, in.ReceivedAt, contactEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if cpu.Assessment.CaptureFloor.Equal(*memory.Assessment.CaptureFloor) {
		t.Fatal("source-specific capture floors conflated")
	}
	if _, err = s.ConfigureWindowsResource(ctx, in, windowsresource.CPU, false, 90, 1, in.ReceivedAt); err != nil {
		t.Fatal(err)
	}
	latest, err := s.WindowsResourceState(ctx, in.DeviceID, windowsresource.Memory)
	if err != nil || !reflect.DeepEqual(memory, latest) {
		t.Fatal("CPU change modified RAM", err)
	}
	for _, table := range []string{"windows_capacity_devices", "windows_contact_devices", "health_devices", "health_analyses", "alarm_outbox"} {
		var n int
		if err = s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("cross-contract write", table, n, err)
		}
	}
}
func TestWindowsResourceBoundedDeviceAndMetricAdmission(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	for n := 1; n <= 25; n++ {
		for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
			if _, err := s.ConfigureWindowsResource(ctx, resourceInput(n, 0, 95, 95), kind, true, 90, 0, contactAt); err != nil {
				t.Fatal(n, kind, err)
			}
		}
	}
	states, err := s.WindowsResourceStates(ctx)
	if err != nil || len(states) != 50 {
		t.Fatal("resource bound", len(states), err)
	}
	if _, err = s.ConfigureWindowsResource(ctx, resourceInput(26, 0, 95, 95), windowsresource.CPU, true, 90, 0, contactAt); err == nil {
		t.Fatal("26th device admitted")
	}
	if _, err = s.WindowsResourceState(ctx, resourceInput(1, 0, 95, 95).DeviceID, windowsresource.Kind("disk")); err == nil {
		t.Fatal("disk alias admitted")
	}
}
