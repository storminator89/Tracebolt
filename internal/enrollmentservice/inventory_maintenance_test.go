package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"path/filepath"
	"testing"
	"time"
)

func TestCompleteOverviewMaintenanceLoopStopsBeforeAnyTick(t *testing.T) {
	for _, s := range []*Service{nil, {}} {
		if e := s.RunInventoryMaintenance(context.Background(), nil); e != ErrConfiguration {
			t.Fatal("invalid runner", e)
		}
	}
	f := newFixture(t, "tls")
	if e := f.service.RunInventoryMaintenance(context.Background(), nil); e != ErrConfiguration {
		t.Fatal("legacy profile started maintenance", e)
	}
	cfg := f.config
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	store, e := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "complete.db"), cfg, f.issuer.IssuerDER())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	service, e := New(store, f.issuer, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = service.RunInventoryMaintenance(ctx, func() { t.Error("canceled loop warned") }); e != nil {
		t.Fatal("canceled loop did not stop", e)
	}
	if e = service.RunInventoryMaintenanceObserved(ctx, nil, func(time.Time, error) { t.Error("canceled loop observed") }); e != nil {
		t.Fatal("canceled observed loop did not stop", e)
	}
}

func TestInventoryMaintenanceObservesSuccessAndFailure(t *testing.T) {
	f := newFixture(t, "tls")
	cfg := f.config
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	store, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "complete.db"), cfg, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	clockCalls := 0
	service, err := New(store, f.issuer, func() time.Time {
		clockCalls++
		return f.now.Add(time.Duration(clockCalls) * time.Millisecond)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, failed := range []bool{false, true} {
		if failed {
			store.Close()
		}
		clockCalls = 0
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		observed := false
		err := service.RunInventoryMaintenanceObserved(ctx, nil, func(at time.Time, err error) {
			observed = true
			if clockCalls != 2 || !at.Equal(f.now.Add(2*time.Millisecond)) || at.Location() != time.UTC {
				t.Error("observer did not receive current UTC completion time", clockCalls, at)
			}
			if (err != nil) != failed {
				t.Error("observer lost completion result", err)
			}
			cancel()
		})
		cancel()
		if err != nil || !observed {
			t.Fatal("maintenance failed to report completion", err, observed)
		}
	}
}
