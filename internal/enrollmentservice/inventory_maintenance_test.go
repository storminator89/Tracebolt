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
}
