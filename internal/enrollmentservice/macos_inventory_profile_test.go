package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"path/filepath"
	"testing"
	"time"
)

func TestMacOSInventoryDeviceProjectionIsScopeOnly(t *testing.T) {
	f := newFixture(t, "tls")
	f.config.Platform = "darwin"
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileMacOSInventory
	f.path = filepath.Join(t.TempDir(), "private", "macos-inventory.db")
	f.restart(t)
	ctx := context.Background()
	pending, _ := claimForPlatform(t, f, "darwin")
	if _, err := f.service.Approve(ctx, pending.InvitationID, id("request", 40), pending.Claim.KeyFingerprint, pending.Revision); err != nil {
		t.Fatal(err)
	}
	rows, err := f.service.Devices(ctx, f.now)
	if err != nil || len(rows) != 1 {
		t.Fatal("projection", err)
	}
	d := rows[0]
	if d.Platform != "macos" || d.Status != "unknown" || !d.LastSeen.IsZero() || len(d.Evidence) != 0 || d.CPU.Value != nil || d.Memory.Value != nil || d.Disk.Value != nil {
		t.Fatal("scope projected as observation")
	}
	found := false
	for _, c := range d.Capabilities {
		if c.ID == "macos_inventory" {
			found = true
			if c.Status != "scope" {
				t.Fatal("scope became observed authority")
			}
		}
		if c.ID == "systemd" || c.ID == "package_inventory" || c.ID == "remote_actions" {
			t.Fatal("foreign authority projected")
		}
	}
	if !found {
		t.Fatal("fresh capability absent")
	}
}

func TestMacOSInventoryMaintenanceObserverCancellation(t *testing.T) {
	f := newFixture(t, "tls")
	f.service.binding.CollectionProfile = enrollmentcrypto.CollectionProfileMacOSInventory
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.service.RunMacOSInventoryMaintenanceObserved(ctx, func() { t.Error("canceled loop warned") }, func(time.Time, error) { t.Error("canceled loop observed") }); err != nil {
		t.Fatal("canceled observed loop did not stop", err)
	}
	for _, service := range []*Service{nil, {}} {
		if err := service.RunMacOSInventoryMaintenanceObserved(ctx, nil, func(time.Time, error) { t.Error("invalid loop observed") }); err != ErrConfiguration {
			t.Fatal("invalid observed runner accepted", err)
		}
	}
}
