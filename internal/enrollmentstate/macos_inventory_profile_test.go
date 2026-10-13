package enrollmentstate

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

func TestMacOSInventoryStoreFreshImmutableFence(t *testing.T) {
	cfg := DefaultConfig(binding())
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileMacOSInventory
	if _, err := New(cfg); err == nil {
		t.Fatal("inventory lacks immutable Darwin fence")
	}
	cfg.Platform = "darwin"
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cmd := createCommand(1)
	for _, platform := range []string{"linux", "windows", "macos", "", "freebsd"} {
		cmd.Platform = platform
		if _, err := e.CreateInvitation(context.Background(), cmd); err == nil {
			t.Fatal("foreign platform admitted", platform)
		}
	}
	cmd.Platform = "darwin"
	created, err := e.CreateInvitation(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.EncodeTrustedLedger()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreTrustedLedger(cfg, raw); err != nil {
		t.Fatal(err)
	}
	for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory} {
		other := cfg
		other.Binding.CollectionProfile = collection
		if _, err := RestoreTrustedLedger(other, raw); err == nil {
			t.Fatal("used inventory ledger relabeled", collection)
		}
	}
	for _, platform := range []string{"linux", "windows", "macos"} {
		other := created
		other.Platform = platform
		if ValidateSnapshot(other) == nil {
			t.Fatal("inventory snapshot crossed OS", platform)
		}
	}
	cfg.Binding.Profile = "http-test"
	cfg.Binding.Origin = "http://manager.example"
	if _, err := New(cfg); err == nil {
		t.Fatal("HTTP inventory domain admitted")
	}
}

func TestSnapshotOSProfileMatrixRejectsForeignScope(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory, enrollmentcrypto.CollectionProfileMacOSInventory} {
			for _, platform := range []string{"linux", "windows", "darwin"} {
				cfg := DefaultConfig(binding())
				cfg.Binding.Profile = transport
				if transport == "http-test" {
					cfg.Binding.Origin = "http://manager.example"
				}
				cfg.Binding.CollectionProfile = collection
				if collection == enrollmentcrypto.CollectionProfileMacOSInventory {
					cfg.Platform = "darwin"
				}
				e, err := New(cfg)
				if collection == enrollmentcrypto.CollectionProfileMacOSInventory && transport != "tls" {
					if err == nil {
						t.Fatal("HTTP inventory configured")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				cmd := createCommand(1)
				cmd.Platform = platform
				_, err = e.CreateInvitation(context.Background(), cmd)
				if (err == nil) != enrollmentcrypto.ValidPlatformCollectionProfile(platform, transport, collection) {
					t.Fatalf("state matrix %s/%s/%s: %v", platform, transport, collection, err)
				}
			}
		}
	}
}
