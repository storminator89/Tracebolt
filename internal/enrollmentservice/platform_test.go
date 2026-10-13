package enrollmentservice

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"path/filepath"
	"testing"
)

func TestInvitationPlatformProfileAdmission(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory, enrollmentcrypto.CollectionProfileMacOSInventory} {
			t.Run(transport+"/"+collection, func(t *testing.T) {
				if transport == "http-test" && collection == enrollmentcrypto.CollectionProfileMacOSInventory {
					return
				}
				f := newFixture(t, transport)
				if collection != f.config.Binding.CollectionProfile {
					f.config.Binding.CollectionProfile = collection
					if collection == enrollmentcrypto.CollectionProfileMacOSInventory {
						f.config.Platform = "darwin"
					}
					f.path = filepath.Join(t.TempDir(), "private", "platform.db")
					f.restart(t)
				}
				ctx := context.Background()
				accepted := 0
				for n, platform := range []string{"darwin", "", "Windows", "windows", "linux"} {
					created, err := f.service.CreateInvitation(ctx, id("request", n+1), platform)
					allowed := platform == "darwin" && collection == enrollmentcrypto.CollectionProfileMacOSInventory || platform == "linux" && (collection == enrollmentcrypto.CollectionProfile || enrollmentcrypto.ManagedCollectionProfile(collection)) || platform == "windows" && (collection == enrollmentcrypto.CollectionProfileWindowsInventory || transport == "tls" && collection == enrollmentcrypto.CollectionProfile)
					if allowed {
						if err != nil {
							t.Fatalf("%s invitation rejected: %v", platform, err)
						}
						v := created.Snapshot()
						if enrollmentstate.ValidateSnapshot(v) != nil || v.Platform != platform || v.Binding != f.config.Binding || created.Secret() == "" {
							t.Fatal("admitted invitation changed its platform/profile binding")
						}
						accepted++
					} else if !errors.Is(err, ErrPlatform) || created.Secret() != "" {
						t.Fatalf("%q unsupported admission result: %v", platform, err)
					}
					rows, err := f.service.Snapshots(ctx)
					if err != nil || len(rows) != accepted {
						t.Fatal("rejected platform changed durable enrollment records", err)
					}
				}
				f.restart(t)
				rows, err := f.service.Snapshots(ctx)
				if err != nil || len(rows) != accepted {
					t.Fatal("platform admission did not survive existing-store reopen", err)
				}
			})
		}
	}
}
