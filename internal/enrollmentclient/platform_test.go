package enrollmentclient

import (
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"testing"
)

// These injected-platform checks do not open files, make network requests,
// generate credentials, install services or require a Windows test host.
func TestPlatformBootstrapAdmission(t *testing.T) {
	for _, runningOS := range []string{"linux", "windows", "darwin", "", "Windows"} {
		for _, transport := range []string{"tls", "http-test", "unknown"} {
			for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory, "unknown", ""} {
				t.Run(runningOS+"/"+transport+"/"+collection, func(t *testing.T) {
					b := Bootstrap{Profile: transport, CollectionProfile: collection}
					allowed := (transport == "tls" || transport == "http-test") && enrollmentcrypto.ValidCollectionProfile(collection) && (runningOS == "linux" && collection != enrollmentcrypto.CollectionProfileWindowsInventory || runningOS == "windows" && (transport == "tls" && collection == enrollmentcrypto.CollectionProfile || collection == enrollmentcrypto.CollectionProfileWindowsInventory))
					err := validatePlatformBootstrap(b, runningOS)
					if allowed && err != nil || !allowed && !errors.Is(err, ErrBootstrap) {
						t.Fatalf("admission = %v, allowed = %v", err, allowed)
					}
				})
			}
		}
	}
}

func TestSnapshotPlatformMustMatchTrustedRuntime(t *testing.T) {
	for _, runningOS := range []string{"linux", "windows", "darwin", ""} {
		for _, remotePlatform := range []string{"linux", "windows", "darwin", ""} {
			for _, transport := range []string{"tls", "http-test"} {
				for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory} {
					t.Run(runningOS+"/"+remotePlatform+"/"+transport+"/"+collection, func(t *testing.T) {
						b := Bootstrap{Profile: transport, CollectionProfile: collection}
						v := enrollmentstate.Snapshot{Platform: remotePlatform}
						allowed := remotePlatform == runningOS && (runningOS == "linux" && collection != enrollmentcrypto.CollectionProfileWindowsInventory || runningOS == "windows" && (transport == "tls" && collection == enrollmentcrypto.CollectionProfile || collection == enrollmentcrypto.CollectionProfileWindowsInventory))
						err := validatePlatformSnapshot(v, b, runningOS)
						if allowed && err != nil || !allowed && !errors.Is(err, ErrResponse) {
							t.Fatalf("platform response = %v, allowed = %v", err, allowed)
						}
					})
				}
			}
		}
	}
}
