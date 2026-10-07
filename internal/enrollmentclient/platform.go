package enrollmentclient

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

// validatePlatformBootstrap is a pure admission check. Production callers pass
// runtime.GOOS, never a platform claimed by bootstrap data or a remote response.
// It precedes opening private state, generating keys or making any request.
func validatePlatformBootstrap(b Bootstrap, runningOS string) error {
	if (b.Profile != "tls" && b.Profile != "http-test") || !enrollmentcrypto.ValidCollectionProfile(b.CollectionProfile) {
		return ErrBootstrap
	}
	switch runningOS {
	case "linux":
		if b.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
			return nil
		}
	case "windows":
		if b.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory || b.Profile == "tls" && b.CollectionProfile == enrollmentcrypto.CollectionProfile {
			return nil
		}
	}
	return ErrBootstrap
}

// The endpoint platform is a local invariant, not authority supplied by the
// manager. This does not add a platform field to the established Linux ledger
// or reinterpret any existing collection profile as expanded Windows consent.
func validatePlatformSnapshot(v enrollmentstate.Snapshot, b Bootstrap, runningOS string) error {
	if validatePlatformBootstrap(b, runningOS) != nil || v.Platform != runningOS {
		return ErrResponse
	}
	return nil
}
