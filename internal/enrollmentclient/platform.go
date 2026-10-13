package enrollmentclient

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

// validatePlatformBootstrap is a pure admission check. Production callers pass
// runtime.GOOS, never a platform claimed by bootstrap data or a remote response.
// It precedes opening private state, generating keys or making any request.
func validatePlatformBootstrap(b Bootstrap, runningOS string) error {
	// The manager domain and inert sender contract do not grant this generic
	// enrollment entry point fresh local inventory consent or a client schema.
	if b.CollectionProfile == enrollmentcrypto.CollectionProfileMacOSInventory {
		return ErrBootstrap
	}
	if enrollmentcrypto.ValidPlatformCollectionProfile(runningOS, b.Profile, b.CollectionProfile) {
		return nil
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
