package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

// SelfClaim creates a fresh TLS pending claim atomically. It does not
// approve a device, issue a certificate or activate telemetry. The client creates
// its own high-entropy proof material; no invitation needs manual transfer.
// Existing invitation records can only be retried when this exact self-claim
// created them. A conventional invitation can never be adopted through here.
func (s *Store) SelfClaim(ctx context.Context, proof enrollmentcrypto.VerifiedClaim, now int64) (enrollmentstate.Snapshot, error) {
	if s == nil || s.storeState == nil {
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrProof
	}
	platform := SelfRegistrationPlatform(s.config)
	if platform == "" || !proof.Valid() || proof.Profile() != "tls" || proof.CollectionProfile() != s.config.Binding.CollectionProfile || proof.RenewalPolicy() != "" {
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrProof
	}
	createID := selfClaimCreationIDForPlatform(platform, proof.InvitationID())
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) {
		current, err := t.engine.Get(proof.InvitationID())
		if errors.Is(err, enrollmentstate.ErrNotFound) {
			hash := proof.InvitationHash()
			current, err = t.engine.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: proof.InvitationID(), RequestID: createID, InvitationHash: hex.EncodeToString(hash[:]), Platform: platform, Now: now})
		} else if err == nil && current.CreateRequestID != createID {
			return enrollmentstate.Snapshot{}, enrollmentstate.ErrConflict
		}
		if err != nil {
			return enrollmentstate.Snapshot{}, err
		}
		return t.engine.Claim(ctx, enrollmentstate.ClaimCommand{Control: enrollmentstate.Control{InvitationID: proof.InvitationID(), RequestID: proof.RequestID(), ExpectedRevision: current.Revision, Now: now}, ClaimID: proof.ClaimID()}, proof)
	})
}

func selfClaimCreationID(invitationID string) string {
	creation := sha256.Sum256([]byte("Tracebolt Windows self-registration creation v1\x00" + invitationID))
	return "request_" + hex.EncodeToString(creation[:16])
}

// SelfRegistrationPlatform derives identity exclusively from the configured domain.
// Legacy unfenced Linux stores remain Linux; macOS always requires its explicit fence.
// Renewal domains retain their separate explicit local-consent workflow.
func SelfRegistrationPlatform(config enrollmentstate.Config) string {
	if config.Binding.Profile != "tls" || config.AutomaticRenewal {
		return ""
	}
	platform := config.Platform
	if platform == "" {
		platform = "linux"
		if config.Binding.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory {
			platform = "windows"
		}
	}
	if !enrollmentcrypto.ValidPlatformCollectionProfile(platform, config.Binding.Profile, config.Binding.CollectionProfile) {
		return ""
	}
	return platform
}

func selfClaimCreationIDForPlatform(platform, invitationID string) string {
	if platform == "windows" {
		return selfClaimCreationID(invitationID)
	}
	creation := sha256.Sum256([]byte("Tracebolt " + platform + " self-registration creation v1\x00" + invitationID))
	return "request_" + hex.EncodeToString(creation[:16])
}

// IsSelfRegistration is an operator display hint, never an authorization check.
func IsSelfRegistration(snapshot enrollmentstate.Snapshot) bool {
	return enrollmentcrypto.ValidPlatformCollectionProfile(snapshot.Platform, snapshot.Binding.Profile, snapshot.Binding.CollectionProfile) && snapshot.Binding.Profile == "tls" && snapshot.CreateRequestID == selfClaimCreationIDForPlatform(snapshot.Platform, snapshot.InvitationID)
}
