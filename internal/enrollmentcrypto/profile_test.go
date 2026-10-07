package enrollmentcrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestOrdinaryGeneratedProofsBindSelectedCollectionProfile(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, profile := range []string{"tls", "http-test"} {
		for _, collection := range []string{CollectionProfile, CollectionProfileOperational, CollectionProfilePackages, CollectionProfileComplete} {
			t.Run(profile+"/"+collection, func(t *testing.T) {
				c := contextFixture(profile, now)
				c.CollectionProfile = collection
				raw, claim, _, _, _ := claimFixture(t, c, now)
				if claim.CollectionProfile() != collection {
					t.Fatal("claim profile not retained")
				}
				other := c
				other.CollectionProfile = CollectionProfileOperational
				if collection == CollectionProfileOperational {
					other.CollectionProfile = CollectionProfile
				}
				if _, err := VerifyClaim(raw, other, now); err == nil {
					t.Fatal("claim accepted different selected profile")
				}
				for _, purpose := range []string{PurposeStatus, PurposeCredential} {
					raw, key := statusFixture(t, c, purpose, now)
					if _, err := VerifyStatus(raw, key, c, now); err != nil {
						t.Fatal("selected status rejected")
					}
					if _, err := VerifyStatus(raw, key, other, now); err == nil {
						t.Fatal("status accepted different selected profile")
					}
				}
				f := certificateFixture(t, profile, now, collection)
				cert, err := VerifyIssued(f.leaf, f.issuer, f.intent, now)
				if err != nil || cert.Intent().CollectionProfile != collection {
					t.Fatal("selected intent rejected")
				}
				request := testID("request_", 23)
				message, err := ActivationSigningMessage(f.context, f.intent, request, cert.CertificateHash(), now)
				if err != nil {
					t.Fatal("activation context rejected")
				}
				body := map[string]string{"schemaVersion": ActivationVersion, "managerInstanceId": f.intent.ManagerInstanceID, "profile": profile, "origin": f.intent.Origin, "deviceId": f.intent.DeviceID, "intentId": f.intent.IntentID, "certificateHash": cert.CertificateHash(), "requestId": request, "challenge": f.context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.endpointKey, message))}
				raw, _ = json.Marshal(body)
				if _, err := VerifyActivation(raw, cert, f.context, now); err != nil {
					t.Fatal("selected activation rejected")
				}
				if _, err := VerifyActivation(raw, cert, other, now); err == nil {
					t.Fatal("activation accepted different selected profile")
				}
				changed := f.intent
				changed.CollectionProfile = other.CollectionProfile
				a, _ := IntentDigest(f.intent)
				b, _ := IntentDigest(changed)
				if a == b {
					t.Fatal("intent digest omitted collection profile")
				}
			})
		}
	}
	for _, unknown := range []string{"", "managed-operations-v99", "Managed-operations-v1", " managed-operations-v1"} {
		if ValidCollectionProfile(unknown) {
			t.Fatal("unknown profile allowed")
		}
	}
}

func TestImplementedCollectionProofDomainsRemainDistinct(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profiles := []string{CollectionProfile, CollectionProfileOperational, CollectionProfilePackages, CollectionProfileComplete, CollectionProfileWindowsInventory}
	for _, selected := range profiles {
		c := contextFixture("tls", now)
		c.CollectionProfile = selected
		raw, _, _, _, _ := claimFixture(t, c, now)
		for _, other := range profiles {
			altered := c
			altered.CollectionProfile = other
			_, err := VerifyClaim(raw, altered, now)
			if (selected == other) != (err == nil) {
				t.Fatal("selected collection proof domain not exact")
			}
		}
	}
}

func TestWindowsInventoryConsentIsSeparateFromLinuxManagedProfiles(t *testing.T) {
	if !ValidCollectionProfile(CollectionProfileWindowsInventory) || ManagedCollectionProfile(CollectionProfileWindowsInventory) {
		t.Fatal("Windows consent must remain valid and outside Linux managed profiles")
	}
}
