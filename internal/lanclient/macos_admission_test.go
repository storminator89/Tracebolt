package lanclient

import (
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

func TestMacOSConfigAdmitsOnlyBasicGuidedTLS(t *testing.T) {
	for _, schema := range []string{ConfigVersion, GuidedConfigVersion, RenewalConfigVersion, OperationalConfigVersion, PackageConfigVersion, CompleteConfigVersion, WindowsInventoryConfigVersion, WindowsRenewalConfigVersion, ""} {
		for _, profile := range []string{"tls", "http-test", ""} {
			for _, collection := range []string{"", enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory} {
				c := Config{SchemaVersion: schema, Profile: profile, CollectionProfile: collection}
				want := profile == "tls" && (schema == GuidedConfigVersion && collection == "" || schema == RenewalConfigVersion && collection == enrollmentcrypto.CollectionProfile)
				if c.platformAllowed("darwin") != want {
					t.Fatalf("Darwin admitted wrong source profile: %s/%s/%s", schema, profile, collection)
				}
			}
		}
	}
}
