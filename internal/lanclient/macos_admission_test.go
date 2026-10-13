package lanclient

import (
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

func TestMacOSConfigAdmitsOnlyBasicGuidedTLS(t *testing.T) {
	for _, schema := range []string{ConfigVersion, GuidedConfigVersion, RenewalConfigVersion, OperationalConfigVersion, PackageConfigVersion, CompleteConfigVersion, WindowsInventoryConfigVersion, WindowsRenewalConfigVersion, ""} {
		for _, profile := range []string{"tls", "http-test", ""} {
			for _, collection := range []string{"", enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory, enrollmentcrypto.CollectionProfileMacOSInventory} {
				c := Config{SchemaVersion: schema, Profile: profile, CollectionProfile: collection}
				want := profile == "tls" && (schema == GuidedConfigVersion && collection == "" || schema == RenewalConfigVersion && collection == enrollmentcrypto.CollectionProfile)
				if c.platformAllowed("darwin") != want {
					t.Fatalf("Darwin admitted wrong source profile: %s/%s/%s", schema, profile, collection)
				}
			}
		}
	}
}

func TestLANConfigPlatformMatrixHasNoForeignProfileFallback(t *testing.T) {
	for _, os := range []string{"linux", "windows", "darwin", "macos", "freebsd", ""} {
		for _, schema := range []string{ConfigVersion, GuidedConfigVersion, RenewalConfigVersion, OperationalConfigVersion, PackageConfigVersion, CompleteConfigVersion, WindowsInventoryConfigVersion, WindowsRenewalConfigVersion, "unknown"} {
			c := Config{SchemaVersion: schema, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileMacOSInventory}
			if c.platformAllowed(os) {
				t.Fatalf("generic sender accepted fresh Mac profile on %s/%s", os, schema)
			}
		}
	}
	for _, c := range []Config{
		{SchemaVersion: OperationalConfigVersion, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileOperational},
		{SchemaVersion: PackageConfigVersion, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfilePackages},
		{SchemaVersion: CompleteConfigVersion, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileComplete},
	} {
		for _, os := range []string{"linux", "windows", "darwin", "freebsd", ""} {
			if c.platformAllowed(os) != (os == "linux") {
				t.Fatalf("managed profile crossed OS %s/%s", os, c.CollectionProfile)
			}
		}
	}
}
