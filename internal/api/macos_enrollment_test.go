package api

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"slices"
	"testing"
)

func TestPrimaryEnrollmentNeverAdvertisesMacOS(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory} {
			got := enrollmentPlatforms(enrollmentstate.Binding{Profile: profile, CollectionProfile: collection})
			want := []string{"linux"}
			if collection == enrollmentcrypto.CollectionProfileWindowsInventory {
				want = []string{"windows"}
			}
			if !slices.Equal(got, want) {
				t.Fatal("UI advertised incompatible scope", profile, collection, got)
			}
		}
	}
}
