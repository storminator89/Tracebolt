package main

import (
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

func TestWindowsBootstrapMustMatchExplicitLocalProfile(t *testing.T) {
	profiles := []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileWindowsInventory, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete, ""}
	for _, selected := range profiles {
		for _, remote := range profiles {
			for _, transport := range []string{"tls", "http-test", ""} {
				allowed := selected == remote && transport == "tls" && (selected == enrollmentcrypto.CollectionProfile || selected == enrollmentcrypto.CollectionProfileWindowsInventory)
				err := validateWindowsBootstrapProfile(enrollmentclient.Bootstrap{Profile: transport, CollectionProfile: remote}, selected)
				if (err == nil) != allowed {
					t.Fatal("Windows bootstrap changed local scope")
				}
			}
		}
	}
}

func TestWindowsInventoryHTTPRequiresBothExplicitAcknowledgements(t *testing.T) {
	for _, selected := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileWindowsInventory} {
		for _, profile := range []string{"tls", "http-test"} {
			for _, acknowledged := range []bool{false, true} {
				b := enrollmentclient.Bootstrap{Profile: profile, CollectionProfile: selected}
				allowed := profile == "tls" && !acknowledged || selected == enrollmentcrypto.CollectionProfileWindowsInventory && profile == "http-test" && acknowledged
				if (validateWindowsBootstrapConsent(b, selected, acknowledged) == nil) != allowed {
					t.Fatal("transport/scope acknowledgement not exact")
				}
			}
		}
	}
}
