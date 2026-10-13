package enrollmentclient

import (
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

func TestMacOSRouteSelectionUsesTrustedRuntimeOnly(t *testing.T) {
	for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory, "/remote/route"} {
		if enrollmentPathPrefix(collection, "darwin") != MacOSEnrollmentPathPrefix {
			t.Fatal("remote profile redirected Darwin route")
		}
	}
	if enrollmentPathPrefix(enrollmentcrypto.CollectionProfile, "linux") != "/v2/enrollment/" || enrollmentPathPrefix(enrollmentcrypto.CollectionProfileWindowsInventory, "windows") != WindowsEnrollmentPathPrefix {
		t.Fatal("historical routes changed")
	}
}
