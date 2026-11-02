package operatorfactorclient

import "testing"

func TestUnknownCapabilityStringsCannotEnterClientStatus(t *testing.T) {
	if validCaps([]string{"read", "private_fixture_value"}) {
		t.Fatal("unknown protocol text was accepted as an output capability")
	}
	if !validCaps([]string{"read", "manage_accounts", "read_customers", "windows_managed_msi_schedule"}) {
		t.Fatal("known explicit grants were rejected")
	}
}
