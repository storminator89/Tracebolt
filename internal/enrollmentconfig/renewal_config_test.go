package enrollmentconfig

import (
	"localrmm/internal/lanconfig"
	"testing"
)

func TestAutomaticRenewalConfigIsExplicitFreshTLSOnly(t *testing.T) {
	for _, tc := range []struct {
		name, schema, profile string
		enabled, want         bool
	}{
		{"legacy-default", SchemaVersion, "tls", false, true},
		{"legacy-cannot-enable", SchemaVersion, "tls", true, false},
		{"fresh-without-consent", RenewableSchemaVersion, "tls", false, false},
		{"fresh-tls", RenewableSchemaVersion, "tls", true, true},
		{"fresh-http", RenewableSchemaVersion, "http-test", true, false},
		{"unknown-version", "tracebolt.enrollment-config.v99", "tls", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{SchemaVersion: tc.schema, Profile: tc.profile, AutomaticRenewal: tc.enabled}
			if validRenewalConfig(c, lanconfig.Config{Profile: tc.profile}) != tc.want {
				t.Fatal("fresh renewal policy admission mismatch")
			}
		})
	}
	if validRenewalConfig(Config{SchemaVersion: RenewableSchemaVersion, Profile: "tls", AutomaticRenewal: true}, lanconfig.Config{Profile: "http-test"}) {
		t.Fatal("mismatched transport enabled renewal")
	}
}
