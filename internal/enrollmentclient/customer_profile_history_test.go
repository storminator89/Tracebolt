package enrollmentclient

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHistoricalCustomerProfileTrustDoesNotAuthorizeCurrentTransport(t *testing.T) {
	// The entire original public chain expired well before the actual clock.
	original := time.Now().UTC().Truncate(time.Second).Add(-72 * time.Hour)
	p := customerProfileFixture(t, original)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{original, original.Add(23*time.Hour + 59*time.Minute)} {
		got, err := ValidateCustomerProfileAt(raw, at)
		if err != nil || got.InstallerProfileID != p.InstallerProfileID {
			t.Fatal("valid historical profile rejected", err)
		}
	}
	if _, err := ValidateCustomerProfileAt(raw, original.Add(24*time.Hour)); err == nil {
		t.Fatal("expired historical issuer accepted")
	}
	if _, _, err := ParseCustomerProfile(raw, time.Now().UTC()); err == nil {
		t.Fatal("historical trust enabled current transport")
	}
}

func TestHistoricalCustomerProfileRejectsWrongCAOriginAndIssuer(t *testing.T) {
	original := time.Now().UTC().Truncate(time.Second).Add(-72 * time.Hour)
	p := customerProfileFixture(t, original)
	expiredCA := customerProfileFixture(t, original.Add(-72*time.Hour))
	for name, mutate := range map[string]func(*CustomerProfile){
		"expired server CA":    func(v *CustomerProfile) { v.ServerCAPEM = expiredCA.ServerCAPEM },
		"wrong issuer root":    func(v *CustomerProfile) { v.IssuerRootPEM = expiredCA.IssuerRootPEM },
		"untrusted origin":     func(v *CustomerProfile) { v.AgentOrigin = "http://agent.example.test" },
		"credential in origin": func(v *CustomerProfile) { v.EnrollmentOrigin = "https://user@manager.example.test" },
		"multicast origin":     func(v *CustomerProfile) { v.AgentOrigin = "https://224.0.0.1" },
		"duplicated server CA": func(v *CustomerProfile) { v.ServerCAPEM += v.ServerCAPEM },
		"private block in public CA": func(v *CustomerProfile) {
			v.ServerCAPEM += "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			mutate(&bad)
			raw, _ := json.Marshal(bad)
			if _, err := ValidateCustomerProfileAt(raw, original); err == nil {
				t.Fatal("invalid historical trust accepted")
			}
		})
	}
}
