//go:build linux

package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
)

// This is server-wide protocol capability metadata, never a pre-authentication
// query of a particular account's enrollment or credentials.
func TestFactorLoginProfileIsServerWideAndTLSOnly(t *testing.T) {
	_, _, live := lifecycleJournal(t)
	fixture := newOperatorFixtureWithAuth(t, live)
	response, view := fixture.call(t, http.MethodGet, "/api/auth/session", nil, "", nil)
	if response.StatusCode != http.StatusOK || view["loginFactorProfile"] != "totp-sha256-8" || view["authenticated"] != false {
		t.Fatal("live TLS bootstrap did not advertise the global factor protocol")
	}
	// Neither fixture account is enrolled yet. Metadata cannot reveal per-account
	// factor status, and factorless login remains the unchanged two-field request.
	response, view = fixture.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": "admin", "password": operatorFixturePassword}, "", nil)
	if response.StatusCode != http.StatusOK || view["loginFactorProfile"] != "totp-sha256-8" {
		t.Fatal("live login lost its validated protocol profile")
	}
	for _, mode := range []string{"shared", "named"} {
		t.Run(mode, func(t *testing.T) {
			config := operatorauth.Config{PasswordHash: testOperatorHash()}
			if mode == "named" {
				config = operatorauth.Config{Operators: []operatorauth.Operator{{ID: lifecycleAdminID, Username: "admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}}
			}
			auth, err := operatorauth.New(config)
			if err != nil {
				t.Fatal(err)
			}
			legacy := newOperatorFixtureWithAuth(t, auth)
			response, view := legacy.call(t, http.MethodGet, "/api/auth/session", nil, "", nil)
			if _, present := view["loginFactorProfile"]; response.StatusCode != http.StatusOK || present {
				t.Fatal("static authentication falsely advertised a factor protocol")
			}
		})
	}
	_, err := NewLANOperatorHandler(fixture.app, LANOperatorConfig{
		Origin: "http://127.0.0.1:12345", Auth: live, Registry: fixture.registry,
		InsecureHTTPTest: true, Devices: func() ([]model.Device, error) { return nil, nil },
	})
	if err == nil {
		t.Fatal("live TLS authority was reused on the plaintext test surface")
	}
	development, err := json.Marshal(fixture.app.developmentAuthView())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(development, &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["loginFactorProfile"]; present {
		t.Fatal("development mode advertised LAN factor authentication")
	}
}
