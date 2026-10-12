package fixture

import (
	"context"
	"crypto/tls"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowssetup"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This synthetic source regression uses the actual public client constructor and
// a test-only TLS listener. It never starts the manual acceptance peer, creates
// an endpoint identity, or invokes native Setup/service/provider operations.
func TestCurrentSetupCompatibilityThroughPublicTLSClient(t *testing.T) {
	var f *Fixture
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.serve(w, r, false)
	}))
	defer server.Close()
	origin := "https://" + server.Listener.Addr().String()
	agentOrigin := "https://127.0.0.1:8444"
	if origin == agentOrigin {
		agentOrigin = "https://127.0.0.1:8445"
	}
	var err error
	f, err = newFixtureMode(context.Background(), origin, agentOrigin, time.Now, profile.InventoryTLS(), true)
	if err != nil {
		t.Fatal("synthetic fixture construction")
	}
	defer f.Close()
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.state.server}}
	server.StartTLS()
	b := f.Bootstrap()
	expected := windowssetup.ExpectedReadAdminV10(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	requests := func() uint64 {
		f.state.mu.Lock()
		defer f.state.mu.Unlock()
		return f.state.requests
	}
	before := f.Snapshot()
	if err := lanclient.CheckWindowsSetupManager(context.Background(), b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM), expected); err != nil {
		t.Fatal("exact current Setup TLS compatibility failed", err)
	}
	if requests() != 1 || f.Snapshot() != before {
		t.Fatal("compatibility did not perform exactly one inert request")
	}
	// The real peer still rejects an older profile and an outage without changing
	// identity state, while the client keeps explicit CA trust and never downgrades.
	old := windowssetup.ExpectedReadAdminV9(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	if lanclient.CheckWindowsSetupManager(context.Background(), b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM), old) == nil || requests() != 1 {
		t.Fatal("old current-fixture contract admitted")
	}
	if lanclient.CheckWindowsSetupManager(context.Background(), b.EnrollmentOrigin, b.Profile, nil, expected) == nil || requests() != 1 {
		t.Fatal("implicit TLS trust admitted")
	}
	f.ToggleUnavailable(true)
	if lanclient.CheckWindowsSetupManager(context.Background(), b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM), expected) == nil || requests() != 2 || f.Snapshot() != before {
		t.Fatal("outage accepted or compatibility mutated identity")
	}
}
