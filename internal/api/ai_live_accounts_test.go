package api

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"localrmm/internal/operatorauth"
)

// Live accounts are named accounts. They currently have no AI-administration
// capability: even ManageAccounts must not implicitly authorize provider I/O.
// This exercises the real TLS route, not an internal AI-handler bypass. It does
// not claim to exercise in-flight live-account AI cancellation, which cannot be
// reached under the current named-route policy.
func TestLiveAccountsCannotStartPersonalAIBeforeOrAfterReset(t *testing.T) {
	const actorID = "operator_00000000000000000000000000000001"
	const authorityID = "authority_11111111111111111111111111111111"
	accounts := &apiAccountStore{snapshot: operatorauth.AccountSnapshot{
		AuthorityID: authorityID, Profile: "tls", Version: operatorauth.AccountVersion, Revision: 1,
		Accounts: []operatorauth.AccountRecord{{Operator: operatorauth.Operator{ID: actorID, Username: "admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1}},
	}}
	auth, err := operatorauth.New(operatorauth.Config{AuthorityStore: accounts, AuthorityID: authorityID, AuthorityProfile: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	o := newOperatorFixtureWithAuth(t, auth)
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); completion(w, providerFixtureFindings) }))
	defer provider.Close()
	// Configure only the source fixture's existing shared/developer surface, so
	// denial cannot be explained by an unconfigured provider or stale revision.
	fixtureApp := setup(t)
	configured := configure(t, fixtureApp, provider.URL+"/v1", "")
	o.app.ai = fixtureApp.ai // Install configured source fixture before any TLS request.
	login := func() string {
		response, value := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": operatorFixturePassword}, "", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatal("live login", response.StatusCode)
		}
		return value["csrfToken"].(string)
	}
	checkDenied := func(csrf string, want int) {
		t.Helper()
		for _, path := range []string{"/api/ai/test", "/api/cases/case-demo-win-01-service/analyze"} {
			body := map[string]any{"configRevision": configured.Revision}
			if path == "/api/ai/test" {
				body["acknowledgeTest"] = true
			}
			response, value := o.call(t, "POST", path, body, csrf, nil)
			if response.StatusCode != want {
				t.Fatalf("%s: status %d, want %d", path, response.StatusCode, want)
			}
			if value["status"] == "passed" || value["ai"] != nil || value["findings"] != nil {
				t.Fatal("denied route disclosed AI result")
			}
		}
		if calls.Load() != 0 {
			t.Fatal("live named account contacted provider")
		}
		o.app.ai.mu.Lock()
		busy, owner := o.app.ai.busy, o.app.ai.activeOwner
		o.app.ai.mu.Unlock()
		if busy || owner != "" {
			t.Fatal("denied route reserved personal AI slot")
		}
	}
	csrf := login()
	checkDenied(csrf, http.StatusForbidden)
	response, _ := o.call(t, "POST", "/api/auth/accounts/update", map[string]any{
		"actorId": actorID, "expectedRevision": 1, "disabled": false,
		"capabilities": []string{"read", "manage_accounts"}, "resetSessions": true, "resetPassword": false,
	}, csrf, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("live self reset", response.StatusCode)
	}
	checkDenied(csrf, http.StatusUnauthorized)
	checkDenied(login(), http.StatusForbidden)
}
