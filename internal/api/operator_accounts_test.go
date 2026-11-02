package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/operatorauth"
	"strings"
	"sync"
	"testing"
)

type apiAccountStore struct {
	mu       sync.Mutex
	snapshot operatorauth.AccountSnapshot
}

func (s *apiAccountStore) Load(context.Context) (operatorauth.AccountSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, nil
}
func (s *apiAccountStore) Commit(_ context.Context, tr operatorauth.AccountTransition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.Revision != tr.PreviousRevision {
		return operatorauth.ErrAccountConflict
	}
	s.snapshot = tr.Next
	return nil
}
func TestLiveAccountsAPIRevisionCSRFRedactionAndSelfReset(t *testing.T) {
	const adminID = "operator_00000000000000000000000000000001"
	const workerID = "operator_00000000000000000000000000000002"
	const authorityID = "authority_11111111111111111111111111111111"
	store := &apiAccountStore{snapshot: operatorauth.AccountSnapshot{AuthorityID: authorityID, Profile: "tls", Version: operatorauth.AccountVersion, Revision: 1, Accounts: []operatorauth.AccountRecord{
		{Operator: operatorauth.Operator{ID: adminID, Username: "admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: workerID, Username: "worker", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}, Revision: 1},
	}}}
	auth, err := operatorauth.New(operatorauth.Config{AuthorityStore: store, AuthorityID: authorityID, AuthorityProfile: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	o := newOperatorFixtureWithAuth(t, auth)
	response, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": operatorFixturePassword}, "", nil)
	if response.StatusCode != 200 {
		t.Fatal("login", response.StatusCode)
	}
	csrf := login["csrfToken"].(string)
	response, views := o.call(t, "GET", "/api/auth/accounts", nil, "", nil)
	if response.StatusCode != 200 {
		t.Fatal("views", response.StatusCode)
	}
	raw, _ := json.Marshal(views)
	if strings.Contains(string(raw), "argon2") || strings.Contains(string(raw), operatorFixturePassword) {
		t.Fatal("credential disclosure")
	}
	body := map[string]any{"actorId": workerID, "expectedRevision": 1, "disabled": true, "capabilities": []string{"read"}, "resetSessions": false, "resetPassword": false}
	if r, _ := o.call(t, "POST", "/api/auth/accounts/update", body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing CSRF", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", "/api/auth/accounts/update", body, csrf, nil); r.StatusCode != 200 {
		t.Fatal("disable", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", "/api/auth/accounts/update", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("replayed revision", r.StatusCode)
	}
	body["actorId"] = adminID
	body["disabled"] = false
	body["capabilities"] = []string{"read", "manage_accounts"}
	body["resetSessions"] = true
	body["passwordHash"] = "caller-controlled"
	if r, _ := o.call(t, "POST", "/api/auth/accounts/update", body, csrf, nil); r.StatusCode != 400 {
		t.Fatal("injected verifier", r.StatusCode)
	}
	delete(body, "passwordHash")
	if r, _ := o.call(t, "POST", "/api/auth/accounts/update", body, csrf, nil); r.StatusCode != 200 {
		t.Fatal("self reset cancelled durable commit", r.StatusCode)
	}
	if r, _ := o.call(t, "GET", "/api/auth/accounts", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("old self cookie survived", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": operatorFixturePassword}, "", nil); r.StatusCode != 200 {
		t.Fatal("new epoch login", r.StatusCode)
	}
}
