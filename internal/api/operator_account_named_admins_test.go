//go:build linux

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"localrmm/internal/operatorauth"
)

// Exercise only the v3 account-administration surface, not the still-denied
// enrollment/trust/customer/AI routes or full TB-06 acceptance.
func TestLiveAccountNamedAdministratorsPersistActualRequesters(t *testing.T) {
	const secondID = "operator_00000000000000000000000000000003"
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "accounts.jsonl")
	initial := operatorauth.AccountSnapshot{Version: operatorauth.AccountVersion, AuthorityID: lifecycleAuthorityID, Profile: "tls", Revision: 1, Accounts: []operatorauth.AccountRecord{
		{Operator: operatorauth.Operator{ID: lifecycleAdminID, Username: "admin-a", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: secondID, Username: "admin-b", PasswordHash: lifecyclePasswordHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: lifecycleWorkerID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}, Revision: 1},
	}}
	journal, err := operatorauth.CreateAccountJournal(path, initial)
	if err != nil {
		t.Fatal("public protected journal", err)
	}
	defer journal.Close()
	auth, err := operatorauth.New(operatorauth.Config{AuthorityStore: journal, AuthorityID: lifecycleAuthorityID, AuthorityProfile: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	a := newOperatorFixtureWithAuth(t, auth)
	b, reader := lifecycleClient(a), lifecycleClient(a)
	csrfA, tokenA := lifecycleLogin(t, a, "admin-a", operatorFixturePassword)
	csrfB, tokenB := lifecycleLogin(t, b, "admin-b", lifecycleNewPassword)
	csrfReader, readerToken := lifecycleLogin(t, reader, "reader", operatorFixturePassword)
	change := func(revision uint64) map[string]any {
		return map[string]any{"actorId": lifecycleWorkerID, "expectedRevision": revision, "disabled": false, "capabilities": []string{"read"}, "resetSessions": true, "resetPassword": false}
	}
	for _, client := range []operatorFixture{a, b} {
		if response, _ := client.call(t, "GET", "/api/auth/accounts", nil, "", nil); response.StatusCode != http.StatusOK {
			t.Fatal("account administrator denied", response.StatusCode)
		}
	}
	if response, _ := reader.call(t, "GET", "/api/auth/accounts", nil, "", nil); response.StatusCode != http.StatusForbidden {
		t.Fatal("reader listed accounts", response.StatusCode)
	}
	// actorId selects a target; even naming an administrator cannot impersonate it.
	forgedTarget := change(1)
	forgedTarget["actorId"] = lifecycleAdminID
	if response, _ := reader.call(t, "POST", "/api/auth/accounts/update", forgedTarget, csrfReader, nil); response.StatusCode != http.StatusForbidden {
		t.Fatal("target identity conferred administrator authority", response.StatusCode)
	}
	injected := change(1)
	injected["requesterId"] = secondID
	if response, _ := a.call(t, "POST", "/api/auth/accounts/update", injected, csrfA, nil); response.StatusCode != http.StatusBadRequest {
		t.Fatal("caller supplied requester accepted", response.StatusCode)
	}
	if response, _ := a.call(t, "POST", "/api/auth/accounts/update", change(1), csrfB, nil); response.StatusCode != http.StatusForbidden {
		t.Fatal("another administrator's CSRF accepted", response.StatusCode)
	}
	snapshot, err := journal.Load(context.Background())
	if err != nil || snapshot.Revision != 1 {
		t.Fatal("rejected requests changed authority", err)
	}
	if _, err := auth.Lookup(readerToken); err != nil {
		t.Fatal("rejected requests revoked reader", err)
	}
	for i, update := range []struct {
		client operatorFixture
		csrf   string
	}{{a, csrfA}, {b, csrfB}} {
		if response, _ := update.client.call(t, "POST", "/api/auth/accounts/update", change(uint64(i+1)), update.csrf, nil); response.StatusCode != http.StatusOK {
			t.Fatal("named administrator update", response.StatusCode)
		}
		if _, err := auth.Lookup(readerToken); err == nil {
			t.Fatal("target session survived reset")
		}
		for _, token := range []string{tokenA, tokenB} {
			if _, err := auth.Lookup(token); err != nil {
				t.Fatal("independent administrator revoked", err)
			}
		}
		for _, client := range []operatorFixture{a, b} {
			if response, _ := client.call(t, "GET", "/api/auth/accounts", nil, "", nil); response.StatusCode != http.StatusOK {
				t.Fatal("independent administrator cannot continue", response.StatusCode)
			}
		}
		_, readerToken = lifecycleLogin(t, reader, "reader", operatorFixturePassword)
	}
	// Inspect actual persisted frames, never a mock store or response-only actor.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var audits []operatorauth.AccountAudit
	frames := 0
	for {
		var frame struct {
			Audit *operatorauth.AccountAudit `json:"audit"`
		}
		err := decoder.Decode(&frame)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("persisted frame encoding", err)
		}
		frames++
		if frame.Audit != nil {
			audits = append(audits, *frame.Audit)
		}
	}
	if frames != 3 || len(audits) != 2 {
		t.Fatal("unexpected durable transitions")
	}
	for i, actor := range []string{lifecycleAdminID, secondID} {
		audit := audits[i]
		if audit.ActorID != actor || audit.TargetID != lifecycleWorkerID || audit.Revision != uint64(i+2) || audit.Previous != uint64(i+1) || audit.Current != uint64(i+2) || audit.Operation != "session_reset" || audit.At <= 0 {
			t.Fatal("durable audit did not bind actual requester and exact transition")
		}
	}
}
