//go:build linux

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/operatorauth"
)

const lifecycleAuthorityID = "authority_11111111111111111111111111111111"
const lifecycleAdminID = "operator_00000000000000000000000000000001"
const lifecycleWorkerID = "operator_00000000000000000000000000000002"
const lifecycleNewPassword = "synthetic-rotated-operator-fixture-only"

var lifecycleHashOnce sync.Once
var lifecycleHash string

func lifecyclePasswordHash() string {
	lifecycleHashOnce.Do(func() {
		salt := []byte("rotation-test-salt")
		hash := argon2.IDKey([]byte(lifecycleNewPassword), salt, 2, 65536, 1, 32)
		lifecycleHash = "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	})
	return lifecycleHash
}
func lifecycleJournal(t *testing.T) (*operatorauth.AccountJournal, string, *operatorauth.Manager) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("create private journal fixture directory", err)
	}
	path := filepath.Join(dir, "accounts.jsonl")
	initial := operatorauth.AccountSnapshot{AuthorityID: lifecycleAuthorityID, Profile: "tls", Version: operatorauth.AccountVersion, Revision: 1, Accounts: []operatorauth.AccountRecord{
		{Operator: operatorauth.Operator{ID: lifecycleAdminID, Username: "admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: lifecycleWorkerID, Username: "worker", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}, Revision: 1},
	}}
	// Deliberately use the public protected-path constructor. An unsuitable runner
	// must fail this acceptance gate; do not bypass ancestor ownership checks.
	journal, e := operatorauth.CreateAccountJournal(path, initial)
	if e != nil {
		t.Fatalf("public protected journal creation failed (runner must satisfy unchanged path policy): %v", e)
	}
	t.Cleanup(func() { _ = journal.Close() })
	auth, e := operatorauth.New(operatorauth.Config{AuthorityID: lifecycleAuthorityID, AuthorityProfile: "tls", AuthorityStore: journal})
	if e != nil {
		t.Fatal("journal-backed auth", e)
	}
	return journal, path, auth
}
func lifecycleClient(o operatorFixture) operatorFixture {
	client := *o.client
	client.Jar, _ = cookiejar.New(nil)
	o.client = &client
	return o
}
func lifecycleLogin(t *testing.T, o operatorFixture, name, password string) (string, string) {
	t.Helper()
	response, view := o.call(t, "POST", "/api/auth/login", map[string]string{"username": name, "password": password}, "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("lifecycle login", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == operatorauth.CookieName {
			return view["csrfToken"].(string), cookie.Value
		}
	}
	t.Fatal("login missing session cookie")
	return "", ""
}
func lifecycleChange(revision uint64, password bool) map[string]any {
	return map[string]any{"actorId": lifecycleWorkerID, "expectedRevision": revision, "disabled": false, "capabilities": []string{"read", "restart_service"}, "resetSessions": !password, "resetPassword": password}
}
func lifecycleProposal(t *testing.T, path string, revision uint64) {
	t.Helper()
	proposal := struct {
		Version          string `json:"version"`
		AuthorityID      string `json:"authorityId"`
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		PasswordHash     string `json:"passwordHash"`
	}{"tracebolt.operator-credential-proposal.v1", lifecycleAuthorityID, lifecycleWorkerID, revision, lifecyclePasswordHash()}
	raw, e := json.Marshal(proposal)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if e = os.WriteFile(path+".credential-"+lifecycleWorkerID+".json", raw, 0600); e != nil {
		t.Fatal("private fixture proposal", e)
	}
}
func lifecycleDeniedEpoch(t *testing.T, auth *operatorauth.Manager) {
	t.Helper()
	release, e := auth.BeginActorAdmission(context.Background(), lifecycleWorkerID, 1, operatorauth.RestartService)
	if e == nil {
		release()
		t.Fatal("retired approval epoch admitted")
	}
}

func TestAccountLifecycleProtectedPasswordProposalAndRestart(t *testing.T) {
	journal, path, auth := lifecycleJournal(t)
	admin := newOperatorFixtureWithAuth(t, auth)
	worker := lifecycleClient(admin)
	adminCSRF, _ := lifecycleLogin(t, admin, "admin", operatorFixturePassword)
	_, oldToken := lifecycleLogin(t, worker, "worker", operatorFixturePassword)
	lifecycleProposal(t, path, 1)
	for _, field := range []string{"passwordHash", "path", "proposalPath"} {
		injected := lifecycleChange(1, true)
		injected[field] = "caller-supplied-authority"
		if response, _ := admin.call(t, "POST", "/api/auth/accounts/update", injected, adminCSRF, nil); response.StatusCode != http.StatusBadRequest {
			t.Fatal("request authority injection", field, response.StatusCode)
		}
	}
	response, view := admin.call(t, "POST", "/api/auth/accounts/update", lifecycleChange(1, true), adminCSRF, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("protected password reset", response.StatusCode)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "argon2") || strings.Contains(string(raw), lifecycleNewPassword) {
		t.Fatal("reset response disclosed verifier or password")
	}
	if _, e := auth.Lookup(oldToken); e == nil {
		t.Fatal("old session survived password reset")
	}
	lifecycleDeniedEpoch(t, auth)
	if response, _ = worker.call(t, "GET", "/api/devices", nil, "", nil); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("old HTTP session survived reset")
	}
	if response, _ = worker.call(t, "POST", "/api/auth/login", map[string]string{"username": "worker", "password": operatorFixturePassword}, "", nil); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("old password remained valid")
	}
	_, newToken := lifecycleLogin(t, worker, "worker", lifecycleNewPassword)
	if response, _ = admin.call(t, "GET", "/api/auth/accounts", nil, "", nil); response.StatusCode != http.StatusOK {
		t.Fatal("other account was revoked")
	}
	if response, _ = admin.call(t, "POST", "/api/auth/accounts/update", lifecycleChange(1, true), adminCSRF, nil); response.StatusCode != http.StatusConflict {
		t.Fatal("stale account revision accepted")
	}
	// The retained proposal is still bound to revision 1, even with a fresh API revision.
	if response, _ = admin.call(t, "POST", "/api/auth/accounts/update", lifecycleChange(2, true), adminCSRF, nil); response.StatusCode != http.StatusBadRequest {
		t.Fatal("stale protected proposal accepted", response.StatusCode)
	}
	snapshot, e := journal.Load(context.Background())
	if e != nil || snapshot.Revision != 2 {
		t.Fatal("stale proposal mutated durable revision", e)
	}
	if _, err := auth.Lookup(newToken); err != nil {
		t.Fatal("stale proposal revoked the new valid session", err)
	}
	release, err := auth.BeginActorAdmission(context.Background(), lifecycleWorkerID, 2, operatorauth.RestartService)
	if err != nil {
		t.Fatal("current approval epoch rejected", err)
	}
	release()
	if e = journal.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := operatorauth.OpenAccountJournal(path)
	if e != nil {
		t.Fatal("public journal reopen", e)
	}
	defer reopened.Close()
	fresh, e := operatorauth.New(operatorauth.Config{AuthorityID: lifecycleAuthorityID, AuthorityProfile: "tls", AuthorityStore: reopened})
	if e != nil {
		t.Fatal(e)
	}
	for _, token := range []string{oldToken, newToken} {
		if _, e = fresh.Lookup(token); e == nil {
			t.Fatal("restart restored ephemeral session")
		}
	}
	lifecycleDeniedEpoch(t, fresh)
	release, err = fresh.BeginActorAdmission(context.Background(), lifecycleWorkerID, 2, operatorauth.RestartService)
	if err != nil {
		t.Fatal("restart rejected current approval epoch", err)
	}
	release()
	restarted := newOperatorFixtureWithAuth(t, fresh)
	if response, _ = restarted.call(t, "POST", "/api/auth/login", map[string]string{"username": "worker", "password": operatorFixturePassword}, "", nil); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("restart revived old credential")
	}
	lifecycleLogin(t, restarted, "worker", lifecycleNewPassword)
	lifecycleLogin(t, lifecycleClient(restarted), "admin", operatorFixturePassword)
	persisted, e := reopened.Load(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, record := range persisted.Accounts {
		if record.Operator.ID == lifecycleWorkerID {
			found = true
			if record.Revision != 2 || record.RevocationFloor != 1 {
				t.Fatal("restart lost durable authority floor")
			}
		}
	}
	if !found {
		t.Fatal("restart lost worker identity")
	}
}

// A real journal size mismatch exercises an uncertain storage transition. This
// is not an fsync-failure simulation and touches only this test's fresh file.
func TestAccountLifecycleJournalIntegrityFailureFencesOnlyTarget(t *testing.T) {
	journal, path, auth := lifecycleJournal(t)
	admin := newOperatorFixtureWithAuth(t, auth)
	worker := lifecycleClient(admin)
	csrf, _ := lifecycleLogin(t, admin, "admin", operatorFixturePassword)
	_, token := lifecycleLogin(t, worker, "worker", operatorFixturePassword)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString("{synthetic-torn-fixture-tail")
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		t.Fatal("fixture corruption failed")
	}
	response, _ := admin.call(t, "POST", "/api/auth/accounts/update", lifecycleChange(1, false), csrf, nil)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("uncertain commit reported success", response.StatusCode)
	}
	if _, e = auth.Lookup(token); e == nil {
		t.Fatal("uncertain target session survived")
	}
	lifecycleDeniedEpoch(t, auth)
	if response, _ = admin.call(t, "GET", "/api/devices", nil, "", nil); response.StatusCode != http.StatusOK {
		t.Fatal("unrelated operator lost read access")
	}
	if response, _ = admin.call(t, "POST", "/api/auth/accounts/update", lifecycleChange(1, false), csrf, nil); response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("uncertain transition was retried")
	}
	if _, e = journal.Load(context.Background()); !errors.Is(e, operatorauth.ErrAuthorityUncertain) {
		t.Fatal("failed journal stayed usable", e)
	}
	if e = journal.Close(); e != nil {
		t.Fatal(e)
	}
	if reopened, e := operatorauth.OpenAccountJournal(path); e == nil {
		reopened.Close()
		t.Fatal("restart adopted corrupt journal")
	}
}
