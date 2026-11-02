//go:build linux

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/operatorauth"
)

type factorAPIClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *factorAPIClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *factorAPIClock) Advance()       { c.mu.Lock(); c.now = c.now.Add(61 * time.Second); c.mu.Unlock() }
func factorAPISecret(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}
func factorAPICode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		t.Fatal(e)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha256.New, key)
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	number := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%08d", number%100000000)
}
func factorAPIProposal(t *testing.T, path, id, secret string, revision uint64) {
	t.Helper()
	proposal := struct {
		Version          string `json:"version"`
		AuthorityID      string `json:"authorityId"`
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		Secret           string `json:"secret"`
	}{"tracebolt.operator-factor-proposal.v1", lifecycleAuthorityID, id, revision, secret}
	raw, e := json.Marshal(proposal)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if e = os.WriteFile(path+".factor-"+id+".json", raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func factorAPINoCookie(t *testing.T, response *http.Response) {
	t.Helper()
	for _, c := range response.Cookies() {
		if c.Name == operatorauth.CookieName && c.Value != "" && c.MaxAge >= 0 {
			t.Fatal("operation minted an authentication cookie")
		}
	}
}

func TestFactorAPILifecycleProtectedEnrollmentResetAndRestart(t *testing.T) {
	const secondID = "operator_00000000000000000000000000000003"
	clock := &factorAPIClock{now: time.Now().UTC()}
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "accounts.jsonl")
	initial := operatorauth.AccountSnapshot{Version: operatorauth.AccountVersion, AuthorityID: lifecycleAuthorityID, Profile: "tls", Revision: 1, Accounts: []operatorauth.AccountRecord{
		{Operator: operatorauth.Operator{ID: lifecycleAdminID, Username: "admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: secondID, Username: "other-admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: lifecycleWorkerID, Username: "worker", PasswordHash: lifecyclePasswordHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}, Revision: 1},
	}}
	journal, e := operatorauth.CreateAccountJournal(path, initial)
	if e != nil {
		t.Fatal("public protected journal", e)
	}
	defer journal.Close()
	config := func(store operatorauth.AccountStore) operatorauth.Config {
		return operatorauth.Config{AuthorityStore: store, AuthorityID: lifecycleAuthorityID, AuthorityProfile: "tls", Now: clock.Now}
	}
	auth, e := operatorauth.New(config(journal))
	if e != nil {
		t.Fatal(e)
	}
	admin := newOperatorFixtureWithAuth(t, auth)
	other, worker := lifecycleClient(admin), lifecycleClient(admin)
	_, otherToken := lifecycleLogin(t, other, "other-admin", operatorFixturePassword)
	record := func(id string) operatorauth.AccountRecord {
		t.Helper()
		snapshot, err := journal.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range snapshot.Accounts {
			if r.Operator.ID == id {
				return r
			}
		}
		t.Fatal("missing fixture account")
		return operatorauth.AccountRecord{}
	}
	enrollBody := func(name, password, secret string, revision uint64) map[string]any {
		return map[string]any{"username": name, "password": password, "otp": factorAPICode(t, secret, clock.Now()), "expectedRevision": revision}
	}
	assertStatus := func(client operatorFixture, path string, body any, csrf string, change func(*http.Request), want int) map[string]any {
		t.Helper()
		response, value := client.call(t, "POST", path, body, csrf, change)
		if response.StatusCode != want {
			t.Fatalf("%s returned %d, want %d", path, response.StatusCode, want)
		}
		if path != "/api/auth/login" || want != http.StatusOK {
			factorAPINoCookie(t, response)
		}
		return value
	}
	login := func(client operatorFixture, name, password, secret string) (string, string) {
		t.Helper()
		response, view := client.call(t, "POST", "/api/auth/login", map[string]any{"username": name, "password": password, "otp": factorAPICode(t, secret, clock.Now())}, "", nil)
		if response.StatusCode != 200 {
			t.Fatal("factor login", response.StatusCode)
		}
		for _, c := range response.Cookies() {
			if c.Name == operatorauth.CookieName {
				return view["csrfToken"].(string), c.Value
			}
		}
		t.Fatal("factor login missing cookie")
		return "", ""
	}
	adminSecret, workerSecret := factorAPISecret(t), factorAPISecret(t)
	factorAPIProposal(t, path, lifecycleAdminID, adminSecret, 1)
	body := enrollBody("admin", operatorFixturePassword, adminSecret, 1)
	assertStatus(admin, "/api/auth/factors/enroll", body, "", func(r *http.Request) { r.Header.Del("Origin") }, 403)
	injected := enrollBody("admin", operatorFixturePassword, adminSecret, 1)
	injected["secret"] = adminSecret
	assertStatus(admin, "/api/auth/factors/enroll", injected, "", nil, 400)
	value := assertStatus(admin, "/api/auth/factors/enroll", body, "", nil, 200)
	if value["enrolled"] != true {
		t.Fatal("enrollment response missing success")
	}
	// Ownership proof is already durably consumed: same-step login cannot reuse it.
	assertStatus(admin, "/api/auth/login", map[string]any{"username": "admin", "password": operatorFixturePassword, "otp": body["otp"]}, "", nil, 401)
	clock.Advance()
	if _, err := auth.LoginNamed(context.Background(), "127.0.0.1", "admin", operatorFixturePassword); err == nil {
		t.Fatal("direct password-only Manager login bypassed factor")
	}
	assertStatus(admin, "/api/auth/login", map[string]any{"username": "admin", "password": operatorFixturePassword}, "", nil, 401)
	clock.Advance()
	csrfAdmin, adminToken := login(admin, "admin", operatorFixturePassword, adminSecret)
	factorAPIProposal(t, path, lifecycleWorkerID, workerSecret, 1)
	assertStatus(worker, "/api/auth/factors/enroll", enrollBody("worker", lifecycleNewPassword, workerSecret, 1), "", nil, 200)
	clock.Advance()
	workerCSRF, workerToken := login(worker, "worker", lifecycleNewPassword, workerSecret)
	oldRecord := record(lifecycleWorkerID)
	oldGeneration := oldRecord.Factor.Generation
	resetBody := func(password, otp string) map[string]any {
		return map[string]any{"actorId": lifecycleWorkerID, "expectedRevision": oldRecord.Revision, "password": password, "otp": otp}
	}
	clock.Advance()
	freshOTP := factorAPICode(t, adminSecret, clock.Now())
	reset := resetBody(operatorFixturePassword, freshOTP)
	// A fresh valid factor proof is not an implicit manage_accounts grant.
	unprivileged := resetBody(lifecycleNewPassword, factorAPICode(t, workerSecret, clock.Now()))
	unprivileged["actorId"] = lifecycleAdminID
	unprivileged["expectedRevision"] = record(lifecycleAdminID).Revision
	assertStatus(worker, "/api/auth/accounts/reset-factor", unprivileged, workerCSRF, nil, 403)
	assertStatus(admin, "/api/auth/accounts/reset-factor", reset, "", nil, 403)
	assertStatus(admin, "/api/auth/accounts/reset-factor", reset, csrfAdmin, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.invalid") }, 403)
	injectedReset := resetBody(operatorFixturePassword, freshOTP)
	injectedReset["requesterId"] = secondID
	assertStatus(admin, "/api/auth/accounts/reset-factor", injectedReset, csrfAdmin, nil, 400)
	// Target's correct credentials must not authenticate the requesting administrator.
	assertStatus(admin, "/api/auth/accounts/reset-factor", resetBody(lifecycleNewPassword, factorAPICode(t, workerSecret, clock.Now())), csrfAdmin, nil, 403)
	clock.Advance()
	freshOTP = factorAPICode(t, adminSecret, clock.Now())
	assertStatus(admin, "/api/auth/accounts/reset-factor", resetBody(operatorFixturePassword, freshOTP), csrfAdmin, nil, 200)
	pending := record(lifecycleWorkerID)
	if pending.Factor == nil || pending.Factor.State != "enrollment_required" || pending.Factor.Secret != "" || pending.Factor.Generation != oldGeneration+1 || pending.Revision != oldRecord.Revision+1 || pending.RevocationFloor != oldRecord.Revision {
		t.Fatal("reset did not persist pending generation and authority floor")
	}
	if _, err := auth.Lookup(workerToken); err == nil {
		t.Fatal("target session survived factor reset")
	}
	if response, _ := worker.call(t, "GET", "/api/devices", nil, "", nil); response.StatusCode != 401 {
		t.Fatal("old target cookie survived reset")
	}
	if release, err := auth.BeginActorAdmission(context.Background(), lifecycleWorkerID, oldRecord.Revision, operatorauth.RestartService); err == nil {
		release()
		t.Fatal("old approval epoch survived factor reset")
	}
	for _, token := range []string{adminToken, otherToken} {
		if _, err := auth.Lookup(token); err != nil {
			t.Fatal("independent administrator session revoked", err)
		}
	}
	replay := resetBody(operatorFixturePassword, freshOTP)
	replay["expectedRevision"] = pending.Revision
	assertStatus(admin, "/api/auth/accounts/reset-factor", replay, csrfAdmin, nil, 403)
	clock.Advance()
	assertStatus(worker, "/api/auth/login", map[string]any{"username": "worker", "password": lifecycleNewPassword, "otp": factorAPICode(t, workerSecret, clock.Now())}, "", nil, 401)
	assertStatus(worker, "/api/auth/login", map[string]any{"username": "worker", "password": lifecycleNewPassword}, "", nil, 401)
	// A fresh API revision cannot redeem the retained, pre-reset proposal.
	assertStatus(worker, "/api/auth/factors/enroll", enrollBody("worker", lifecycleNewPassword, workerSecret, pending.Revision), "", nil, 401)
	// A newly written exact-revision proposal cannot revive a retired secret.
	factorAPIProposal(t, path, lifecycleWorkerID, workerSecret, pending.Revision)
	clock.Advance()
	assertStatus(worker, "/api/auth/factors/enroll", enrollBody("worker", lifecycleNewPassword, workerSecret, pending.Revision), "", nil, 401)
	stillPending := record(lifecycleWorkerID)
	if stillPending.Revision != pending.Revision || stillPending.Factor.State != "enrollment_required" {
		t.Fatal("retired-secret proposal changed pending authority")
	}
	replacement := factorAPISecret(t)
	factorAPIProposal(t, path, lifecycleWorkerID, replacement, pending.Revision)
	clock.Advance()
	assertStatus(worker, "/api/auth/factors/enroll", enrollBody("worker", lifecycleNewPassword, replacement, pending.Revision), "", nil, 200)
	current := record(lifecycleWorkerID)
	if current.Factor.State != "active" || current.Factor.Generation < pending.Factor.Generation {
		t.Fatal("replacement enrollment lost factor generation")
	}
	clock.Advance()
	lastOTP := factorAPICode(t, replacement, clock.Now())
	_, newToken := login(worker, "worker", lifecycleNewPassword, replacement)
	// Account views and retained audit metadata must not disclose factor material.
	response, views := admin.call(t, "GET", "/api/auth/accounts", nil, "", nil)
	if response.StatusCode != 200 {
		t.Fatal("account view denied")
	}
	viewRaw, _ := json.Marshal(views)
	for _, secret := range []string{adminSecret, workerSecret, replacement, "passwordHash", "argon2"} {
		if strings.Contains(string(viewRaw), secret) {
			t.Fatal("account view leaked protected material")
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	resetAudits := 0
	for {
		var frame struct {
			Audit json.RawMessage `json:"audit"`
		}
		err := decoder.Decode(&frame)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{adminSecret, workerSecret, replacement, operatorFixturePassword, lifecycleNewPassword, "argon2"} {
			if bytes.Contains(frame.Audit, []byte(secret)) {
				t.Fatal("factor audit disclosed credentials")
			}
		}
		var audit operatorauth.AccountAudit
		if json.Unmarshal(frame.Audit, &audit) == nil && audit.Operation == "factor_reset" {
			resetAudits++
			if audit.ActorID != lifecycleAdminID || audit.TargetID != lifecycleWorkerID {
				t.Fatal("factor reset audit lost actual requester")
			}
		}
	}
	if resetAudits != 1 {
		t.Fatal("missing or duplicate durable factor reset audit")
	}
	if err = journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := operatorauth.OpenAccountJournal(path)
	if err != nil {
		t.Fatal("public protected factor reopen", err)
	}
	defer reopened.Close()
	fresh, err := operatorauth.New(config(reopened))
	if err != nil {
		t.Fatal(err)
	}
	restarted := newOperatorFixtureWithAuth(t, fresh)
	if _, err = fresh.Lookup(newToken); err == nil {
		t.Fatal("restart restored ephemeral factor session")
	}
	assertStatus(restarted, "/api/auth/login", map[string]any{"username": "worker", "password": lifecycleNewPassword, "otp": lastOTP}, "", nil, 401)
	clock.Advance()
	// Avoid the inherent 1-in-10^8 truncated-code collision in this negative fixture.
	for factorAPICode(t, workerSecret, clock.Now()) == factorAPICode(t, replacement, clock.Now()) {
		clock.Advance()
	}
	assertStatus(restarted, "/api/auth/login", map[string]any{"username": "worker", "password": lifecycleNewPassword, "otp": factorAPICode(t, workerSecret, clock.Now())}, "", nil, 401)
	clock.Advance()
	login(restarted, "worker", lifecycleNewPassword, replacement)
	snapshot, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range snapshot.Accounts {
		if r.Operator.ID == lifecycleWorkerID && (r.Revision != current.Revision || r.RevocationFloor != current.RevocationFloor || r.Factor.Generation != current.Factor.Generation || r.Factor.LastStep < current.Factor.LastStep) {
			t.Fatal("restart lost factor/revocation floors")
		}
	}
	if release, err := fresh.BeginActorAdmission(context.Background(), lifecycleWorkerID, oldRecord.Revision, operatorauth.RestartService); err == nil {
		release()
		t.Fatal("restart revived old approval epoch")
	}
	lifecycleLogin(t, lifecycleClient(restarted), "other-admin", operatorFixturePassword)
}

// The optional live-v3 OTP field must not relax the existing exact JSON grammar
// or change either legacy login schema. Raw request bodies preserve duplicates.
func TestFactorOptionalLoginParserKeepsStrictLegacySchemas(t *testing.T) {
	for _, mode := range []string{"live-v3", "named-v2", "shared-v1"} {
		t.Run(mode, func(t *testing.T) {
			var auth *operatorauth.Manager
			var err error
			switch mode {
			case "live-v3":
				_, _, auth = lifecycleJournal(t)
			case "named-v2":
				auth, err = operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: lifecycleAdminID, Username: "admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}})
			case "shared-v1":
				auth, err = operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash()})
			}
			if err != nil {
				t.Fatal(err)
			}
			fixture := newOperatorFixtureWithAuth(t, auth)
			passwordJSON, _ := json.Marshal(operatorFixturePassword)
			named := `"username":"admin","password":` + string(passwordJSON)
			valid := `{` + named + `}`
			if mode == "shared-v1" {
				valid = `{"password":` + string(passwordJSON) + `}`
			}
			callRaw := func(raw string, want int) {
				t.Helper()
				response, _ := fixture.call(t, "POST", "/api/auth/login", nil, "", func(r *http.Request) {
					r.Body = io.NopCloser(strings.NewReader(raw))
					r.ContentLength = int64(len(raw))
				})
				if response.StatusCode != want {
					t.Fatalf("%s login grammar returned %d, want %d", mode, response.StatusCode, want)
				}
				if want != http.StatusOK {
					factorAPINoCookie(t, response)
				}
			}
			// Optional MFA never mandates adding otp to existing factorless requests.
			callRaw(valid, http.StatusOK)
			if mode != "live-v3" {
				withOTP := strings.TrimSuffix(valid, "}") + `,"otp":"12345678"}`
				callRaw(withOTP, http.StatusBadRequest)
				callRaw(valid, http.StatusOK)
				return
			}
			for _, tc := range []struct{ name, raw string }{
				{"null-otp", `{` + named + `,"otp":null}`},
				{"duplicate-otp", `{` + named + `,"otp":"","otp":""}`},
				{"unknown-field", `{` + named + `,"otp":"","requesterId":"caller"}`},
				{"missing-username", `{"password":` + string(passwordJSON) + `,"otp":""}`},
				{"missing-password", `{"username":"admin","otp":""}`},
				{"number-otp", `{` + named + `,"otp":12345678}`},
				{"array-otp", `{` + named + `,"otp":[]}`},
				{"boolean-otp", `{` + named + `,"otp":false}`},
				{"wrong-username-type", `{"username":1,"password":` + string(passwordJSON) + `,"otp":""}`},
				{"wrong-password-type", `{"username":"admin","password":1,"otp":""}`},
				{"duplicate-required", `{` + named + `,"username":"admin"}`},
				{"case-alias", `{` + named + `,"OTP":""}`},
			} {
				t.Run(tc.name, func(t *testing.T) { callRaw(tc.raw, http.StatusBadRequest) })
			}
			callRaw(valid, http.StatusOK)
		})
	}
}
