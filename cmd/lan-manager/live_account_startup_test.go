//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/operatorauth"
)

// This is a Go startup integration fixture, not execution of the initializer
// CLI. It uses its public profile/marker/journal contracts and normal prepare.
// Public ancestor protections are hard acceptance gates, never skipped/relaxed.
func TestLiveAccountPublicInitializationPrepareAndRestart(t *testing.T) {
	material, _, _, _ := fixture(t, lanconfig.TLS)
	original := material
	c := material.Config
	configPath := filepath.Join(filepath.Dir(c.OperatorAuthFile), "lan.json")
	const authority = "authority_11111111111111111111111111111111"
	const adminID = "operator_00000000000000000000000000000001"
	const workerID = "operator_00000000000000000000000000000002"
	const password = "fixture-password-only"
	const rotated = "fixture-rotated-password-only"
	if e := os.Mkdir(c.StateDirectory, 0700); e != nil {
		t.Fatal(e)
	}
	lease, e := lanstore.AcquireManagerWriter(c.StateDirectory)
	if e != nil {
		t.Fatal("public writer admission", e)
	}
	defer lease.Close()
	if e = lanstore.PrepareProfileDirectory(c.StateDirectory, c.Profile); e != nil {
		t.Fatal("public profile admission before authority artifacts", e)
	}
	reference := lanconfig.AccountAuthorityReference{SchemaVersion: lanconfig.AccountAuthorityVersion, Profile: c.Profile, AuthorityID: authority, AuthorityFile: filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityJournalFile)}
	marker, e := lanconfig.AccountAuthorityMarkerBytes(c.StateDirectory, reference)
	if e != nil {
		t.Fatal(e)
	}
	startupCreatePrivate(t, filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityMarkerFile), marker)
	operators := []operatorauth.Operator{
		{ID: adminID, Username: "admin", PasswordHash: material.PasswordHash, Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}},
		{ID: workerID, Username: "worker", PasswordHash: material.PasswordHash, Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}},
	}
	journal, e := operatorauth.CreateAccountJournal(reference.AuthorityFile, operatorauth.AccountSnapshot{AuthorityID: authority, Profile: c.Profile, Version: operatorauth.AccountVersion, Revision: 1, Accounts: []operatorauth.AccountRecord{{Operator: operators[0], Revision: 1}, {Operator: operators[1], Revision: 1}}})
	if e != nil {
		t.Fatal("public protected journal creation", e)
	}
	if e = journal.Close(); e != nil {
		t.Fatal(e)
	}
	refRaw, e := json.Marshal(reference)
	if e != nil {
		t.Fatal(e)
	}
	refPath := filepath.Join(filepath.Dir(c.OperatorAuthFile), "live-auth.json")
	startupCreatePrivate(t, refPath, refRaw)
	c.OperatorAuthFile = refPath
	configRaw, _ := json.Marshal(c)
	if e = os.WriteFile(configPath, configRaw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = lease.Close(); e != nil {
		t.Fatal(e)
	}
	material, e = lanconfig.Load(configPath)
	if e != nil {
		t.Fatal("v3 material", e)
	}
	p, e := prepare(material)
	if e != nil {
		t.Fatal("normal prepare after public initialization", e)
	}
	defer p.close()
	call := func(h http.Handler, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, c.OperatorOrigin+path, strings.NewReader(string(raw)))
		r.RemoteAddr = "127.0.0.1:12345"
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		r.Header.Set("Origin", c.OperatorOrigin)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := func(h http.Handler, name, secret string) (*http.Cookie, string) {
		w := call(h, "POST", "/api/auth/login", map[string]string{"username": name, "password": secret}, nil, "")
		var view struct {
			CSRF string `json:"csrfToken"`
		}
		cookies := w.Result().Cookies()
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || len(cookies) != 1 || !cookies[0].Secure {
			t.Fatal("prepared live login", w.Code)
		}
		return cookies[0], view.CSRF
	}
	admin, csrf := login(p.operator, "admin", password)
	worker, _ := login(p.operator, "worker", password)
	salt := []byte("rotated-fixture-salt")
	hash := argon2.IDKey([]byte(rotated), salt, 2, 65536, 1, 32)
	phc := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	proposal := struct {
		Version          string `json:"version"`
		AuthorityID      string `json:"authorityId"`
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		PasswordHash     string `json:"passwordHash"`
	}{"tracebolt.operator-credential-proposal.v1", authority, workerID, 1, phc}
	proposalRaw, _ := json.Marshal(proposal)
	startupCreatePrivate(t, reference.AuthorityFile+".credential-"+workerID+".json", proposalRaw)
	clear(proposalRaw)
	change := func(rev uint64, disabled, resetPassword bool) {
		body := map[string]any{"actorId": workerID, "expectedRevision": rev, "disabled": disabled, "capabilities": []string{"read", "restart_service"}, "resetSessions": false, "resetPassword": resetPassword}
		if w := call(p.operator, "POST", "/api/auth/accounts/update", body, admin, csrf); w.Code != 200 {
			t.Fatal("prepared account transition", w.Code)
		}
	}
	change(1, false, true)
	if w := call(p.operator, "GET", "/api/devices", nil, worker, ""); w.Code != 401 {
		t.Fatal("password reset retained original session")
	}
	freshWorker, _ := login(p.operator, "worker", rotated)
	change(2, true, false)
	if w := call(p.operator, "GET", "/api/devices", nil, freshWorker, ""); w.Code != 401 {
		t.Fatal("disable retained new session")
	}
	change(3, false, false)
	if w := call(p.operator, "GET", "/api/devices", nil, admin, ""); w.Code != 200 {
		t.Fatal("other account unavailable")
	}
	p.close()
	// Public reopen validates the exact persisted account revision/floor and actor
	// admission. No direct private initializer or test-only storage constructor.
	journal, e = operatorauth.OpenAccountJournal(reference.AuthorityFile)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := operatorauth.New(operatorauth.Config{AuthorityID: authority, AuthorityProfile: c.Profile, AuthorityStore: journal})
	if e != nil {
		journal.Close()
		t.Fatal(e)
	}
	for _, epoch := range []uint64{1, 2, 3} {
		release, err := auth.BeginActorAdmission(context.Background(), workerID, epoch, operatorauth.RestartService)
		if err == nil {
			release()
			journal.Close()
			t.Fatal("restart revived old approval epoch")
		}
	}
	release, e := auth.BeginActorAdmission(context.Background(), workerID, 4, operatorauth.RestartService)
	if e != nil {
		journal.Close()
		t.Fatal("current epoch lost", e)
	}
	release()
	if e = journal.Close(); e != nil {
		t.Fatal(e)
	}
	reloaded, e := lanconfig.Load(configPath)
	if e != nil {
		t.Fatal(e)
	}
	restarted, e := prepare(reloaded)
	if e != nil {
		t.Fatal("normal live restart", e)
	}
	defer restarted.close()
	for _, old := range []*http.Cookie{worker, freshWorker, admin} {
		if w := call(restarted.operator, "GET", "/api/devices", nil, old, ""); w.Code != 401 {
			t.Fatal("old session survived restart")
		}
	}
	if w := call(restarted.operator, "POST", "/api/auth/login", map[string]string{"username": "worker", "password": password}, nil, ""); w.Code != 401 {
		t.Fatal("old credential revived")
	}
	login(restarted.operator, "worker", rotated)
	login(restarted.operator, "admin", password)
	restarted.close()
	// Neither a v1 material nor a valid v2 material can downgrade a used v3 state.
	if fallback, err := prepare(original); err == nil {
		fallback.close()
		t.Fatal("v1 fallback adopted used live authority")
	}
	v2Operators := make([]map[string]any, 0, len(operators))
	for _, op := range operators {
		v2Operators = append(v2Operators, map[string]any{"id": op.ID, "username": op.Username, "passwordHash": op.PasswordHash, "capabilities": op.Capabilities})
	}
	v2Raw, _ := json.Marshal(map[string]any{"schemaVersion": "tracebolt.operator-auth.v2", "profile": c.Profile, "operators": v2Operators})
	if e = os.WriteFile(original.Config.OperatorAuthFile, v2Raw, 0600); e != nil {
		t.Fatal(e)
	}
	oldConfig, _ := json.Marshal(original.Config)
	if e = os.WriteFile(configPath, oldConfig, 0600); e != nil {
		t.Fatal(e)
	}
	v2, e := lanconfig.Load(configPath)
	if e != nil {
		t.Fatal("valid v2 fallback fixture", e)
	}
	if fallback, err := prepare(v2); err == nil {
		fallback.close()
		t.Fatal("v2 fallback adopted used live authority")
	}
}

func startupCreatePrivate(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal("exclusive fixture file", e)
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = os.ErrInvalid
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		t.Fatal("durable fixture file")
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	e = dir.Sync()
	ce = dir.Close()
	if e != nil || ce != nil {
		t.Fatal("durable fixture directory")
	}
}
