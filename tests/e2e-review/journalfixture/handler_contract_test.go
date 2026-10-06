package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
)

// The second cancellation check occurs in transact after inventoryAdmission
// has acquired the shared write slot. Hold only that test call at this boundary.
type journalAdmissionContext struct {
	context.Context
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (c *journalAdmissionContext) Err() error {
	if c.calls.Add(1) == 2 {
		close(c.entered)
		<-c.release
	}
	return c.Context.Err()
}

// Only the production handler and existing synthetic fixture helpers execute.
// Recorder requests open no listener and never invoke run, a collector, a
// journal reader, systemd, or native setup. SQLite contention is local to TempDir.
func TestJournalHandlerReadinessBusyAndEndpointBinding(t *testing.T) {
	ctx := context.Background()
	origin := "http://127.0.0.1:19897"
	issuer, err := makeIssuer(time.Now().UTC())
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(err)
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: "manager_" + strings.Repeat("1", 32), Profile: "http-test", Origin: origin, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "enrollment", "state.db")
	state, err := enrollmentstore.Open(dbPath, cfg, issuer.IssuerDER())
	check(err)
	defer state.Close()
	f := &fixture{store: state, devices: map[string]enrollmentstate.Snapshot{}}
	f.service, err = enrollmentservice.New(state, issuer, f.now)
	check(err)
	f.devices["alpha"], f.devices["beta"] = f.seed(true), f.seed(true)
	alpha, beta := f.devices["alpha"], f.devices["beta"]
	path := "/api/devices/" + alpha.Approval.DeviceID + "/journal"
	appDB, err := store.Open(filepath.Join(dir, "app.db"))
	check(err)
	defer appDB.Close()
	app, err := api.New(appDB, 19897, dir, model.Device{})
	check(err)
	salt := []byte("browser-test-salt")
	hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: encoded, TTL: time.Hour})
	check(err)
	issuerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IssuerDER()}))
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.RootDER()}))
	registry, err := lantrust.NewRegistry(ctx, []byte(issuerPEM), lantrust.NewMemoryStore())
	check(err)
	handler, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Enrollment: f.service, EnrollmentBootstrap: api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: cfg.Binding.InstanceID, Profile: cfg.Binding.Profile, EnrollmentOrigin: origin, AgentOrigin: "http://127.0.0.1:19893", CollectionProfile: cfg.Binding.CollectionProfile, IssuerRootPEM: rootPEM, IssuerPEM: issuerPEM}, Devices: func() ([]model.Device, error) { return f.service.Devices(ctx, f.now()) }})
	check(err)
	var cookie *http.Cookie
	var csrf string
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body != nil {
			raw = jsonBytes(body)
		}
		r := httptest.NewRequest(method, origin+path, bytes.NewReader(raw))
		r.RemoteAddr = "127.0.0.1:1234"
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if method == "POST" {
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
			if csrf != "" {
				r.Header.Set("X-CSRF-Token", csrf)
			}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, status int, out any) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("HTTP status = %d, want %d", w.Code, status)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable response")
		}
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatal("response JSON decode failed", err)
		}
	}
	errorCode := func(w *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		var body struct{ Error struct{ Code string } }
		decode(w, status, &body)
		if body.Error.Code != code {
			t.Fatalf("error code = %q, want %q", body.Error.Code, code)
		}
	}
	errorCode(call("GET", path, nil), 401, "authentication_required")
	login := call("POST", "/api/auth/login", map[string]string{"password": fixturePassword})
	var session struct{ CSRFToken string }
	decode(login, 200, &session)
	if session.CSRFToken == "" || len(login.Result().Cookies()) != 1 {
		t.Fatal("fixture login contract")
	}
	cookie, csrf = login.Result().Cookies()[0], session.CSRFToken
	type view struct {
		SchemaVersion, DeviceID, ExpectedFloor, LocalStatus, ContentStatus string
		Configured                                                         bool
		Request                                                            *journalrequest.Status
		Generation                                                         *enrollmentstore.JournalGenerationView
	}
	read := func() view {
		t.Helper()
		var v view
		decode(call("GET", path, nil), 200, &v)
		if v.DeviceID != alpha.Approval.DeviceID || !v.Configured {
			t.Fatal("endpoint binding lost")
		}
		return v
	}
	before := read()
	if before.Request != nil || before.ExpectedFloor != "0" || before.ContentStatus != "unavailable" {
		t.Fatal("unobserved endpoint invented a request")
	}
	at := f.now().Truncate(time.Microsecond)
	q := journalview.Query{Unit: "invented.service", Start: at.Add(-time.Minute), End: at, MaxPriority: 7}
	input := map[string]any{"expectedFloor": "0", "query": q, "acknowledgeLogContent": true, "acknowledgePlaintext": true}
	errorCode(call("POST", path+"/create", input), 409, "journal_not_ready")
	check(f.seedSystem("alpha"))
	check(f.seedSystem("beta"))
	// Native read-admin creates a generation-bound request; use the same shape.
	policy := sha256.Sum256([]byte("invented-journal-browser-policy:alpha"))
	tuple := journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + hex.EncodeToString(policy[:])}
	report := journalgeneration.Report{SchemaVersion: journalgeneration.ReportVersionV2, Tuple: tuple, Sequence: 1, ObservedAt: f.now(), PolicyEnabled: true, ServiceAuthorization: journalgeneration.AllSystemServices, AllowedUnits: []string{}}
	_, err = state.AcceptJournalGeneration(ctx, alpha.InvitationID, alpha.Issuance.CertificateHash, report, f.now())
	check(err)
	ready := read()
	if ready.SchemaVersion != "tracebolt.journal-view.v2" || ready.Generation == nil || !ready.Generation.Fresh || ready.Generation.PolicyGeneration != tuple || ready.Request != nil {
		t.Fatal("fresh generation status contract")
	}
	input["expectedPolicyGeneration"] = tuple
	var created view
	decode(call("POST", path+"/create", input), 200, &created)
	if created.Request == nil || created.Request.State != journalrequest.Pending || created.Request.Description.DeviceID != alpha.Approval.DeviceID || created.Request.Description.PolicyGeneration != tuple {
		t.Fatal("generation-bound create contract")
	}
	// A burst faster than the native 300 ms polling interval has no status-rate
	// limit when uncontended. Delay alone must not manufacture a receipt.
	for i := 0; i < 20; i++ {
		v := read()
		if v.Request == nil || v.Request.State != journalrequest.Pending || v.Request.Receipt != nil {
			t.Fatal("poll changed request")
		}
	}
	_, err = f.deliver("alpha", "complete")
	check(err)
	accepted := read()
	if accepted.Request == nil || accepted.Request.Receipt == nil || accepted.Request.State != journalrequest.Accepted || accepted.ContentStatus != "available" {
		t.Fatal("synthetic delivery not available")
	}
	pageInput := map[string]any{"identity": accepted.Request.Description.Identity, "snapshotDigest": accepted.Request.Receipt.ResultDigest, "search": "Needle[.*]", "offset": 0, "limit": 100}
	var page journalcache.Page
	decode(call("POST", path+"/query", pageInput), 200, &page)
	if page.DeviceID != alpha.Approval.DeviceID || page.Identity != accepted.Request.Description.Identity || page.Query != q || len(page.Rows) != 3 {
		t.Fatal("exact request page contract")
	}
	errorCode(call("POST", "/api/devices/"+beta.Approval.DeviceID+"/journal/query", pageInput), 404, "journal_not_found")
	// A public store operation holds the single shared inventory write slot.
	// Another real handler GET must fail fast rather than wait for that writer.
	held := &journalAdmissionContext{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := state.JournalGenerationStatus(held, alpha.Approval.DeviceID, f.now()); done <- err }()
	released := false
	defer func() {
		if !released {
			close(held.release)
			<-done
		}
	}()
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not reach write admission")
	}
	admissionBusy := call("GET", path, nil)
	errorCode(admissionBusy, 429, "journal_busy")
	if admissionBusy.Header().Get("Retry-After") != "2" {
		t.Fatal("admission busy omitted backoff")
	}
	close(held.release)
	released = true
	check(<-done)
	if got := read(); !reflect.DeepEqual(got.Request, accepted.Request) || got.ContentStatus != "available" {
		t.Fatal("admission contention changed accepted request")
	}
	// A real SQLite writer in this disposable DB forces production BEGIN busy.
	// This is a demonstrated handler outcome, not attribution of a native failure.
	blocker, err := sql.Open("sqlite", dbPath)
	check(err)
	defer blocker.Close()
	connection, err := blocker.Conn(ctx)
	check(err)
	defer connection.Close()
	_, err = connection.ExecContext(ctx, "BEGIN IMMEDIATE")
	check(err)
	defer connection.ExecContext(ctx, "ROLLBACK")
	busy := call("GET", path, nil)
	errorCode(busy, 429, "journal_busy")
	if busy.Header().Get("Retry-After") != "2" {
		t.Fatal("missing busy backoff")
	}
	var nativeOut struct {
		ExpectedFloor string
		Request       *journalrequest.Status
	}
	if json.Unmarshal(busy.Body.Bytes(), &nativeOut) != nil {
		t.Fatal("busy response was malformed JSON")
	}
	if busy.Code == 200 {
		t.Fatal("native one-shot non-200 branch not exercised")
	}
	_, err = connection.ExecContext(ctx, "ROLLBACK")
	check(err)
	after := read()
	if !reflect.DeepEqual(after.Request, accepted.Request) || after.ContentStatus != "available" {
		t.Fatal("busy retry changed receipt or original expiry")
	}
	t.Log("real handler: not-ready create 409; status polling 200; exact generation-bound delivery 200; cross-device query 404; held shared write admission GET 429; held fixture SQLite writer GET 429 journal_busy, Retry-After 2; released writer GET 200 with unchanged request/receipt")
}
