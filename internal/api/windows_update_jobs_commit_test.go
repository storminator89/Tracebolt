package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsupdatejob"
)

// This wrapper represents deterministic lock/commit delay, not a fake job store.
// All authority checks, record changes, rejection floors, and commits still run
// inside the real enrollmentstore transaction. The hooks are armed only after
// OpenTransactional has validated the already-created enrollment-owned grant.
// No goroutine, listening socket, host provider, or native executor is involved.
type windowsUpdateCommitStore struct {
	store           *enrollmentstore.Store
	beforeStore     func()
	afterTransition func()
	callbacks       int
}

func (s *windowsUpdateCommitStore) WindowsUpdateEnrollmentBinding() enrollmentstate.Binding {
	return s.store.WindowsUpdateEnrollmentBinding()
}
func (s *windowsUpdateCommitStore) WindowsUpdateJobTransaction(ctx context.Context, b windowsupdatejob.Binding, key ed25519.PublicKey, now time.Time, fn func(*windowsupdatejob.Record, windowsupdatejob.Current, time.Time) error) (windowsupdatejob.Record, time.Time, error) {
	if hook := s.beforeStore; hook != nil {
		s.beforeStore = nil
		hook()
	}
	return s.store.WindowsUpdateJobTransaction(ctx, b, key, now, func(r *windowsupdatejob.Record, current windowsupdatejob.Current, at time.Time) error {
		s.callbacks++
		err := fn(r, current, at)
		if err == nil {
			if hook := s.afterTransition; hook != nil {
				s.afterTransition = nil
				hook()
			}
		}
		return err
	})
}

type windowsUpdateCommitFixture struct {
	handler  *operatorHandler
	session  operatorauth.Session
	store    *windowsUpdateCommitStore
	clock    *windowsEventOperatorClock
	snapshot enrollmentstate.Snapshot
	at       time.Time
	path     string
	consent  windowsupdatejob.Consent
}

func newWindowsUpdateCommitFixture(t *testing.T, ttl time.Duration) windowsUpdateCommitFixture {
	t.Helper()
	const origin = "https://manager.invalid"
	at := time.Now().UTC().Truncate(time.Second)
	clock := &windowsEventOperatorClock{at: at}
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic update commit root"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("update-commit-root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic update commit issuer"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("update-commit-issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerHash := sha256.Sum256(issuerDER)
	issuer, err := enrollmentissuer.New(issuerDER, rootDER, issuerKey, hex.EncodeToString(issuerHash[:]), at)
	if err != nil {
		t.Fatal(err)
	}
	binding := enrollmentstate.Binding{InstanceID: "manager_" + strings.Repeat("1", 32), Profile: "tls", Origin: origin, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, IssuerFingerprint: issuer.Fingerprint()}
	config := enrollmentstate.DefaultConfig(binding)
	config.RecordLimit, config.InvitationLimit, config.PendingLimit = 25, 25, 25
	path := filepath.Join(t.TempDir(), "private", "update-commit.sqlite")
	store, err := enrollmentstore.Open(path, config, issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	service, err := enrollmentservice.New(store, issuer, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.CloseWindowsEventContent)
	// This activation helper is pure; unlike newWindowsEventOperatorFixture it
	// creates no TLS test server and performs no HTTP client requests.
	snapshot := windowsEventOperatorActivate(t, service, at)
	managerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{127}, ed25519.SeedSize))
	executorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{128}, ed25519.SeedSize))
	jobBinding := windowsupdatejob.Binding{ManagerID: binding.InstanceID, DeviceID: snapshot.Approval.DeviceID, IncarnationDigest: "sha256:" + snapshot.Issuance.CertificateHash, ExecutorID: "executor_" + strings.Repeat("3", 32), ExecutorKeyID: actionpermit.Digest(executorKey.Public().(ed25519.PublicKey)), GrantID: "grant_" + strings.Repeat("4", 32), KeyID: actionpermit.Digest(managerKey.Public().(ed25519.PublicKey))}
	consent := windowsupdatejob.Consent{Version: windowsupdatejob.ConsentVersion, Scope: windowsupdatejob.Scope, Binding: jobBinding, Enabled: true, Acknowledged: true, ExpiresAt: at.Unix() + 600}
	if err = store.SetupWindowsUpdateJobsCreateOnly(context.Background(), managerKey.Public().(ed25519.PublicKey), executorKey.Public().(ed25519.PublicKey), consent, at); err != nil {
		t.Fatal(err)
	}
	wrapped := &windowsUpdateCommitStore{store: store}
	manager, err := windowsupdatejob.OpenTransactional(context.Background(), wrapped, jobBinding, managerKey, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	auth, err := operatorauth.New(operatorauth.Config{TTL: ttl, Now: clock.now, Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.ConfigureOperatorPolicy(func(actor string) bool { return auth.ActorHasCapability(actor, operatorauth.WindowsUpdateInstall) }); err != nil {
		t.Fatal(err)
	}
	session, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	app := setup(t)
	app.mu.Lock()
	app.lanOnly = true
	app.lanDevices = func() ([]model.Device, error) {
		return []model.Device{{ID: snapshot.Approval.DeviceID, Platform: "windows"}}, nil
	}
	app.mu.Unlock()
	// Exercise the production ServeHTTP session/CSRF/capability dispatch, while
	// avoiding unrelated bootstrap/registry setup and any listening test server.
	handler := &operatorHandler{app: app, auth: auth, origin: origin, authority: "manager.invalid", cookieName: operatorauth.CookieName, windowsUpdateJobs: manager}
	wrapped.callbacks = 0
	return windowsUpdateCommitFixture{handler, session, wrapped, clock, snapshot, at, path, consent}
}

func (f windowsUpdateCommitFixture) saved(t *testing.T) ([]byte, int64) {
	t.Helper()
	u := url.URL{Scheme: "file", Path: f.path}
	query := u.Query()
	query.Set("mode", "ro")
	query.Set("readonly_shm", "1")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw []byte
	var rejected int64
	if err = db.QueryRow(`SELECT body,rejected_clock_floor FROM enrollment_windows_update_job_records WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&raw, &rejected); err != nil {
		t.Fatal(err)
	}
	if _, err = windowsupdatejob.DecodeRecord(raw); err != nil {
		t.Fatal("unreadable persisted record", err)
	}
	return raw, rejected
}

func (f windowsUpdateCommitFixture) request(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"requestId": "update_" + strings.Repeat("6", 32), "updateId": "11111111-2222-3333-4444-555555555555", "revision": 3})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://manager.invalid/api/devices/"+f.snapshot.Approval.DeviceID+"/windows-update-jobs/request", bytes.NewReader(body))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.RemoteAddr = "127.0.0.1:34567"
	request.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: f.session.Token})
	request.Header.Set("Origin", "https://manager.invalid")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", f.session.CSRFToken)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func TestWindowsUpdateJobAPIUsesLiveClockAtEnrollmentCommit(t *testing.T) {
	for _, boundary := range []string{"store-entry-after-wait", "final-commit-after-transition", "final-session-expiry"} {
		t.Run(boundary, func(t *testing.T) {
			ttl := time.Hour
			if boundary == "final-session-expiry" {
				ttl = 30 * time.Second
			}
			f := newWindowsUpdateCommitFixture(t, ttl)
			before, floor := f.saved(t)
			if floor != 0 {
				t.Fatal("fixture already rejected time")
			}
			crossed := time.Unix(f.consent.ExpiresAt, 0).UTC()
			wantCallbacks := 0
			wantStatus, wantError := http.StatusConflict, "windows_update_job_expired"
			if boundary == "store-entry-after-wait" {
				// This is after Manager sampled now, just as admission waiting on
				// SQLite can cross the original grant deadline before loading it.
				f.store.beforeStore = func() { f.clock.set(crossed) }
			} else {
				// Request has created a manager-signed 120-second challenge. Cross
				// that exact deadline only after its mutation callback succeeds.
				crossed = f.at.Add(121 * time.Second)
				if boundary == "final-session-expiry" {
					crossed = f.session.ExpiresAt
					wantStatus, wantError = http.StatusForbidden, "windows_update_job_authority"
				}
				f.store.afterTransition = func() { f.clock.set(crossed) }
				wantCallbacks = 1
			}
			response := f.request(t)
			if response.Code != wantStatus || !bytes.Contains(response.Body.Bytes(), []byte(wantError)) {
				t.Fatalf("expired commit was not rejected: status=%d body=%s", response.Code, response.Body.String())
			}
			if f.store.callbacks != wantCallbacks {
				t.Fatalf("unexpected mutation callbacks: got=%d want=%d", f.store.callbacks, wantCallbacks)
			}
			after, rejected := f.saved(t)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected HTTP request committed request/challenge/permit bytes")
			}
			if rejected != crossed.Unix() {
				t.Fatalf("final observed rejection time not durable: got=%d want=%d", rejected, crossed.Unix())
			}
			// Reopening only the feature domain cannot reconstruct/reset this
			// floor, and rolling the trusted clock back must not revive the job.
			if err := f.store.store.OpenWindowsUpdateJobs(context.Background(), f.handler.windowsUpdateJobs.PublicKey()); err != nil {
				t.Fatal("rejection made committed history unreadable", err)
			}
			f.clock.set(f.at)
			if retry := f.request(t); retry.Code != http.StatusConflict {
				t.Fatalf("clock rollback revived rejected request: status=%d body=%s", retry.Code, retry.Body.String())
			}
			rolledBack, keptFloor := f.saved(t)
			if !bytes.Equal(before, rolledBack) || keptFloor != rejected {
				t.Fatal("rollback changed request bytes or rejection floor")
			}
		})
	}
}
