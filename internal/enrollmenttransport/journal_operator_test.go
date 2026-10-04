package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalwire"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
)

var journalPasswordOnce sync.Once
var journalPasswordHash string

func journalFixturePasswordHash() string {
	journalPasswordOnce.Do(func() {
		salt := []byte("journal-test-only-salt")
		hash := argon2.IDKey([]byte("invented-journal-password"), salt, 2, 65536, 1, 32)
		journalPasswordHash = "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	})
	return journalPasswordHash
}

type journalOperatorFixture struct {
	handler          http.Handler
	service          *enrollmentservice.Service
	session          operatorauth.Session
	origin, profile  string
	clock, authClock atomic.Int64
}

func journalOperatorFixtureNew(t *testing.T, f *fixture, h *Ingress) *journalOperatorFixture {
	t.Helper()
	o := &journalOperatorFixture{origin: f.config.Binding.Origin, profile: f.config.Binding.Profile}
	o.clock.Store(time.Now().UTC().UnixNano())
	o.authClock.Store(o.clock.Load())
	now := func() time.Time { return time.Unix(0, o.clock.Load()).UTC() }
	var e error
	o.service, e = enrollmentservice.New(f.store, f.issuer, now)
	if e != nil {
		t.Fatal(e)
	}
	h.journal = o.service.JournalCache()
	db, e := store.Open(filepath.Join(t.TempDir(), "journal-ui.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	app, e := api.New(db, 8787, t.TempDir(), model.Device{})
	if e != nil {
		t.Fatal(e)
	}
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: journalFixturePasswordHash(), TTL: 2 * time.Minute, Now: func() time.Time { return time.Unix(0, o.authClock.Load()).UTC() }})
	if e != nil {
		t.Fatal(e)
	}
	o.session, e = auth.Login(context.Background(), "127.0.0.1", "invented-journal-password")
	if e != nil {
		t.Fatal(e)
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})
	registry, e := lantrust.NewRegistry(context.Background(), root, lantrust.NewMemoryStore())
	if e != nil {
		t.Fatal(e)
	}
	bootstrap := api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: f.config.Binding.InstanceID, Profile: o.profile, EnrollmentOrigin: o.origin, AgentOrigin: o.origin, CollectionProfile: f.config.Binding.CollectionProfile, IssuerRootPEM: string(root), IssuerPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.IssuerDER()}))}
	if o.profile == "tls" {
		bootstrap.ServerCAPEM = string(root)
	}
	o.handler, e = api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: o.origin, Auth: auth, Registry: registry, Devices: func() ([]model.Device, error) { return o.service.Devices(context.Background(), now()) }, InsecureHTTPTest: o.profile == "http-test", Enrollment: o.service, EnrollmentBootstrap: bootstrap})
	if e != nil {
		t.Fatal(e)
	}
	return o
}

type journalClockBody struct {
	io.ReadCloser
	change func()
	once   sync.Once
}

func (b *journalClockBody) Read(p []byte) (int, error) {
	b.once.Do(b.change)
	return b.ReadCloser.Read(p)
}
func (o *journalOperatorFixture) call(t *testing.T, path string, input any, onRead func()) *httptest.ResponseRecorder {
	t.Helper()
	raw, e := json.Marshal(input)
	if e != nil {
		t.Fatal(e)
	}
	req := httptest.NewRequest(http.MethodPost, o.origin+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", o.origin)
	req.Header.Set("X-CSRF-Token", o.session.CSRFToken)
	name := operatorauth.CookieName
	if o.profile == "http-test" {
		name = "tracebolt-http-test-session"
	} else {
		req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	}
	req.AddCookie(&http.Cookie{Name: name, Value: o.session.Token})
	if onRead != nil {
		req.Body = &journalClockBody{ReadCloser: req.Body, change: onRead}
	}
	out := httptest.NewRecorder()
	o.handler.ServeHTTP(out, req)
	return out
}

// The operator calls use a TLS-shaped direct handler so a controlled body reader
// can advance trusted clocks mid-parse. Agent calls use actual loopback TLS/HTTP.
func TestJournalOperatorCreationAndPageRechecksBodyTimeAndSession(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, expiry := range []string{"content", "session"} {
			t.Run(profile+"/"+expiry, func(t *testing.T) {
				f, h, origin, client, initial := prepareJournalTransportFixture(t, profile)
				o := journalOperatorFixtureNew(t, f, h)
				path := "/api/devices/" + initial.DeviceID + "/journal"
				canceled := o.call(t, path+"/cancel", map[string]any{"identity": initial.Identity}, nil)
				if canceled.Code != 200 {
					t.Fatal("cancel boundary", canceled.Code)
				}
				created := o.call(t, path+"/create", map[string]any{"expectedFloor": "1", "query": initial.Query, "acknowledgeLogContent": true, "acknowledgePlaintext": profile == "http-test"}, nil)
				if created.Code != 200 {
					t.Fatal("create boundary", created.Code)
				}
				var view struct {
					Request       *journalrequest.Status `json:"request"`
					ExpectedFloor string                 `json:"expectedFloor"`
				}
				if json.Unmarshal(created.Body.Bytes(), &view) != nil || view.Request == nil || view.ExpectedFloor != "2" {
					t.Fatal("create response")
				}
				d := view.Request.Description
				claim := claimJournalFixture(t, f, origin, client, d)
				result := journalResultFixture(d, claim, 3)
				body, _ := journalwire.EncodeResult(result)
				accepted := response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, body), 200)
				receipt, e := journalwire.DecodeReceipt(accepted)
				if e != nil {
					t.Fatal(e)
				}
				o.clock.Store(time.Now().UTC().UnixNano())
				q := journalcache.PageRequest{Identity: d.Identity, SnapshotDigest: receipt.ResultDigest, Search: "NEEDLE", Limit: 100}
				before := o.call(t, path+"/query", q, nil)
				if before.Code != 200 || !bytes.Contains(before.Body.Bytes(), []byte("INVENTED_JOURNAL_CONTENT_ONLY")) {
					t.Fatal("positive operator page", before.Code)
				}
				changed := false
				after := o.call(t, path+"/query", q, func() {
					changed = true
					if expiry == "content" {
						o.clock.Store(d.ExpiresAt.Add(time.Second).UnixNano())
					} else {
						o.authClock.Store(o.session.ExpiresAt.Add(time.Second).UnixNano())
					}
				})
				want := 409
				if expiry == "session" {
					want = 401
				}
				if !changed || after.Code != want || bytes.Contains(after.Body.Bytes(), []byte("INVENTED_JOURNAL_CONTENT_ONLY")) || bytes.Contains(after.Body.Bytes(), []byte(`"rows"`)) {
					t.Fatal("post-body authority/time check", after.Code, want)
				}
			})
		}
	}
}
