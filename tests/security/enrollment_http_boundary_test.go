package security_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
)

type independentEnrollmentHTTP struct {
	f              *independentServiceFixture
	handler        http.Handler
	server         *httptest.Server
	client         *http.Client
	auth           *operatorauth.Manager
	origin, cookie string
	config         api.LANOperatorConfig
	app            *api.Server
}

const independentSignerErrorMarker = "synthetic-private-signer-detail-must-never-be-in-http"

type independentHTTPErrorSigner struct{ *enrollmentissuer.Issuer }

func (s independentHTTPErrorSigner) Sign(context.Context, enrollmentcrypto.Intent, time.Time) (enrollmentcrypto.VerifiedCertificate, error) {
	return enrollmentcrypto.VerifiedCertificate{}, errors.New(independentSignerErrorMarker)
}

func independentEnrollmentHTTPNew(t *testing.T, httpTest, failSigner bool) *independentEnrollmentHTTP {
	t.Helper()
	h := &independentEnrollmentHTTP{server: httptest.NewUnstartedServer(nil), cookie: operatorauth.CookieName}
	t.Cleanup(h.server.Close)
	scheme, profile := "https", "tls"
	if httpTest {
		scheme, profile, h.cookie = "http", "http-test", "tracebolt-http-test-session"
	}
	h.origin = scheme + "://" + h.server.Listener.Addr().String()
	h.f = independentServiceNewBound(t, false, h.origin, profile)
	var err error
	if failSigner {
		h.f.service, err = enrollmentservice.New(h.f.store, independentHTTPErrorSigner{h.f.issuer}, h.f.clock)
		if err != nil {
			t.Fatal("test signer service failed")
		}
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "ui.sqlite"))
	if err != nil {
		t.Fatal("ephemeral operator database failed")
	}
	t.Cleanup(func() { _ = db.Close() })
	h.app, err = api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal("operator app fixture failed")
	}
	h.auth, err = operatorauth.New(operatorauth.Config{PasswordHash: reviewPasswordHash()})
	if err != nil {
		t.Fatal("operator auth fixture failed")
	}
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(context.Background(), ca.pem, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal("ephemeral registry failed")
	}
	bootstrap := api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: h.f.service.Binding().InstanceID, Profile: profile, EnrollmentOrigin: h.origin, AgentOrigin: h.origin, CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.f.issuer.IssuerDER()})), IssuerRootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.f.issuer.RootDER()}))}
	if !httpTest {
		bootstrap.ServerCAPEM = string(ca.pem)
	}
	h.config = api.LANOperatorConfig{Origin: h.origin, Auth: h.auth, Registry: registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }, InsecureHTTPTest: httpTest, Enrollment: h.f.service, EnrollmentBootstrap: bootstrap}
	h.handler, err = api.NewLANOperatorHandler(h.app, h.config)
	if err != nil {
		t.Fatal("valid enrollment HTTP boundary rejected")
	}
	h.server.Config.Handler = h.handler
	h.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	transport := &http.Transport{}
	if httpTest {
		h.server.Start()
	} else {
		pair, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
		h.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
		h.server.StartTLS()
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca.pem) {
			t.Fatal("ephemeral TLS root failed")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	}
	t.Cleanup(transport.CloseIdleConnections)
	h.client = &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}
func (h *independentEnrollmentHTTP) request(t *testing.T, path string, raw []byte, change func(*http.Request)) (int, []byte, http.Header) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, h.origin+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("request fixture failed")
	}
	r.Header.Set("Content-Type", "application/json")
	if change != nil {
		change(r)
	}
	response, err := h.client.Do(r)
	if err != nil {
		t.Fatal("loopback request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("loopback response failed")
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("enrollment cache or CORS boundary changed")
	}
	return response.StatusCode, body, response.Header
}
func independentChallengeBody() []byte {
	raw, _ := json.Marshal(map[string]string{"invitationId": independentEnrollmentID("invite", 8001), "claimId": independentEnrollmentID("claim", 8001), "purpose": "status"})
	return raw
}
func (h *independentEnrollmentHTTP) session(t *testing.T) operatorauth.Session {
	t.Helper()
	s, err := h.auth.Login(context.Background(), "127.0.0.1", fakeOperatorPassword)
	if err != nil {
		t.Fatal("ordinary disposable session failed")
	}
	return s
}
func (h *independentEnrollmentHTTP) browser(s operatorauth.Session) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set("Origin", h.origin)
		r.Header.Set("X-CSRF-Token", s.CSRFToken)
		r.AddCookie(&http.Cookie{Name: h.cookie, Value: s.Token})
	}
}

func TestIndependentEnrollmentHTTPActualTransportProfiles(t *testing.T) {
	for _, httpTest := range []bool{false, true} {
		name := "tls"
		if httpTest {
			name = "http-test"
		}
		t.Run(name, func(t *testing.T) {
			h := independentEnrollmentHTTPNew(t, httpTest, false)
			code, raw, _ := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), nil)
			var c enrollmentservice.Challenge
			if code != 200 || json.Unmarshal(raw, &c) != nil || c.Context.Origin != h.origin || c.Context.Profile != name || c.Context.ManagerInstanceID != h.f.service.Binding().InstanceID || c.Context.ExpiresAt != h.f.clock().Add(time.Minute).Unix() {
				t.Fatal("actual transport challenge did not use trusted binding/time")
			}
			if code, _, _ := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), func(r *http.Request) { r.Host = "other.example" }); code != 403 {
				t.Fatal("wrong Host admitted")
			}
			pending := h.f.pending(t)
			c = h.f.challenge(t, pending, "status")
			code, raw, _ = h.request(t, "/v2/enrollment/status", h.f.statusBody(t, c, "status"), nil)
			var got enrollmentstate.Snapshot
			if code != 200 || json.Unmarshal(raw, &got) != nil || got != pending {
				t.Fatal("ordinary bound proof did not return exact pending state")
			}
			c = h.f.challenge(t, pending, "credential")
			if code, _, _ := h.request(t, "/v2/enrollment/credential", h.f.statusBody(t, c, "status"), nil); code != 401 {
				t.Fatalf("wrong-purpose proof did not map to invalid proof: HTTP %d", code)
			}
			if code, _, _ := h.request(t, "/api/enrollment/invitations", []byte(`{"requestId":"`+h.f.nextRequest()+`","platform":"linux"}`), nil); code != 401 {
				t.Fatal("native client entered operator mutation")
			}
			// Direct application guard complements the actual transport request.
			r := httptest.NewRequest(http.MethodPost, h.origin+"/v2/enrollment/challenge", bytes.NewReader(independentChallengeBody()))
			r.Header.Set("Content-Type", "application/json")
			if httpTest {
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			} else {
				r.TLS = nil
			}
			w := httptest.NewRecorder()
			h.handler.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal("profile crossed actual-transport requirement")
			}
			changed := h.config
			changed.EnrollmentBootstrap.Profile = "other"
			if _, err := api.NewLANOperatorHandler(h.app, changed); err == nil {
				t.Fatal("bootstrap profile mismatch accepted")
			}
			if httpTest {
				changed = h.config
				changed.InsecureHTTPTest = false
				if _, err := api.NewLANOperatorHandler(h.app, changed); err == nil {
					t.Fatal("plaintext enrollment silently enabled")
				}
			}
		})
	}
}

func TestIndependentEnrollmentHTTPHeadersPathsAndSizes(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	for _, name := range []string{"Cookie", "Origin", "Authorization", "Proxy-Authorization", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "Content-Encoding", "X-CSRF-Token"} {
		t.Run(name, func(t *testing.T) {
			value := "test-value"
			if name == "Origin" {
				value = h.origin
			}
			if code, _, _ := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), func(r *http.Request) { r.Header.Set(name, value) }); code != 400 {
				t.Fatal("native route accepted browser/authority header")
			}
		})
	}
	for _, path := range []string{"/v2/enrollment//challenge", "/v2/enrollment/%63hallenge", "/v2/enrollment/challenge?anything=1", "/v2/enrollment/challenge?"} {
		if code, _, _ := h.request(t, path, independentChallengeBody(), nil); code != 400 {
			t.Fatal("noncanonical native path admitted")
		}
	}
	if code, _, _ := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }); code != 400 {
		t.Fatal("ambiguous native content type accepted")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), func(r *http.Request) { r.Method = "GET" }); code != 405 {
		t.Fatal("native non-POST method accepted")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/status", []byte(strings.Repeat(" ", enrollmentcrypto.MaxClaimBytes+1)), nil); code != 413 {
		t.Fatal("oversized native proof accepted")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/challenge", []byte(strings.Repeat(" ", 1025)), nil); code != 413 {
		t.Fatal("oversized challenge request accepted")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/status", []byte(`{"challenge":"`+strings.Repeat("a", 44)+`"}`), nil); code != 400 {
		t.Fatal("oversized nonce accepted")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/status", []byte(`{"challenge":"`+strings.Repeat("a", 43)+`"}`), nil); code != 401 {
		t.Fatal("unknown exact-size nonce was not rejected")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/challenge", []byte(`{"invitationId":"`+independentEnrollmentID("invite", 8001)+`","claimId":"`+independentEnrollmentID("claim", 8001)+`","purpose":"status","purpose":"status"}`), nil); code != 400 {
		t.Fatal("duplicate challenge fields accepted")
	}
}

func TestIndependentEnrollmentHTTPUsesSocketPeer(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	for n := 0; n < 30; n++ {
		if code, _, _ := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), func(r *http.Request) { r.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", n+1)) }); code != 200 {
			t.Fatal("premature socket-peer limit")
		}
	}
	code, _, header := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), func(r *http.Request) { r.Header.Set("X-Forwarded-For", "203.0.113.9") })
	if code != 429 || header.Get("Retry-After") != "60" {
		t.Fatal("forwarded peer bypassed actual socket limit")
	}
}

func TestIndependentEnrollmentHTTPFixedSignerError(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, true)
	approved := h.f.approved(t)
	c := h.f.challenge(t, approved, "status")
	code, raw, _ := h.request(t, "/v2/enrollment/status", h.f.statusBody(t, c, "status"), nil)
	if code != 503 || bytes.Contains(raw, []byte(independentSignerErrorMarker)) || !bytes.Contains(raw, []byte(`"code":"enrollment_unavailable"`)) {
		t.Fatal("signer dependency error escaped fixed public mapping")
	}
	snapshot, err := h.f.store.Get(context.Background(), approved.InvitationID)
	if err != nil || snapshot.State != enrollmentstate.IssuanceIntent {
		t.Fatal("signer error did not retain durable intent")
	}
}

func TestIndependentEnrollmentHTTPOperatorGuardsAndSecretReadback(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	session := h.session(t)
	payload := []byte(`{"requestId":"` + h.f.nextRequest() + `","platform":"linux"}`)
	for _, missing := range []string{"Origin", "X-CSRF-Token"} {
		if code, _, _ := h.request(t, "/api/enrollment/invitations", payload, func(r *http.Request) { h.browser(session)(r); r.Header.Del(missing) }); code != 403 {
			t.Fatal("operator mutation missing origin/CSRF was admitted")
		}
	}
	code, raw, _ := h.request(t, "/api/enrollment/invitations", payload, h.browser(session))
	var created struct {
		InvitationSecret string                   `json:"invitationSecret"`
		Snapshot         enrollmentstate.Snapshot `json:"snapshot"`
	}
	if code != 201 || json.Unmarshal(raw, &created) != nil || len(created.InvitationSecret) != 43 {
		t.Fatal("authorized invitation creation failed")
	}
	if code, raw, _ := h.request(t, "/api/enrollment/invitations", payload, h.browser(session)); code != 409 || bytes.Contains(raw, []byte(created.InvitationSecret)) {
		t.Fatal("invitation replay recovered one-time secret or minted another grant")
	}
	code, raw, _ = h.request(t, "/api/enrollment", nil, func(r *http.Request) { h.browser(session)(r); r.Method = "GET" })
	if code != 200 || bytes.Contains(raw, []byte(created.InvitationSecret)) || bytes.Contains(raw, []byte("invitationSecret")) {
		t.Fatal("operator readback exposed one-time invitation secret")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/challenge", independentChallengeBody(), h.browser(session)); code != 400 {
		t.Fatal("authenticated browser entered native proof surface")
	}
}

func TestIndependentEnrollmentHTTPOperatorLifecycleFailureDoesNotInvalidateSession(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	pending := h.f.pending(t)
	session := h.session(t)
	approve := func(fingerprint string) int {
		payload, _ := json.Marshal(map[string]any{"requestId": h.f.nextRequest(), "expectedRevision": pending.Revision, "expectedKeyFingerprint": fingerprint})
		code, _, _ := h.request(t, "/api/enrollment/"+pending.InvitationID+"/approve", payload, h.browser(session))
		return code
	}
	if code := approve(strings.Repeat("f", 64)); code != http.StatusBadRequest {
		t.Fatal("operator comparison mismatch did not return the fixed bad-request status")
	}
	h.f.now.Store(pending.DeadlineAt + 1)
	if code := approve(pending.Claim.KeyFingerprint); code != http.StatusConflict {
		t.Fatal("expired enrollment lifecycle was misclassified as session authentication failure")
	}
	if _, err := h.auth.Lookup(session.Token); err != nil {
		t.Fatal("lifecycle rejection revoked the operator session")
	}
	if code, _, _ := h.request(t, "/api/session", nil, func(r *http.Request) { h.browser(session)(r); r.Method = http.MethodGet }); code != http.StatusOK {
		t.Fatal("operator could not continue after lifecycle rejection")
	}
}

func TestIndependentEnrollmentHTTPOperatorLogoutDuringBody(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	pending := h.f.pending(t)
	for _, action := range []string{"create", "approve", "terminate"} {
		t.Run(action, func(t *testing.T) {
			session := h.session(t)
			path := "/api/enrollment/invitations"
			raw := []byte(`{"requestId":"` + h.f.nextRequest() + `","platform":"linux"}`)
			if action == "approve" {
				path = "/api/enrollment/" + pending.InvitationID + "/approve"
				raw, _ = json.Marshal(map[string]any{"requestId": h.f.nextRequest(), "expectedRevision": pending.Revision, "expectedKeyFingerprint": pending.Claim.KeyFingerprint})
			}
			if action == "terminate" {
				path = "/api/enrollment/" + pending.InvitationID + "/terminate"
				raw, _ = json.Marshal(map[string]any{"requestId": h.f.nextRequest(), "expectedRevision": pending.Revision, "action": "canceled"})
			}
			r := httptest.NewRequest(http.MethodPost, h.origin+path, nil)
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			r.Header.Set("Content-Type", "application/json")
			h.browser(session)(r)
			r.ContentLength = int64(len(raw))
			r.Body = &reviewRevokingBody{reader: bytes.NewReader(raw), revoke: func() { h.auth.Logout(session.Token) }}
			w := httptest.NewRecorder()
			h.handler.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatal("logout during body read retained mutation authority")
			}
			snapshots, err := h.f.store.Snapshots(context.Background())
			if err != nil || len(snapshots) != 1 || snapshots[0] != pending {
				t.Fatal("revoked operator changed enrollment state")
			}
		})
	}
}

func TestIndependentEnrollmentHTTPRejectsTLS12(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	tls12 := h.client.Transport.(*http.Transport).TLSClientConfig.Clone()
	tls12.MinVersion, tls12.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	transport := &http.Transport{TLSClientConfig: tls12}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	r, err := http.NewRequest(http.MethodPost, h.origin+"/v2/enrollment/challenge", bytes.NewReader(independentChallengeBody()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("TLS 1.2 reached enrollment listener")
	}
	// Even if a future listener offers TLS 1.2, the handler must reject it.
	direct := httptest.NewRequest(http.MethodPost, h.origin+"/v2/enrollment/challenge", bytes.NewReader(independentChallengeBody()))
	direct.Header.Set("Content-Type", "application/json")
	direct.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, direct)
	if w.Code != 403 {
		t.Fatal("application accepted TLS below 1.3")
	}
}

func TestIndependentEnrollmentHTTPBootstrapBindingAndPublicMaterial(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	keyDER, err := x509.MarshalPKCS8PrivateKey(h.f.key)
	if err != nil {
		t.Fatal("disposable private material fixture failed")
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	cases := map[string]func(*api.EnrollmentBootstrap){
		"instance":               func(b *api.EnrollmentBootstrap) { b.ManagerInstanceID = independentEnrollmentID("manager", 9002) },
		"profile":                func(b *api.EnrollmentBootstrap) { b.Profile = "http-test" },
		"enrollment destination": func(b *api.EnrollmentBootstrap) { b.EnrollmentOrigin = "https://other.example" },
		"collection profile":     func(b *api.EnrollmentBootstrap) { b.CollectionProfile = "unexpected" },
		"preset invitation":      func(b *api.EnrollmentBootstrap) { b.InvitationID = independentEnrollmentID("invite", 9002) },
		"issuer":                 func(b *api.EnrollmentBootstrap) { b.IssuerPEM = b.IssuerRootPEM },
		"issuer root":            func(b *api.EnrollmentBootstrap) { b.IssuerRootPEM = b.IssuerPEM },
		"agent downgrade":        func(b *api.EnrollmentBootstrap) { b.AgentOrigin = "http://other.example" },
		"agent userinfo":         func(b *api.EnrollmentBootstrap) { b.AgentOrigin = "https://name@other.example" },
		"server private block":   func(b *api.EnrollmentBootstrap) { b.ServerCAPEM = privatePEM + b.ServerCAPEM },
		"issuer private block":   func(b *api.EnrollmentBootstrap) { b.IssuerPEM += privatePEM },
		"root private block":     func(b *api.EnrollmentBootstrap) { b.IssuerRootPEM = privatePEM + b.IssuerRootPEM },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := h.config
			mutate(&config.EnrollmentBootstrap)
			if _, err := api.NewLANOperatorHandler(h.app, config); err == nil {
				t.Fatal("mismatched or non-public bootstrap accepted")
			}
		})
	}
}

func TestIndependentEnrollmentHTTPBootstrapRejectsSkippedPrefixes(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	for _, field := range []string{"server", "issuer", "root"} {
		for n, prefix := range []string{"harmless-non-certificate-prefix\n", "-----BEGIN NON-CERTIFICATE\nharmless malformed fixture prefix\n"} {
			t.Run(fmt.Sprintf("%s/%d", field, n), func(t *testing.T) {
				config := h.config
				switch field {
				case "server":
					config.EnrollmentBootstrap.ServerCAPEM = prefix + config.EnrollmentBootstrap.ServerCAPEM
				case "issuer":
					config.EnrollmentBootstrap.IssuerPEM = prefix + config.EnrollmentBootstrap.IssuerPEM
				case "root":
					config.EnrollmentBootstrap.IssuerRootPEM = prefix + config.EnrollmentBootstrap.IssuerRootPEM
				}
				if _, err := api.NewLANOperatorHandler(h.app, config); err == nil {
					t.Fatal("bootstrap retained non-certificate prefix skipped by pem.Decode")
				}
			})
		}
	}
}

func TestIndependentEnrollmentHTTPRejectsProofContextAndReplay(t *testing.T) {
	h := independentEnrollmentHTTPNew(t, false, false)
	pending := h.f.pending(t)
	for _, field := range []string{"instance", "profile"} {
		c := h.f.challenge(t, pending, "status")
		changed := c
		if field == "instance" {
			changed.Context.ManagerInstanceID = independentEnrollmentID("manager", 9901)
		}
		if field == "profile" {
			changed.Context.Profile = "http-test"
			changed.Context.Origin = strings.Replace(h.origin, "https://", "http://", 1)
		}
		if code, _, _ := h.request(t, "/v2/enrollment/status", h.f.statusBody(t, changed, "status"), nil); code != 401 {
			t.Fatal("proof moved to another trusted instance/profile")
		}
		if code, _, _ := h.request(t, "/v2/enrollment/status", h.f.statusBody(t, c, "status"), nil); code != 401 {
			t.Fatal("rejected request left challenge reusable")
		}
	}
	c := h.f.challenge(t, pending, "status")
	raw := h.f.statusBody(t, c, "status")
	if code, _, _ := h.request(t, "/v2/enrollment/status", raw, nil); code != 200 {
		t.Fatal("ordinary proof failed")
	}
	if code, _, _ := h.request(t, "/v2/enrollment/status", raw, nil); code != 401 {
		t.Fatal("HTTP proof replay accepted")
	}
	c = h.f.challenge(t, pending, "status")
	raw = h.f.statusBody(t, c, "status")
	h.f.now.Add(60)
	if code, _, _ := h.request(t, "/v2/enrollment/status", raw, nil); code != 401 {
		t.Fatal("HTTP proof accepted at challenge expiry")
	}
}
