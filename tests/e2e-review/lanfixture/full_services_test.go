package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/api"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/windowsfullservices"
)

func TestFullServicesBrowserFixtureRealProtectedPages(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	_, portText, e := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if e != nil {
		t.Fatal(e)
	}
	port, _ := strconv.Atoi(portText)
	dir := t.TempDir()
	web := filepath.Join(dir, "web")
	if os.Mkdir(web, 0700) != nil || os.WriteFile(filepath.Join(web, "index.html"), []byte("fixture"), 0600) != nil {
		t.Fatal("fixture web")
	}
	appStore, e := store.Open(filepath.Join(dir, "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer appStore.Close()
	app, e := api.New(appStore, port, web, model.Device{})
	if e != nil {
		t.Fatal(e)
	}
	salt := []byte("browser-test-salt")
	hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: encoded, TTL: 10 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	issuer, e := fullServicesIssuer(time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	registry, e := lantrust.NewRegistry(context.Background(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.RootDER()}), lantrust.NewMemoryStore())
	if e != nil {
		t.Fatal(e)
	}
	cfg := api.LANOperatorConfig{Origin: server.URL, Auth: auth, Registry: registry, InsecureHTTPTest: true}
	fixture, e := newFullServicesFixture(server.URL, dir, &cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer fixture.close()
	handler, e := api.NewLANOperatorHandler(app, cfg)
	if e != nil {
		t.Fatal(e)
	}
	server.Config.Handler = fixture.handler(handler, auth)
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path string, v any, authorized bool) (int, []byte) {
		var body io.Reader
		if v != nil {
			body = bytes.NewReader(fsJSON(v))
		}
		req, e := http.NewRequest(method, server.URL+path, body)
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if authorized {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		for _, c := range res.Cookies() {
			cookie = c
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, windowsfullservices.MaxPageBytes+1))
		if e != nil {
			t.Fatal(e)
		}
		return res.StatusCode, raw
	}
	control := "/__fixture/windows-full-services"
	if status, _ := call("GET", control, nil, false); status != 401 {
		t.Fatal("anonymous fixture admitted", status)
	}
	status, raw := call("POST", "/api/auth/login", map[string]string{"password": fixturePassword}, false)
	var login struct {
		CSRF string `json:"csrfToken"`
	}
	if status != 200 || json.Unmarshal(raw, &login) != nil || login.CSRF == "" {
		t.Fatal("fixture login", status)
	}
	csrf = login.CSRF
	if status, _ := call("POST", control, map[string]string{"action": "replace"}, false); status != 403 {
		t.Fatal("missing fixture csrf", status)
	}
	path := "/api/devices/" + fixture.snap.Approval.DeviceID
	if status, raw := call("GET", path, nil, false); status != 200 || !bytes.Contains(raw, []byte(`"platform":"windows"`)) {
		t.Fatal("Windows detail missing", status)
	}
	phase := "initial"
	query := windowsfullservices.Query{Sort: "name-asc", Limit: 100}
	page := func() windowsfullservices.Page {
		t.Helper()
		status, raw := call("POST", path+"/windows-full-services/query", query, true)
		var p windowsfullservices.Page
		if status != 200 || json.Unmarshal(raw, &p) != nil {
			t.Fatal("real fixture page", phase, status)
		}
		return p
	}
	first := page()
	if first.Status != "ready" || len(first.Rows) != 100 || first.MatchingCount != 2051 {
		t.Fatal("initial generation", first.Status)
	}
	phase = "search"
	query.Search = fixture.info.LaterSearch
	p := page()
	if len(p.Rows) != 1 || p.Rows[0].Name != fixture.info.LaterName {
		t.Fatal("later Unicode row missing")
	}
	query.Search = ""
	for _, action := range []string{"fail", "byte-short", "empty", "near-expiry", "replace", "disable", "enable", "revoke"} {
		phase = action
		if status, _ := call("POST", control, map[string]string{"action": action}, true); status != 200 {
			t.Fatal("fixture action", action, status)
		}
		if action == "revoke" {
			if status, _ := call("POST", path+"/windows-full-services/query", query, true); status != 403 {
				t.Fatal("revoked generation disclosed", status)
			}
			continue
		}
		p = page()
		switch action {
		case "fail":
			if p.Complete == nil || p.Complete.ManifestSHA256 != first.Complete.ManifestSHA256 || p.LatestAttempt.Status != "source_failed" {
				t.Fatal("failure refreshed complete")
			}
		case "byte-short":
			if len(p.Rows) < 1 || len(p.Rows) >= 100 || p.NextCursor == "" {
				t.Fatal("byte-short page missing", len(p.Rows))
			}
			query.Cursor = p.NextCursor
			second := page()
			query.Cursor = ""
			if len(p.Rows)+len(second.Rows) != 128 || second.NextCursor != "" {
				t.Fatal("byte-short continuation")
			}
		case "empty":
			if p.Status != "ready" || p.MatchingCount != 0 || p.Complete.Manifest.RowCount != 0 {
				t.Fatal("healthy empty missing")
			}
		case "disable":
			if p.Status != "disabled" || len(p.Rows) != 0 {
				t.Fatal("disabled rows")
			}
		case "near-expiry":
			remaining := p.Complete.Manifest.ExpiresAt.Sub(p.ServerNow)
			if remaining < 5*time.Second || remaining > 8*time.Second {
				t.Fatal("near-expiry interval", remaining)
			}
		default:
			if p.MatchingCount != 2051 {
				t.Fatal("replacement missing")
			}
		}
	}
}

func BenchmarkFullServicesStorePage2051(b *testing.B) {
	cfg := api.LANOperatorConfig{}
	f, e := newFullServicesFixture("http://127.0.0.1:19887", b.TempDir(), &cfg)
	if e != nil {
		b.Fatal(e)
	}
	defer f.close()
	query := windowsfullservices.Query{Search: "Invented", Sort: "name-asc", Limit: 100}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, e := f.service.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, query, f.now())
		if e != nil || p.MatchingCount != 2051 || len(p.Rows) != 100 {
			b.Fatal("bounded full-generation search failed", e)
		}
	}
}
