package api

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"localrmm/internal/offlinecatalog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const catalogFixtureJSON = `{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture"],"rules":[{"sourcePackage":"fixture","advisoryId":"CVE-2099-99990001","release":"trixie","status":"resolved","fixedVersion":"2.0-1","qualifications":[],"archiveVersions":[]}]}`

func enabledCatalogOperator(t *testing.T) operatorFixture {
	t.Helper()
	o := newOperatorFixture(t, 0)
	// Endpoint mechanics are tested behind the actual TLS/session wrapper. The
	// production enablement decision remains the constructor's immutable profile.
	o.app.mu.Lock()
	o.app.catalogStore = offlinecatalog.New()
	o.app.catalogImports = make(chan struct{}, 1)
	o.app.catalogNow = func() time.Time { return time.Now().UTC() }
	o.app.mu.Unlock()
	return o
}
func catalogViewFrom(t *testing.T, o operatorFixture) offlinecatalog.View {
	t.Helper()
	r, v := o.call(t, "GET", "/api/security/catalog", nil, "", nil)
	raw, _ := json.Marshal(v)
	var view offlinecatalog.View
	if r.StatusCode != 200 || json.Unmarshal(raw, &view) != nil {
		t.Fatal("catalog read failed")
	}
	return view
}
func postCatalog(t *testing.T, o operatorFixture, csrf, revision, raw string, change func(*http.Request)) (*http.Response, map[string]any) {
	t.Helper()
	return o.call(t, "POST", "/api/security/catalog", json.RawMessage(raw), csrf, func(r *http.Request) {
		r.Header.Set("X-Tracebolt-Catalog-Revision", revision)
		if change != nil {
			change(r)
		}
	})
}
func TestOfflineCatalogIsDisabledOutsideSelectedProfile(t *testing.T) {
	s := setup(t)
	w := request(s, "GET", "/api/security/catalog", "", nil)
	var v offlinecatalog.View
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Enabled || v.Catalog != nil || v.Revision != "" {
		t.Fatal("development enabled catalog")
	}
	if w = request(s, "POST", "/api/security/catalog", catalogFixtureJSON, nil); w.Code != 404 {
		t.Fatal("development imported catalog")
	}
	o := newOperatorFixture(t, 0)
	_, login := o.login(t)
	if v = catalogViewFrom(t, o); v.Enabled || v.Catalog != nil {
		t.Fatal("manual profile enabled catalog")
	}
	if r, _ := postCatalog(t, o, login["csrfToken"].(string), "revision_"+strings.Repeat("1", 32), catalogFixtureJSON, nil); r.StatusCode != 404 {
		t.Fatal("manual profile imported catalog")
	}
}
func TestOfflineCatalogRealTLSAuthCASAndUnverifiedMetadata(t *testing.T) {
	o := enabledCatalogOperator(t)
	if r, _ := o.call(t, "GET", "/api/security/catalog", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("unauthenticated catalog readable")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before := catalogViewFrom(t, o)
	if !before.Enabled || before.Catalog != nil || !before.ResetsOnRestart || before.Storage != "memory-only" {
		t.Fatal("invalid empty catalog")
	}
	if r, _ := postCatalog(t, o, csrf, before.Revision, catalogFixtureJSON, nil); r.StatusCode != 200 {
		t.Fatal("valid normalized catalog rejected")
	}
	loaded := catalogViewFrom(t, o)
	if loaded.Catalog == nil || loaded.Catalog.OriginAssurance != "unverified" || loaded.Catalog.Freshness != "unknown" || loaded.Catalog.PublishedAt != nil || loaded.Catalog.RuleCount != 1 || loaded.Catalog.CoveredSourceCount != 1 || !loaded.Catalog.Synthetic || loaded.Revision == before.Revision {
		t.Fatal("file import claimed authority or wrong counts")
	}
	raw, _ := json.Marshal(loaded)
	if strings.Contains(string(raw), "CVE-2099") || strings.Contains(string(raw), "fixedVersion") || strings.Contains(string(raw), "sourcePackage") {
		t.Fatal("catalog metadata leaked raw rules")
	}
	if r, _ := postCatalog(t, o, csrf, before.Revision, catalogFixtureJSON, nil); r.StatusCode != 409 {
		t.Fatal("stale revision replaced catalog")
	}
	if after := catalogViewFrom(t, o); after.Revision != loaded.Revision || !after.Catalog.ImportedAt.Equal(loaded.Catalog.ImportedAt) {
		t.Fatal("rejected import changed prior snapshot")
	}
	if r, _ := o.call(t, "POST", "/api/security/catalog/clear", map[string]string{"expectedRevision": loaded.Revision}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("clear failed")
	}
	if cleared := catalogViewFrom(t, o); cleared.Catalog != nil || cleared.Revision == loaded.Revision {
		t.Fatal("clear did not invalidate revision")
	}
}
func TestOfflineCatalogRejectsHeadersAndMalformedInputWithoutReplacing(t *testing.T) {
	o := enabledCatalogOperator(t)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before := catalogViewFrom(t, o)
	if r, _ := postCatalog(t, o, csrf, before.Revision, catalogFixtureJSON, nil); r.StatusCode != 200 {
		t.Fatal("fixture import")
	}
	before = catalogViewFrom(t, o)
	for _, tc := range []struct {
		name   string
		edit   func(*http.Request)
		status int
	}{
		{"missingcsrf", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
		{"duplicatecsrf", func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) }, 403},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"duplicaterevision", func(r *http.Request) { r.Header.Add("X-Tracebolt-Catalog-Revision", before.Revision) }, 400},
		{"encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{"duplicatecontenttype", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r, _ := postCatalog(t, o, csrf, before.Revision, catalogFixtureJSON, tc.edit); r.StatusCode != tc.status {
				t.Fatalf("guard status %d", r.StatusCode)
			}
		})
	}
	bad := []string{
		strings.Replace(catalogFixtureJSON, `"release":"trixie"`, `"release":"noble"`, 1),
		strings.Replace(catalogFixtureJSON, `"synthetic":true`, `"synthetic":null`, 1),
		strings.Replace(catalogFixtureJSON, `"synthetic":true`, `"synthetic":true,"synthetic":false`, 1),
		strings.Replace(catalogFixtureJSON, `"schema":`, `"trust":"vendor_signature_verified","schema":`, 1),
	}
	for _, raw := range bad {
		if r, v := postCatalog(t, o, csrf, before.Revision, raw, nil); r.StatusCode != 400 {
			t.Fatal("invalid file accepted")
		} else {
			encoded, _ := json.Marshal(v)
			if strings.Contains(string(encoded), "CVE-2099") || strings.Contains(string(encoded), "vendor_signature_verified") {
				t.Fatal("raw file echoed")
			}
		}
	}
	if after := catalogViewFrom(t, o); after.Revision != before.Revision || !after.Catalog.ImportedAt.Equal(before.Catalog.ImportedAt) {
		t.Fatal("failed parse changed last-good catalog")
	}
	if r, _ := o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	if r, _ := postCatalog(t, o, csrf, before.Revision, catalogFixtureJSON, nil); r.StatusCode != 401 {
		t.Fatal("logout did not revoke catalog mutation")
	}
}

type catalogActionReader struct {
	reader io.Reader
	once   sync.Once
	action func()
}

func (r *catalogActionReader) Read(p []byte) (int, error) {
	r.once.Do(r.action)
	return r.reader.Read(p)
}
func catalogDirectRequest(o operatorFixture, cookie *http.Cookie, csrf, path, revision, body string, action func()) *http.Request {
	r := httptest.NewRequest("POST", o.server.URL+path, &catalogActionReader{reader: strings.NewReader(body), action: action})
	r.ContentLength = int64(len(body))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", o.server.URL)
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	if revision != "" {
		r.Header.Set("X-Tracebolt-Catalog-Revision", revision)
	}
	return r
}
func TestOfflineCatalogLogoutDuringBodyNeverMutates(t *testing.T) {
	for _, action := range []string{"import", "clear"} {
		t.Run(action, func(t *testing.T) {
			o := enabledCatalogOperator(t)
			login, v := o.login(t)
			csrf := v["csrfToken"].(string)
			cookie := login.Cookies()[0]
			h := o.server.Config.Handler.(*operatorHandler)
			before := catalogViewFrom(t, o)
			if r, _ := postCatalog(t, o, csrf, before.Revision, catalogFixtureJSON, nil); r.StatusCode != 200 {
				t.Fatal("fixture import")
			}
			before = catalogViewFrom(t, o)
			path, revision, body := "/api/security/catalog", before.Revision, catalogFixtureJSON
			if action == "clear" {
				path += "/clear"
				revision = ""
				body = `{"expectedRevision":"` + before.Revision + `"}`
			}
			r := catalogDirectRequest(o, cookie, csrf, path, revision, body, func() { h.auth.Logout(cookie.Value) })
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			after := o.app.catalogStore.View(time.Now().UTC())
			if w.Code != 401 || after.Revision != before.Revision || after.Catalog == nil || !after.Catalog.ImportedAt.Equal(before.Catalog.ImportedAt) {
				t.Fatal("post-logout body mutation admitted")
			}
		})
	}
}
func TestOfflineCatalogAdmissionAndClearInvalidateInFlightImport(t *testing.T) {
	o := enabledCatalogOperator(t)
	login, v := o.login(t)
	csrf := v["csrfToken"].(string)
	cookie := login.Cookies()[0]
	h := o.server.Config.Handler.(*operatorHandler)
	before := catalogViewFrom(t, o)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	r := catalogDirectRequest(o, cookie, csrf, "/api/security/catalog", before.Revision, catalogFixtureJSON, func() { close(entered); <-release })
	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(first, r); close(done) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("import did not enter bounded body slot")
	}
	second := catalogDirectRequest(o, cookie, csrf, "/api/security/catalog", before.Revision, catalogFixtureJSON, func() { t.Error("busy request read its body") })
	w := httptest.NewRecorder()
	h.ServeHTTP(w, second)
	if w.Code != 429 || w.Header().Get("Retry-After") != "2" {
		t.Fatal("unbounded parser/body queue")
	}
	if response, _ := o.call(t, "POST", "/api/security/catalog/clear", map[string]string{"expectedRevision": before.Revision}, csrf, nil); response.StatusCode != 200 {
		t.Fatal("clear blocked behind import read")
	}
	cleared := catalogViewFrom(t, o)
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight import did not finish")
	}
	after := catalogViewFrom(t, o)
	if first.Code != 409 || after.Revision != cleared.Revision || after.Catalog != nil || len(o.app.catalogImports) != 0 {
		t.Fatal("late import resurrected cleared state or leaked slot")
	}
}
