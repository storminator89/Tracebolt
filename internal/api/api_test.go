package api

import (
	"encoding/json"
	"localrmm/internal/fixtures"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T) *Server {
	t.Helper()
	db, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	ds, cs := fixtures.Seed(time.Now())
	if e = db.Seed(ds, cs); e != nil {
		t.Fatal(e)
	}
	s, e := New(db, 8787, t.TempDir(), model.Device{ID: "sandbox-local", Source: "sandbox", Status: "unknown"})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func request(s *Server, method, path, body string, modify func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8787"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:34567"
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", s.csrf)
	if modify != nil {
		modify(r)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestReadContract(t *testing.T) {
	s := setup(t)
	for _, path := range []string{"/api/health", "/api/overview", "/api/devices", "/api/cases", "/api/runbooks", "/api/capabilities", "/api/session", "/api/devices/demo-win-01", "/api/cases/case-demo-win-01-service"} {
		w := request(s, "GET", path, "", nil)
		if w.Code != 200 {
			t.Fatalf("%s status %d: %s", path, w.Code, w.Body)
		}
		if !json.Valid(w.Body.Bytes()) {
			t.Fatal("bad json")
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("headers unsafe")
		}
	}
}
func TestBoundaryGuards(t *testing.T) {
	s := setup(t)
	tests := []struct {
		name, path string
		modify     func(*http.Request)
		want       int
	}{
		{"foreign host", "/api/overview", func(r *http.Request) { r.Host = "evil.test:8787" }, 403},
		{"remote peer", "/api/overview", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:34567" }, 403},
		{"foreign origin", "/api/overview", func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, 403},
		{"duplicate origin", "/api/overview", func(r *http.Request) { r.Header.Add("Origin", "https://evil.test") }, 403},
		{"crosssite", "/api/overview", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"chunked", "/api/overview", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		{"encoded path", "/api/devices/%64emo-win-01", nil, 400},
		{"traversal", "/api/devices/../cases", nil, 400},
		{"query", "/api/devices?limit=-1", nil, 400},
		{"unknown endpoint", "/api/nope", nil, 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(s, "GET", tt.path, "", tt.modify)
			if w.Code != tt.want {
				t.Fatalf("got %d want %d: %s", w.Code, tt.want, w.Body)
			}
		})
	}
}
func TestMutationValidationAndPersistence(t *testing.T) {
	s := setup(t)
	path := "/api/cases/case-demo-win-01-service/notes"
	tests := []struct {
		name, body string
		modify     func(*http.Request)
		want       int
	}{
		{"no origin", `{"text":"hello"}`, func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"no csrf", `{"text":"hello"}`, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
		{"duplicate csrf", `{"text":"hello"}`, func(r *http.Request) { r.Header.Add("X-CSRF-Token", s.csrf) }, 403},
		{"wrong media type", `{"text":"hello"}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"unknown key", `{"text":"hello","extra":"x"}`, nil, 400},
		{"duplicate key", `{"text":"hello","text":"x"}`, nil, 400},
		{"trailing data", `{"text":"hello"}{}`, nil, 400},
		{"null value", `{"text":null}`, nil, 400},
		{"surrogate", `{"text":"\ud800"}`, nil, 400},
		{"empty", `{"text":" "}`, nil, 400},
		{"note cap", `{"text":"` + strings.Repeat("a", 2001) + `"}`, nil, 400},
		{"body cap", `{"text":"` + strings.Repeat("a", 5000) + `"}`, nil, 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(s, "POST", path, tt.body, tt.modify)
			if w.Code != tt.want {
				t.Fatalf("got %d want %d: %s", w.Code, tt.want, w.Body)
			}
		})
	}
	c, e := s.store.Case("case-demo-win-01-service")
	if e != nil || len(c.Notes) != 0 {
		t.Fatal("invalid writes changed state")
	}
	w := request(s, "POST", path, `{"text":"<script>alert(1)</script>"}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("JSON HTML escaping missing")
	}
	c, e = s.store.Case(c.ID)
	if e != nil || len(c.Notes) != 1 {
		t.Fatal("valid note missing")
	}
	w = request(s, "POST", "/api/cases/"+c.ID+"/status", `{"status":"resolved"}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
}
