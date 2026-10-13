package api

import (
	"context"
	"crypto/tls"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/macosinventorywire"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const macInventoryDevice = "agent_1234567890abcdef1234567890abcdef"
const macInventoryQueryBody = `{"section":"summary","generationId":"","offset":0,"limit":100}`

type fixtureMacInventorySource struct {
	at                    time.Time
	page                  enrollmentstore.MacOSInventoryPage
	readErr, finalErr     error
	readCalls, finalCalls int
	onRead, onFinal       func()
}

func (f *fixtureMacInventorySource) Now() time.Time { return f.at }
func (f *fixtureMacInventorySource) MacOSInventoryPage(_ context.Context, device string, q enrollmentstore.MacOSInventoryQuery, _ time.Time) (enrollmentstore.MacOSInventoryPage, error) {
	f.readCalls++
	if f.onRead != nil {
		f.onRead()
	}
	return f.page, f.readErr
}
func (f *fixtureMacInventorySource) RecheckMacOSInventoryPage(context.Context, enrollmentstore.MacOSInventoryPage, time.Time) error {
	f.finalCalls++
	if f.onFinal != nil {
		f.onFinal()
	}
	return f.finalErr
}
func macInventoryRequest(body string, active *bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://manager.invalid/api/devices/"+macInventoryDevice+"/macos-inventory/query", strings.NewReader(body))
	r.Header.Set("Origin", "https://manager.invalid")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", "synthetic-csrf")
	owner := operatorRequest{origin: "https://manager.invalid", session: operatorauth.Session{ID: "synthetic-session", CSRFToken: "synthetic-csrf", ExpiresAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)}, active: func() bool { return *active }}
	return r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, owner))
}
func TestMacOSInventoryPrivateQueryFinalGuards(t *testing.T) {
	for _, kind := range []string{"success", "expired", "revoked", "generation", "logout-during-read", "logout-at-write", "oversize", "source-error"} {
		t.Run(kind, func(t *testing.T) {
			live := true
			r := macInventoryRequest(macInventoryQueryBody, &live)
			f := &fixtureMacInventorySource{at: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC), page: enrollmentstore.MacOSInventoryPage{DeviceID: macInventoryDevice, ReceiptIDs: []string{"private-synthetic-receipt"}}}
			switch kind {
			case "expired":
				f.finalErr = macosinventorywire.ErrExpired
			case "revoked":
				f.finalErr = enrollmentstate.ErrProof
			case "generation":
				f.finalErr = macosinventorywire.ErrConflict
			case "logout-during-read":
				f.onRead = func() { live = false }
			case "logout-at-write":
				f.onFinal = func() { live = false }
			case "oversize":
				f.page.ReceiptIDs = []string{strings.Repeat("x", enrollmentstore.MacOSInventoryMaxPageBytes)}
			case "source-error":
				f.readErr = errors.New("private-source-error")
			}
			w := httptest.NewRecorder()
			h := operatorHandler{app: &Server{}}
			h.writeMacOSInventoryQuery(w, r, f)
			if kind == "success" {
				if w.Code != 200 || f.finalCalls != 1 || !strings.Contains(w.Body.String(), "private-synthetic-receipt") {
					t.Fatal("valid page", w.Code, f.finalCalls)
				}
				return
			}
			if w.Code == 200 || strings.Contains(w.Body.String(), "private-synthetic-receipt") || strings.Contains(w.Body.String(), "private-source-error") {
				t.Fatal("private bytes escaped final guard", kind, w.Code)
			}
			if kind == "oversize" && f.finalCalls != 0 {
				t.Fatal("oversized body reached final admission")
			}
		})
	}
}
func TestMacOSInventoryQueryStrictBoundary(t *testing.T) {
	for _, kind := range []string{"GET", "query", "force-query", "wrong-domain", "wrong-device", "encoded-path", "csrf", "origin", "content-type", "compressed", "chunked", "missing-session", "inactive", "unknown", "duplicate", "null", "missing", "case", "huge", "bad-generation", "bad-limit", "bad-offset", "bad-section"} {
		t.Run(kind, func(t *testing.T) {
			live := true
			body := macInventoryQueryBody
			switch kind {
			case "unknown":
				body = strings.Replace(body, "{", `{"extra":1,`, 1)
			case "duplicate":
				body = strings.Replace(body, "{", `{"limit":100,`, 1)
			case "null":
				body = strings.Replace(body, `"summary"`, `null`, 1)
			case "missing":
				body = `{"section":"summary","offset":0,"limit":100}`
			case "case":
				body = strings.Replace(body, "section", "Section", 1)
			case "huge":
				body = strings.Repeat(" ", 1025) + body
			case "bad-generation":
				body = strings.Replace(body, `"generationId":""`, `"generationId":"sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, 1)
			case "bad-limit":
				body = strings.Replace(body, "100", "101", 1)
			case "bad-offset":
				body = strings.Replace(body, `"offset":0`, `"offset":1`, 1)
			case "bad-section":
				body = strings.Replace(body, "summary", "logs", 1)
			}
			r := macInventoryRequest(body, &live)
			switch kind {
			case "GET":
				r.Method = "GET"
			case "query":
				r.URL.RawQuery = "receipt=private"
			case "force-query":
				r.URL.ForceQuery = true
			case "wrong-domain":
				r.URL.Path = strings.Replace(r.URL.Path, "macos-inventory", "windows-full-processes", 1)
			case "wrong-device":
				r.URL.Path = strings.Replace(r.URL.Path, macInventoryDevice, "not-an-agent", 1)
			case "encoded-path":
				r.URL.RawPath = strings.Replace(r.URL.Path, "query", "%71uery", 1)
			case "csrf":
				r.Header.Del("X-CSRF-Token")
			case "origin":
				r.Header.Set("Origin", "https://foreign.invalid")
			case "content-type":
				r.Header.Set("Content-Type", "text/plain")
			case "compressed":
				r.Header.Set("Content-Encoding", "gzip")
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
			case "missing-session":
				r = r.WithContext(context.Background())
			case "inactive":
				live = false
			}
			f := &fixtureMacInventorySource{}
			w := httptest.NewRecorder()
			h := operatorHandler{app: &Server{}}
			h.writeMacOSInventoryQuery(w, r, f)
			if w.Code == 200 || f.readCalls != 0 {
				t.Fatal("invalid query reached source", kind, w.Code, f.readCalls)
			}
		})
	}
}
func TestMacOSInventoryReadCapabilityDoesNotAuthorizeEnrollment(t *testing.T) {
	for _, path := range []string{"/api/devices/" + macInventoryDevice + "/macos-inventory/query", "/api/devices/" + macInventoryDevice + "/macos-inventory/query?", "/api/devices/" + macInventoryDevice + "/macos-inventory/query?x=y", "/api/macos-inventory/enrollment/invitations", "/api/devices/" + macInventoryDevice + "/macos-inventory/disable"} {
		r := httptest.NewRequest("POST", "https://manager.invalid"+path, nil)
		want := path == "/api/devices/"+macInventoryDevice+"/macos-inventory/query"
		if namedReadRoute(r) != want {
			t.Fatal("read privilege widened", path)
		}
	}
}
func TestMacOSInventoryInvitationRequiresFreshAcknowledgement(t *testing.T) {
	for _, body := range []string{`{"requestId":"request_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"darwin"}`, `{"requestId":"request_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"darwin","collectionAcknowledged":false}`, `{"requestId":"request_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"darwin","collectionAcknowledged":true}`, `{"requestId":"request_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"darwin","collectionAcknowledged":true,"insecureHTTPAcknowledged":true}`} {
		r := httptest.NewRequest("POST", "https://manager.invalid/api/macos-inventory/enrollment/invitations", strings.NewReader(body))
		w := httptest.NewRecorder()
		_, ok := readInvitationInput(w, r, enrollmentcrypto.CollectionProfileMacOSInventory)
		want := strings.HasSuffix(body, `"collectionAcknowledged":true}`)
		if ok != want {
			t.Fatal("scope acknowledgement mismatch", ok)
		}
	}
	// A basic profile cannot acquire expanded scope through request fields.
	r := httptest.NewRequest("POST", "https://manager.invalid/api/macos/enrollment/invitations", strings.NewReader(`{"requestId":"request_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"darwin","collectionAcknowledged":true}`))
	w := httptest.NewRecorder()
	if _, ok := readInvitationInput(w, r, enrollmentcrypto.CollectionProfile); ok {
		t.Fatal("basic invitation promoted")
	}
}
func TestMacOSInventoryClientRoutesReservedWhenDisabled(t *testing.T) {
	h := operatorHandler{origin: "https://manager.invalid", authority: "manager.invalid"}
	for _, suffix := range []string{"", "/challenge", "/claim", "/renewal/activate", "/unknown"} {
		r := httptest.NewRequest("POST", "https://manager.invalid/v2/macos-inventory/enrollment"+suffix, strings.NewReader("{}"))
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 || !strings.Contains(w.Body.String(), "enrollment_unavailable") {
			t.Fatal("disabled domain fell through", suffix, w.Code)
		}
	}
}

func TestMacOSInventoryPlatformAdvertisementStaysTLSOnly(t *testing.T) {
	for _, profile := range []string{"tls", "http-test", ""} {
		got := enrollmentPlatforms(enrollmentstate.Binding{Profile: profile, CollectionProfile: enrollmentcrypto.CollectionProfileMacOSInventory})
		if profile == "tls" {
			if len(got) != 1 || got[0] != "darwin" {
				t.Fatal("fresh TLS platform missing")
			}
		} else if len(got) != 0 {
			t.Fatal("non-TLS inventory advertised")
		}
	}
}
