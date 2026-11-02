package operatorfactorclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testActor = "operator_11111111111111111111111111111111"
const targetActor = "operator_22222222222222222222222222222222"

var testToken = strings.Repeat("a", 64)
var testCSRF = strings.Repeat("b", 64)

func certificate(t *testing.T) tls.Certificate {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "local fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func fixture(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)
	c, e := New(Config{Origin: server.URL, ServerCertificate: server.Certificate().Raw})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c, server
}
func view(auth bool) map[string]any {
	now := time.Now().UTC().Truncate(time.Second)
	v := map[string]any{"loginMode": "named", "loginFactorProfile": "totp-sha256-8", "actorId": nil, "capabilities": []string{}, "mode": "lan", "transport": "https", "insecureTestMode": false, "transportWarning": nil, "authenticationRequired": true, "authenticated": auth, "csrfToken": nil, "serverNow": now, "expiresAt": nil, "expiresInSeconds": nil}
	if auth {
		v["actorId"] = testActor
		v["capabilities"] = []string{"read", "manage_accounts"}
		v["csrfToken"] = testCSRF
		v["expiresAt"] = now.Add(30 * time.Minute)
		v["expiresInSeconds"] = 1800
	}
	return v
}
func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func sessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "__Host-tracebolt-session", Value: testToken, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 1800, Expires: time.Now().UTC().Truncate(time.Second).Add(30 * time.Minute)})
}
func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "__Host-tracebolt-session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
func TestFixedTLSOperationsCookieCSRFAndRedaction(t *testing.T) {
	var calls atomic.Int32
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.ProtoMajor != 1 || r.Header.Get("Origin") != "https://"+r.Host {
			t.Error("unsafe transport/origin")
		}
		if r.URL.RawQuery != "" {
			t.Error("query secret")
		}
		if r.Method == "POST" && r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing JSON")
		}
		switch r.URL.Path {
		case "/api/auth/session":
			if r.Header.Get("Cookie") != "" {
				t.Error("preflight sent ambient cookie")
			}
			reply(w, view(false))
		case "/api/auth/login":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["password"] != "fixture-password" || in["otp"] != "12345678" {
				t.Error("credentials not supplied")
			}
			sessionCookie(w)
			reply(w, view(true))
		case "/api/auth/accounts":
			cookie, e := r.Cookie("__Host-tracebolt-session")
			if e != nil || cookie.Value != testToken {
				t.Error("missing private session")
			}
			reply(w, map[string]any{"items": []any{map[string]any{"id": targetActor, "revision": uint64(3), "revocationFloor": uint64(2), "disabled": false, "uncertain": false, "capabilities": []string{"read"}, "factorState": "active", "factorGeneration": uint64(1)}}})
		case "/api/auth/accounts/reset-factor":
			if r.Header.Get("X-CSRF-Token") != testCSRF {
				t.Error("missing csrf")
			}
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["actorId"] != targetActor || in["expectedRevision"] != float64(3) {
				t.Error("wrong target")
			}
			reply(w, map[string]any{"updated": true, "revision": 4, "factorState": "enrollment_required"})
		case "/api/auth/logout":
			if r.Header.Get("X-CSRF-Token") != testCSRF {
				t.Error("missing logout csrf")
			}
			clearCookie(w)
			reply(w, view(false))
		default:
			t.Error("unexpected path")
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	if e := c.Check(ctx); e != nil {
		t.Fatal(e)
	}
	if e := c.Login(ctx, "admin", []byte("fixture-password"), []byte("12345678")); e != nil {
		t.Fatal(e)
	}
	if c.ActorID() != testActor || !c.CanManageAccounts() {
		t.Fatal("validated server authority missing")
	}
	items, e := c.Accounts(ctx)
	if e != nil || len(items) != 1 || items[0].ID != targetActor {
		t.Fatal("accounts", e)
	}
	if e = c.Reset(ctx, targetActor, 3, []byte("fixture-password"), []byte("23456789")); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(c)
	for _, out := range []string{string(raw), fmt.Sprintf("%v %+v %#v %v %+v %#v", c, c, c, *c, *c, *c)} {
		for _, secret := range []string{testToken, testCSRF, "fixture-password", s.URL} {
			if strings.Contains(out, secret) {
				t.Fatal("client serialization leaked private state")
			}
		}
	}
	if e = c.Logout(ctx); e != nil {
		t.Fatal(e)
	}
	if c.ActorID() != "" || c.CanManageAccounts() {
		t.Fatal("logout retained authority")
	}
	before := calls.Load()
	c.Close()
	if calls.Load() != before {
		t.Fatal("Close performed HTTP")
	}
}
func TestEnrollNeverAcceptsCookieAndRequiresExactResponse(t *testing.T) {
	for _, mode := range []string{"ok", "cookie", "revision", "duplicate", "extra", "missing"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/auth/session" {
					reply(w, view(false))
					return
				}
				if r.URL.Path != "/api/auth/factors/enroll" || r.Header.Get("Cookie") != "" {
					t.Error("enrollment context")
				}
				if mode == "cookie" {
					sessionCookie(w)
				}
				v := map[string]any{"enrolled": true, "revision": uint64(2), "nextStep": "sign_in_with_fresh_factor"}
				switch mode {
				case "revision":
					v["revision"] = 3
				case "extra":
					v["token"] = "secret"
				case "missing":
					delete(v, "enrolled")
				case "duplicate":
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"enrolled":true,"enrolled":true,"revision":2,"nextStep":"sign_in_with_fresh_factor"}`)
					return
				}
				reply(w, v)
			})
			e := c.Enroll(context.Background(), "admin", []byte("password"), []byte("12345678"), 1)
			if mode == "ok" && e != nil {
				t.Fatal(e)
			}
			if mode != "ok" && !errors.Is(e, ErrUncertain) {
				t.Fatal("ambiguous mutation accepted", e)
			}
			if c.ActorID() != "" {
				t.Fatal("enrollment issued local session")
			}
		})
	}
}
func TestPinnedTLSOriginAndProxyPolicy(t *testing.T) {
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) { reply(w, view(false)) })
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	if e := c.Check(context.Background()); e != nil {
		t.Fatal("ambient proxy affected connection", e)
	}
	for _, origin := range []string{"http://127.0.0.1", "https://user@127.0.0.1", s.URL + "/", s.URL + "?q=secret", s.URL + "#fragment", "https://127.0.0.1:443", "https://LOCALHOST", strings.Replace(s.URL, "127.0.0.1", "localhost", 1)} {
		if _, e := New(Config{Origin: origin, ServerCertificate: s.Certificate().Raw}); !errors.Is(e, ErrConfiguration) {
			t.Fatal("invalid origin/certificate accepted")
		}
	}
	other := certificate(t)
	wrong, e := New(Config{Origin: s.URL, ServerCertificate: other.Certificate[0]})
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if e = wrong.Check(context.Background()); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wrong pinned certificate accepted", e)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	valid, e := New(Config{Origin: s.URL, ServerCertificate: public})
	if e != nil {
		t.Fatal(e)
	}
	valid.Close()
	for _, raw := range [][]byte{append(public, public...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private")}), []byte("bad")} {
		if _, e := New(Config{Origin: s.URL, ServerCertificate: raw}); !errors.Is(e, ErrConfiguration) {
			t.Fatal("invalid public material accepted")
		}
	}
}
func TestNoRedirectNoMutationRetryAndSafeErrors(t *testing.T) {
	for _, mode := range []string{"redirect", "lost", "503", "malformed", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			var posts, followed atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
			defer destination.Close()
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/auth/session" {
					reply(w, view(false))
					return
				}
				posts.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				switch mode {
				case "redirect":
					w.Header().Set("Location", destination.URL+"/fixture-password")
					w.WriteHeader(307)
				case "lost":
					connection, _, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
						return
					}
					_ = connection.Close()
				case "503":
					http.Error(w, "fixture-password "+testToken, 503)
				case "malformed":
					reply(w, map[string]any{"authenticated": true, "csrfToken": testToken})
				case "oversize":
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, strings.Repeat("x", (1<<20)+1))
				}
			})
			err := c.Login(context.Background(), "admin", []byte("fixture-password"), []byte("12345678"))
			if !errors.Is(err, ErrUncertain) {
				t.Fatal("lost mutation not uncertain", err)
			}
			if posts.Load() != 1 || followed.Load() != 0 {
				t.Fatal("mutation replay or redirect")
			}
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "fixture-password") || Code(err) != "uncertain" {
				t.Fatal("unsafe error")
			}
		})
	}
}
func TestRejectUnsafeCookiesAndOlderServerBeforeCredentialPOST(t *testing.T) {
	for _, mode := range []string{"old", "missingSecurityField", "domain", "insecure", "lax", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			var posts atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/auth/session" {
					v := view(false)
					if mode == "old" {
						delete(v, "loginFactorProfile")
					}
					if mode == "missingSecurityField" {
						delete(v, "insecureTestMode")
					}
					reply(w, v)
					return
				}
				posts.Add(1)
				cookie := &http.Cookie{Name: "__Host-tracebolt-session", Value: testToken, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 1800, Expires: time.Now().UTC().Truncate(time.Second).Add(30 * time.Minute)}
				switch mode {
				case "domain":
					cookie.Domain = "127.0.0.1"
				case "insecure":
					cookie.Secure = false
				case "lax":
					cookie.SameSite = http.SameSiteLaxMode
				}
				http.SetCookie(w, cookie)
				if mode == "duplicate" {
					http.SetCookie(w, cookie)
				}
				reply(w, view(true))
			})
			err := c.Login(context.Background(), "admin", []byte("password"), []byte("12345678"))
			if mode == "old" || mode == "missingSecurityField" {
				if !errors.Is(err, ErrUnsupported) || posts.Load() != 0 {
					t.Fatal("credentials sent to unsupported profile", err)
				}
			} else if !errors.Is(err, ErrUncertain) {
				t.Fatal("unsafe cookie accepted", err)
			}
		})
	}
}
func TestLogoutOnlyConfirmsKnownInvalidation(t *testing.T) {
	for _, status := range []int{401, 503, 200} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/auth/session" {
					reply(w, view(false))
					return
				}
				if r.URL.Path == "/api/auth/login" {
					sessionCookie(w)
					reply(w, view(true))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{}`)
			})
			if e := c.Login(context.Background(), "admin", []byte("password"), nil); e != nil {
				t.Fatal(e)
			}
			e := c.Logout(context.Background())
			if status == 401 && e != nil {
				t.Fatal(e)
			}
			if status != 401 && !errors.Is(e, ErrUncertain) {
				t.Fatal("unknown logout reported confirmed", e)
			}
			if c.ActorID() != "" {
				t.Fatal("logout retained local cookie")
			}
		})
	}
}

func TestJSONMIMECharsetInteropAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		valid  bool
	}{
		{"plain", []string{"application/json"}, true},
		{"utf8", []string{"application/json; charset=utf-8"}, true},
		{"quotedcase", []string{`Application/JSON; Charset="UTF-8"`}, true},
		{"html", []string{"text/html; charset=utf-8"}, false},
		{"otherCharset", []string{"application/json; charset=iso-8859-1"}, false},
		{"duplicateHeader", []string{"application/json", "application/json"}, false},
		{"unknownParameter", []string{"application/json; profile=other"}, false},
		{"malformed", []string{"application/json; charset"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/auth/session" {
					reply(w, view(false))
					return
				}
				for _, value := range tc.values {
					w.Header().Add("Content-Type", value)
				}
				_, _ = io.WriteString(w, `{"enrolled":true,"revision":2,"nextStep":"sign_in_with_fresh_factor"}`)
			})
			err := c.Enroll(context.Background(), "admin", []byte("password"), []byte("12345678"), 1)
			if tc.valid && err != nil {
				t.Fatal("valid JSON MIME rejected", err)
			}
			if !tc.valid && !errors.Is(err, ErrUncertain) {
				t.Fatal("malformed mutation MIME not uncertain", err)
			}
		})
	}
	// The real server uses this legal header on its preflight auth view too.
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(view(false))
	})
	if err := c.Check(context.Background()); err != nil {
		t.Fatal("preflight charset rejected", err)
	}
	var output map[string]any
	if decode([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, &output) {
		t.Fatal("invalid UTF-8 accepted")
	}
}
