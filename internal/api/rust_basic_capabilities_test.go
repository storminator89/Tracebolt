package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/rustcompat"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rustBasicFixture(t *testing.T, renewable ...bool) (*operatorHandler, *enrollmentservice.Service) {
	now := time.Now().UTC()
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral checksum root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("checksum-root")}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rd)
	if e != nil {
		t.Fatal(e)
	}
	ip, ik, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Ephemeral checksum issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("checksum-issuer")}
	id, e := x509.CreateCertificate(rand.Reader, issuerTemplate, root, ip, rk)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(id)
	issuer, e := enrollmentissuer.New(id, rd, ik, hex.EncodeToString(sum[:]), now)
	if e != nil {
		t.Fatal(e)
	}
	binding := enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "tls", Origin: "https://127.0.0.1:8787", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, IssuerFingerprint: issuer.Fingerprint()}
	config := enrollmentstate.DefaultConfig(binding)
	if len(renewable) == 1 && renewable[0] {
		config.AutomaticRenewal = true
		config.RenewalAgentOrigin = "https://127.0.0.1:8788"
	}
	config.RecordLimit = 25
	config.InvitationLimit = 25
	config.PendingLimit = 25
	store, e := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "enrollment.db"), config, id)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	service, e := enrollmentservice.New(store, issuer, nil)
	if e != nil {
		t.Fatal(e)
	}
	pemText := func(raw []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	b := EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, EnrollmentOrigin: binding.Origin, AgentOrigin: "https://127.0.0.1:8788", ServerCAPEM: pemText(rd), CollectionProfile: binding.CollectionProfile, IssuerRootPEM: pemText(rd), IssuerPEM: pemText(id)}

	if config.AutomaticRenewal {
		b.SchemaVersion = "tracebolt.enrollment-bootstrap.renewable.v1"
		b.RenewalPolicy = enrollmentcrypto.RenewalPolicySameKey
	}
	return &operatorHandler{origin: binding.Origin, authority: "127.0.0.1:8787", windowsEnrollment: &operatorHandler{enrollment: service, enrollmentBootstrap: b}}, service
}

func TestRustBasicCapabilitiesRealServiceGuardedNonmutating(t *testing.T) {
	h, service := rustBasicFixture(t)
	original := h.windowsEnrollment.enrollmentBootstrap
	if !service.SelfClaimAvailable() || service.SelfClaimPlatform() != "windows" {
		t.Fatal("fixture must have real automatic Windows registration")
	}
	for _, kind := range []string{"exact", "head", "post", "body", "hidden-body", "cookie", "authorization", "noncanonical-credential", "origin", "forwarded", "query", "force-query", "encoded", "missing-tls", "old-tls", "incomplete-tls", "wrong-host", "missing-host", "http-test", "absent", "wrong-domain", "wrong-binding", "invalid-bootstrap", "renewal-policy"} {
		t.Run(kind, func(t *testing.T) {
			h.windowsEnrollment.enrollmentBootstrap = original
			h.windowsEnrollment.enrollment = service
			h.insecureHTTPTest = false
			r := httptest.NewRequest(http.MethodGet, h.origin+rustcompat.Path, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			switch kind {
			case "head":
				r.Method = http.MethodHead
			case "post":
				r.Method = http.MethodPost
			case "body":
				r.ContentLength = 1
			case "hidden-body":
				r.Body = io.NopCloser(strings.NewReader("x"))
			case "cookie":
				r.Header.Set("Cookie", "fixture")
			case "authorization":
				r.Header.Set("Authorization", "fixture")
			case "noncanonical-credential":
				r.Header["authorization"] = []string{"fixture"}
			case "origin":
				r.Header.Set("Origin", h.origin)
			case "forwarded":
				r.Header.Set("X-Forwarded-For", "127.0.0.1")
			case "query":
				r.URL.RawQuery = "x=1"
			case "force-query":
				r.URL.ForceQuery = true
			case "encoded":
				r.URL.RawPath = strings.Replace(r.URL.Path, "rust", "%72ust", 1)
			case "missing-tls":
				r.TLS = nil
			case "old-tls":
				r.TLS.Version = tls.VersionTLS12
			case "incomplete-tls":
				r.TLS.HandshakeComplete = false
			case "wrong-host":
				r.Host = "wrong.example"
			case "missing-host":
				r.Host = ""
			case "http-test":
				h.insecureHTTPTest = true
				r.TLS = nil
			case "absent":
				h.windowsEnrollment.enrollment = nil
			case "wrong-domain":
				h.windowsEnrollment.enrollmentBootstrap.CollectionProfile = enrollmentcrypto.CollectionProfile
			case "wrong-binding":
				h.windowsEnrollment.enrollmentBootstrap.ManagerInstanceID = "manager_" + strings.Repeat("9", 32)
			case "invalid-bootstrap":
				h.windowsEnrollment.enrollmentBootstrap.IssuerPEM = ""
			case "renewal-policy":
				h.windowsEnrollment.enrollmentBootstrap.RenewalPolicy = enrollmentcrypto.RenewalPolicySameKey
			}
			before, err := service.Snapshots(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			after, err := service.Snapshots(context.Background())
			if err != nil || len(before) != 0 || len(after) != 0 {
				t.Fatal("public request wrote enrollment")
			}
			if kind != "exact" {
				if w.Code < 400 {
					t.Fatal("invalid request accepted", kind, w.Code)
				}
				return
			}
			want, _ := json.Marshal(rustcompat.Expected(original.EnrollmentOrigin, original.AgentOrigin, service.SelfClaimAvailable() && service.SelfClaimPlatform() == "windows"))
			if w.Code != 200 || w.Body.String() != string(want) || w.Body.Len() > 2048 {
				t.Fatal("wrong exact bounded contract", w.Code)
			}
			var fields map[string]any
			if json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 9 {
				t.Fatal("unexpected public fields")
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unsafe public headers")
			}
		})
	}
}

func TestRustBasicCapabilitiesSharesMetadataAdmission(t *testing.T) {
	h, _ := rustBasicFixture(t)
	r := httptest.NewRequest(http.MethodGet, h.origin+rustcompat.Path, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal("public metadata budget bypassed", w.Code)
	}
	other := httptest.NewRequest(http.MethodGet, h.origin+"/v1/windows/setup-capabilities", nil)
	other.RemoteAddr, other.TLS = r.RemoteAddr, r.TLS
	w = httptest.NewRecorder()
	h.ServeHTTP(w, other)
	if w.Code != 429 {
		t.Fatal("compatibility bypassed the cross-endpoint public metadata budget", w.Code)
	}
}

func TestRustBasicCapabilitiesUnavailableOnDevelopment(t *testing.T) {
	if request(setup(t), http.MethodGet, rustcompat.Path, "", nil).Code != 404 {
		t.Fatal("development exposes compatibility")
	}
}

func TestRustBasicCapabilitiesRejectsConfiguredRenewal(t *testing.T) {
	h, service := rustBasicFixture(t, true)
	if !validEnrollmentBootstrap(service, h.windowsEnrollment.enrollmentBootstrap, h.origin, false) {
		t.Fatal("renewal fixture must be genuinely valid")
	}
	r := httptest.NewRequest(http.MethodGet, h.origin+rustcompat.Path, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 || h.bootstrapAdmission.global.count != 0 {
		t.Fatal("renewable enrollment advertised")
	}
}

func TestRustBasicCapabilitiesActualTLSListener(t *testing.T) {
	h, _ := rustBasicFixture(t)
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	r, err := http.NewRequest(http.MethodGet, server.URL+rustcompat.Path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The ephemeral socket stands in for the configured origin; preserve its
	// exact HTTP authority while using the test server's trusted TLS client.
	r.Host = h.authority
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	want, _ := json.Marshal(rustcompat.Expected(h.origin, h.windowsEnrollment.enrollmentBootstrap.AgentOrigin, true))
	if err != nil || response.StatusCode != 200 || string(raw) != string(want) {
		t.Fatal("actual TLS listener contract mismatch", response.StatusCode)
	}
}
