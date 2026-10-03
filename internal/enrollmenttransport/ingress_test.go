package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/signedhttp"
)

func TestRealIngressActivatedIdentityReplayReusedConnectionRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, false)
			_, s, client := f.listen(t, nil)
			at := time.Now().UTC()
			raw := frame(t, 1, at)
			response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusForbidden)
			f.activate(t)
			var receipt lanstore.Receipt
			if err := json.Unmarshal(response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusOK), &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.AgentID != f.snapshot.Approval.DeviceID || receipt.Duplicate {
				t.Fatal("identity not derived from durable approval")
			}
			reused := false
			r := f.request(t, s.URL, 1, at, raw)
			r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
			var retry lanstore.Receipt
			if err := json.Unmarshal(response(t, client, r, http.StatusOK), &retry); err != nil {
				t.Fatal(err)
			}
			if !reused || !retry.Duplicate || !retry.ReceivedAt.Equal(receipt.ReceivedAt) {
				t.Fatal("keep-alive retry changed receipt")
			}
			rows, err := f.store.LatestObservations(context.Background())
			if err != nil || len(rows) != 1 || rows[0].Device.ID != receipt.AgentID {
				t.Fatal("stored observation identity mismatch", err)
			}
			f.revoke(t)
			reused = false
			r = f.request(t, s.URL, 1, at, raw)
			r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
			response(t, client, r, http.StatusForbidden)
			if !reused {
				t.Fatal("did not exercise revocation on reused connection")
			}
		})
	}
}

func TestTLSExactStaleRetryAndRestartPreserveOriginalReceipt(t *testing.T) {
	f := newFixture(t, "tls", true)
	h, s, client := f.listen(t, nil)
	at := time.Now().UTC()
	raw := frame(t, 1, at)
	var first lanstore.Receipt
	json.Unmarshal(response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusOK), &first)
	f.store.Close()
	var err error
	f.store, err = enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	h.store = f.store
	h.now = func() time.Time { return at.Add(3 * time.Minute) }
	var retry lanstore.Receipt
	json.Unmarshal(response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusOK), &retry)
	if !retry.Duplicate || !retry.ReceivedAt.Equal(first.ReceivedAt) || !retry.CollectedAt.Equal(first.CollectedAt) {
		t.Fatal("exact old retry refreshed freshness")
	}
	response(t, client, f.request(t, s.URL, 2, at, frame(t, 2, at)), http.StatusConflict)
	response(t, client, f.request(t, s.URL, 1, at.Add(3*time.Minute), frame(t, 1, at.Add(3*time.Minute))), http.StatusConflict)
}

func TestUnavailableStoreReturns503OnEveryProfile(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			_, s, client := f.listen(t, nil)
			at := time.Now().UTC()
			raw := frame(t, 1, at)
			response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusOK)
			f.store.Close()
			body := response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusServiceUnavailable)
			if !bytes.Contains(body, []byte("storage_unavailable")) || bytes.Contains(body, []byte("sqlite")) {
				t.Fatal("storage failure exposed details or looked like revocation")
			}
		})
	}
}

func TestTLSConfigAcceptsOnlyDedicatedIssuerAndNormalServerVerification(t *testing.T) {
	f := newFixture(t, "tls", true)
	var requests atomic.Int32
	h, s, client := f.listen(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); next.ServeHTTP(w, r) })
	})
	cfg, err := h.TLSConfig(f.server)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert || !cfg.SessionTicketsDisabled || cfg.InsecureSkipVerify {
		t.Fatal("TLS verification policy weakened")
	}
	subjects := cfg.ClientCAs.Subjects()
	issuer, _ := x509.ParseCertificate(f.issuer.IssuerDER())
	if len(subjects) != 1 || !bytes.Equal(subjects[0], issuer.RawSubject) {
		t.Fatal("trusted something beyond dedicated issuer")
	}
	at := time.Now().UTC()
	raw := frame(t, 1, at)
	response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusOK)
	sp, sk := key(t)
	sibling := makeCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "Ephemeral sibling issuer"}, NotBefore: f.root.NotBefore, NotAfter: f.root.NotAfter, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, f.root, sp, f.rootKey)
	lp, lk := key(t)
	leaf := makeCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "Ordinary sibling client"}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, sibling, lp, sk)
	pair := tls.Certificate{Certificate: [][]byte{leaf.Raw, sibling.Raw}, PrivateKey: lk}
	base := client.Transport.(*http.Transport)
	for _, scenario := range []string{"sibling", "wrong-server-name", "no-client", "tls12"} {
		t.Run(scenario, func(t *testing.T) {
			transport := base.Clone()
			transport.TLSClientConfig = base.TLSClientConfig.Clone()
			defer transport.CloseIdleConnections()
			switch scenario {
			case "sibling":
				transport.TLSClientConfig.Certificates = nil
				transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }
			case "wrong-server-name":
				transport.TLSClientConfig.ServerName = "not-the-server.test"
			case "no-client":
				transport.TLSClientConfig.Certificates = nil
			case "tls12":
				transport.TLSClientConfig.MinVersion = tls.VersionTLS12
				transport.TLSClientConfig.MaxVersion = tls.VersionTLS12
			}
			badClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			before := requests.Load()
			res, err := badClient.Do(f.request(t, s.URL, 1, at, raw))
			if res != nil {
				res.Body.Close()
			}
			if err == nil || requests.Load() != before {
				t.Fatal("invalid TLS reached HTTP ingress")
			}
		})
	}
}

func TestRequestContractGuards(t *testing.T) {
	f := newFixture(t, "tls", true)
	h, _, _ := f.listen(t, nil)
	at := time.Now().UTC()
	raw := frame(t, 1, at)
	cases := map[string]func(*http.Request){
		"host":             func(r *http.Request) { r.Host = "elsewhere.test" },
		"query":            func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force-query":      func(r *http.Request) { r.URL.ForceQuery = true },
		"escaped-path":     func(r *http.Request) { r.URL.RawPath = "/v1/agent/%74elemetry" },
		"path":             func(r *http.Request) { r.URL.Path = "/v2/agent/telemetry" },
		"method":           func(r *http.Request) { r.Method = "GET" },
		"absolute-uri":     func(r *http.Request) { r.RequestURI = h.origin + signedhttp.Path },
		"transfer":         func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		"transfer-header":  func(r *http.Request) { r.Header["Transfer-Encoding"] = []string{"chunked"} },
		"trailer":          func(r *http.Request) { r.Trailer = http.Header{"X-Trailer": []string{"x"}} },
		"cookie-empty":     func(r *http.Request) { r.Header["Cookie"] = []string{""} },
		"origin-empty":     func(r *http.Request) { r.Header["Origin"] = []string{""} },
		"bearer":           func(r *http.Request) { r.Header.Set("Authorization", "Bearer rejected") },
		"forwarded":        func(r *http.Request) { r.Header.Set("Forwarded", "host=elsewhere.test") },
		"x-forwarded":      func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "elsewhere.test") },
		"encoding":         func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"browser":          func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") },
		"ambiguous-type":   func(r *http.Request) { r.Header["content-type"] = []string{"application/json"} },
		"type":             func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"duplicate-length": func(r *http.Request) { r.Header["Content-Length"] = []string{"1", "1"} },
		"bad-length":       func(r *http.Request) { r.Header.Set("Content-Length", "01") },
		"unknown-length":   func(r *http.Request) { r.ContentLength = -1 },
		"signed-on-tls":    func(r *http.Request) { r.Header.Set(signedhttp.CertificateHeader, "unused") },
		"large-headers":    func(r *http.Request) { r.Header.Set("X-Test", strings.Repeat("x", signedhttp.MaxHeaderBytes)) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := f.request(t, h.origin, 1, at, raw)
			change(r)
			if validRequest(r, h.authority, "tls") {
				t.Fatal("invalid contract accepted")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
}

func TestRealHTTPGuardsAndSignatureMetadata(t *testing.T) {
	f := newFixture(t, "http-test", true)
	_, s, client := f.listen(t, nil)
	at := time.Now().UTC()
	raw := frame(t, 1, at)
	for _, header := range []string{"Cookie", "Origin", "Authorization", "Forwarded", "X-Forwarded-Host", "Content-Encoding"} {
		t.Run(header, func(t *testing.T) {
			r := f.request(t, s.URL, 1, at, raw)
			r.Header.Set(header, "rejected")
			response(t, client, r, http.StatusBadRequest)
		})
	}
	r := f.request(t, s.URL, 1, at, raw)
	r.Header.Del(signedhttp.SignatureHeader)
	response(t, client, r, http.StatusForbidden)
	r = f.request(t, s.URL, 2, at, raw)
	response(t, client, r, http.StatusBadRequest)
	r = f.request(t, s.URL, 1, at, raw)
	r.URL.Path = "/v2/agent/telemetry"
	response(t, client, r, http.StatusBadRequest)
	r = f.request(t, s.URL, 1, at, raw)
	r.ContentLength = -1
	response(t, client, r, http.StatusBadRequest)
	r = f.request(t, s.URL, 1, at, raw)
	r.ContentLength = lanstore.MaxFrameBytes + 1
	r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", lanstore.MaxFrameBytes+1)))
	response(t, client, r, http.StatusRequestEntityTooLarge)
	rows, err := f.store.LatestObservations(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatal("rejected frame committed", err)
	}
}

type gatedBody struct {
	io.ReadCloser
	once    sync.Once
	entered chan<- struct{}
	release <-chan struct{}
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { b.entered <- struct{}{}; <-b.release })
	return b.ReadCloser.Read(p)
}
func TestSlowBodyCannotOutrunRevocationAndAdmissionIsBounded(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			entered := make(chan struct{}, MaxInFlight)
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			_, s, client := f.listen(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.Body = &gatedBody{ReadCloser: r.Body, entered: entered, release: release}
					next.ServeHTTP(w, r)
				})
			})
			at := time.Now().UTC()
			raw := frame(t, 1, at)
			statuses := make(chan int, MaxInFlight)
			for n := 0; n < MaxInFlight; n++ {
				r := f.request(t, s.URL, 1, at, raw)
				go func() {
					res, err := client.Do(r)
					if err != nil {
						statuses <- 0
						return
					}
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
					statuses <- res.StatusCode
				}()
			}
			for n := 0; n < MaxInFlight; n++ {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("request did not reach body after authorization")
				}
			}
			response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusTooManyRequests)
			f.revoke(t)
			releaseOnce.Do(func() { close(release) })
			for n := 0; n < MaxInFlight; n++ {
				select {
				case status := <-statuses:
					if status != http.StatusForbidden {
						t.Fatalf("slow revoked request returned %d", status)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("request stuck")
				}
			}
			rows, err := f.store.LatestObservations(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatal("slow revoked request committed", err)
			}
		})
	}
}

func TestZeroConfigurationAndPlaintextTLSSeparation(t *testing.T) {
	for _, h := range []*Ingress{nil, {}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatal("zero handler authorized")
		}
		if _, err := h.TLSConfig(tls.Certificate{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal(err)
		}
	}
	f := newFixture(t, "http-test", true)
	for _, origin := range []string{"https://agent.test", "http://agent.test:80", "http://AGENT.test", "http://agent.test/", "http://agent.test?", "http://user@agent.test", "http://[::1%25eth0]", "http://agent.test:080", "http://agent.test:"} {
		if _, err := New(f.store, f.issuer.IssuerDER(), origin); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid origin accepted", origin)
		}
	}
	if _, err := New(nil, f.issuer.IssuerDER(), "http://agent.test"); !errors.Is(err, ErrConfiguration) {
		t.Fatal(err)
	}
	if _, err := New(&enrollmentstore.Store{}, f.issuer.IssuerDER(), "http://agent.test"); !errors.Is(err, ErrConfiguration) {
		t.Fatal(err)
	}
	if _, err := New(f.store, f.root.Raw, "http://agent.test"); !errors.Is(err, ErrConfiguration) {
		t.Fatal("offline root accepted")
	}
	h, err := New(f.store, f.issuer.IssuerDER(), "http://agent.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.TLSConfig(f.server); !errors.Is(err, ErrConfiguration) {
		t.Fatal("http-test created TLS config")
	}
	r := f.request(t, h.origin, 1, f.now, frame(t, 1, f.now))
	r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("HTTP proof used as TLS fallback")
	}
	for _, a := range []*publicAuthorizer{nil, {}} {
		if _, err := a.AuthorizePublicCertificate(nil); !errors.Is(err, lantrust.ErrRegistryUnavailable) {
			t.Fatal("zero authorizer did not fail closed")
		}
	}
	a := &publicAuthorizer{store: f.store, ctx: context.Background(), now: time.Now}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cert.DER()})
	for _, raw := range [][]byte{append([]byte("prefix"), pemBytes...), append(bytes.Clone(pemBytes), pemBytes...), append(bytes.Clone(pemBytes), ' ')} {
		if _, err := a.AuthorizePublicCertificate(raw); !errors.Is(err, lantrust.ErrUnauthorized) {
			t.Fatal("noncanonical public certificate accepted")
		}
	}
}

func TestReusedConnectionRechecksCertificateExpiry(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			h, s, client := f.listen(t, nil)
			at := time.Now().UTC()
			raw := frame(t, 1, at)
			response(t, client, f.request(t, s.URL, 1, at, raw), http.StatusOK)
			h.now = func() time.Time { return time.Unix(f.snapshot.Intent.NotAfter, 0) }
			reused := false
			r := f.request(t, s.URL, 1, at, raw)
			r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
			response(t, client, r, http.StatusForbidden)
			if !reused {
				t.Fatal("did not exercise expiry on reused connection")
			}
		})
	}
}
