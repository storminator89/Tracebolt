package signedhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	ca       *x509.Certificate
	caKey    ed25519.PrivateKey
	caPEM    []byte
	pair     tls.Certificate
	public   []byte
	registry *lantrust.Registry
	agent    lantrust.Agent
}

func testSerial(t *testing.T) *big.Int {
	t.Helper()
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func makeFixture(t *testing.T, store lantrust.Store) fixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: testSerial(t), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{ca: ca, caKey: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	f.pair, f.public = f.leaf(t, nil, nil)
	if store == nil {
		store = lantrust.NewMemoryStore()
	}
	f.registry, err = lantrust.NewRegistry(context.Background(), f.caPEM, store)
	if err != nil {
		t.Fatal(err)
	}
	f.agent, err = f.registry.Approve(context.Background(), f.public, "Test endpoint")
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f fixture) leaf(t *testing.T, key ed25519.PrivateKey, edit func(*x509.Certificate)) (tls.Certificate, []byte) {
	t.Helper()
	if key == nil {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = generated
	}
	now := time.Now().UTC()
	leaf := &x509.Certificate{SerialNumber: testSerial(t), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: []string{"forged-identity"}}
	if edit != nil {
		edit(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, key.Public(), f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

const testOrigin = "http://127.0.0.1:9001"

var testBody = []byte(`{"id":"claimed-victim","value":42}`)

func verifier(t *testing.T, f fixture) *Verifier {
	t.Helper()
	v, err := New(Config{Origin: testOrigin, Registry: f.registry})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func request(t *testing.T, f fixture) *http.Request {
	t.Helper()
	r, err := NewSignedRequest(context.Background(), testOrigin, f.pair, 1, time.Now().UTC(), testBody)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestSignedRequestUsesApprovedOpaqueIdentity(t *testing.T) {
	f := makeFixture(t, nil)
	v := verifier(t, f)
	r := request(t, f)
	r.Header.Set("X-Agent-ID", "victim")
	got, err := v.Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Agent.ID != f.agent.ID || !bytes.Equal(got.Body, testBody) || got.Sequence != 1 || got.SignedAt.IsZero() {
		t.Fatalf("invalid result: %+v", got)
	}
	if got.Agent.ID == "claimed-victim" || got.Agent.ID == "forged-identity" {
		t.Fatal("untrusted identifier selected identity")
	}
	if got.SignedAt.UTC().Format(time.RFC3339Nano) != r.Header.Get(SignedAtHeader) {
		t.Fatal("signed time precision changed")
	}
}
func TestTranscriptTamperingCannotAuthenticate(t *testing.T) {
	f := makeFixture(t, nil)
	v := verifier(t, f)
	replacement, replacementPEM := f.leaf(t, f.pair.PrivateKey.(ed25519.PrivateKey), nil)
	if _, err := f.registry.Approve(context.Background(), replacementPEM, "Renewed endpoint"); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*http.Request){
		"body": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Replace(string(testBody), "42", "43", 1)))
		},
		"sequence": func(r *http.Request) { r.Header.Set(SequenceHeader, "2") },
		"timestamp": func(r *http.Request) {
			at, _ := time.Parse(time.RFC3339Nano, r.Header.Get(SignedAtHeader))
			r.Header.Set(SignedAtHeader, at.Add(time.Millisecond).UTC().Format(time.RFC3339Nano))
		},
		"leaf same key": func(r *http.Request) {
			r.Header.Set(CertificateHeader, base64.RawStdEncoding.EncodeToString(replacement.Certificate[0]))
		},
		"signature": func(r *http.Request) {
			r.Header.Set(SignatureHeader, base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
		},
		"signature different domain": func(r *http.Request) {
			cert, _ := x509.ParseCertificate(f.pair.Certificate[0])
			msg := transcript(testOrigin, lantrust.Fingerprint(cert), r.Header.Get(SequenceHeader), r.Header.Get(SignedAtHeader), testBody)
			msg = bytes.Replace(msg, []byte("v1"), []byte("v2"), 1)
			r.Header.Set(SignatureHeader, base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.pair.PrivateKey.(ed25519.PrivateKey), msg)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := request(t, f)
			edit(r)
			if _, err := v.Verify(r); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("tampered request error=%v", err)
			}
		})
	}
	other, err := New(Config{Origin: "http://127.0.0.1:9002", Registry: f.registry})
	if err != nil {
		t.Fatal(err)
	}
	r := request(t, f)
	r.Host = "127.0.0.1:9002"
	r.URL.Host = r.Host
	if _, err := other.Verify(r); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("signature reused at another configured origin: %v", err)
	}
}
func TestRequestBoundaryRejectsAmbiguityAndTLSFallback(t *testing.T) {
	f := makeFixture(t, nil)
	v := verifier(t, f)
	for name, edit := range map[string]func(*http.Request){
		"TLS fallback": func(r *http.Request) {
			r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
		},
		"method": func(r *http.Request) { r.Method = "PUT" }, "path": func(r *http.Request) { r.URL.Path = "/v1/agent/other" }, "escaped path": func(r *http.Request) { r.URL.RawPath = "/v1/agent/%74elemetry" },
		"host": func(r *http.Request) { r.Host = "victim.local" }, "URL host": func(r *http.Request) { r.URL.Host = "victim.local" }, "query": func(r *http.Request) { r.URL.RawQuery = "other=1" }, "empty query": func(r *http.Request) { r.URL.ForceQuery = true }, "absolute request target": func(r *http.Request) { r.RequestURI = testOrigin + Path },
		"chunked": func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, "trailer": func(r *http.Request) { r.Trailer = http.Header{"X-Trailer": []string{"value"}} }, "unknown content length": func(r *http.Request) { r.ContentLength = -1 }, "truncated body": func(r *http.Request) { r.ContentLength++ },
		"browser origin": func(r *http.Request) { r.Header.Set("Origin", testOrigin) }, "cookie": func(r *http.Request) { r.Header.Set("Cookie", "session=synthetic") }, "bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") }, "forwarded": func(r *http.Request) { r.Header.Set("Forwarded", "host=other") }, "forwarded cert": func(r *http.Request) { r.Header.Set("X-Forwarded-Client-Cert", "forged") }, "fetch": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }, "encoding": func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"wrong media": func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, "duplicate media": func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, "oversized headers": func(r *http.Request) { r.Header.Set("X-Oversized", strings.Repeat("x", MaxHeaderBytes)) },
	} {
		t.Run(name, func(t *testing.T) {
			r := request(t, f)
			edit(r)
			if _, err := v.Verify(r); !errors.Is(err, ErrRequest) {
				t.Fatalf("boundary request error=%v", err)
			}
		})
	}
	for _, name := range []string{CertificateHeader, SequenceHeader, SignedAtHeader, SignatureHeader} {
		t.Run("duplicate "+name, func(t *testing.T) {
			r := request(t, f)
			r.Header.Add(name, r.Header.Get(name))
			if _, err := v.Verify(r); !errors.Is(err, ErrUnauthorized) {
				t.Fatal(err)
			}
		})
	}
	r := request(t, f)
	r.Header[strings.ToLower(SequenceHeader)] = []string{"1"}
	if _, err := v.Verify(r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("case-folded duplicate accepted")
	}
}
func TestCanonicalSignatureFieldsAndTimeWindow(t *testing.T) {
	f := makeFixture(t, nil)
	v := verifier(t, f)
	for _, seq := range []string{"", "0", "01", "+1", "-1", "1 ", "9223372036854775808", "1,1"} {
		r := request(t, f)
		r.Header.Set(SequenceHeader, seq)
		if _, err := v.Verify(r); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("sequence %q: %v", seq, err)
		}
	}
	for _, at := range []string{"", time.Now().Add(-MaxAge - time.Second).UTC().Format(time.RFC3339Nano), time.Now().Add(ClockSkew + time.Second).UTC().Format(time.RFC3339Nano), time.Now().Format("2006-01-02T15:04:05-07:00"), "2026-10-03T16:00:00.000000000Z"} {
		r := request(t, f)
		r.Header.Set(SignedAtHeader, at)
		if _, err := v.Verify(r); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("time %q: %v", at, err)
		}
	}
	for _, header := range []string{CertificateHeader, SignatureHeader} {
		for _, value := range []string{"!invalid", " ", strings.Repeat("x", MaxCertificateHeaderBytes+1)} {
			r := request(t, f)
			r.Header.Set(header, value)
			if _, err := v.Verify(r); !errors.Is(err, ErrUnauthorized) {
				t.Errorf("field %s %q: %v", header, value[:1], err)
			}
		}
		r := request(t, f)
		r.Header.Set(header, r.Header.Get(header)+"=")
		if _, err := v.Verify(r); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("noncanonical padded base64 accepted")
		}
	}
}
func TestRevocationAndUnapprovedCertificates(t *testing.T) {
	f := makeFixture(t, nil)
	v := verifier(t, f)
	unapproved, _ := f.leaf(t, nil, nil)
	r, err := NewSignedRequest(context.Background(), testOrigin, unapproved, 1, time.Now(), testBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unapproved key accepted")
	}
	foreign := makeFixture(t, nil)
	r = request(t, foreign)
	if _, err = v.Verify(r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign CA accepted")
	}
	if err = f.registry.Revoke(context.Background(), f.agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(request(t, f)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked key accepted: %v", err)
	}
}
func TestExpiredCertificateAndSlowBodyRecheck(t *testing.T) {
	f := makeFixture(t, nil)
	store := lantrust.NewMemoryStore()
	pair, public := f.leaf(t, nil, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) })
	cert, _ := x509.ParseCertificate(pair.Certificate[0])
	a := f.agent
	a.FingerprintSHA256 = lantrust.Fingerprint(cert)
	a.NotBefore = cert.NotBefore
	a.ExpiresAt = cert.NotAfter
	a.ApprovedAt = cert.NotBefore.Add(time.Minute)
	if err := store.Save(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	r, err := lantrust.NewRegistry(context.Background(), f.caPEM, store)
	if err != nil {
		t.Fatal(err)
	}
	expired := f
	expired.registry = r
	expired.pair = pair
	expired.public = public
	if _, err := verifier(t, expired).Verify(request(t, expired)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired key accepted")
	}
	v := verifier(t, f)
	req := request(t, f)
	req.Body = &onRead{Reader: bytes.NewReader(testBody), once: func() {
		if err := f.registry.Revoke(context.Background(), f.agent.ID); err != nil {
			t.Error(err)
		}
	}}
	if _, err = v.Verify(req); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revocation during body read accepted: %v", err)
	}
}

type onRead struct {
	*bytes.Reader
	once func()
}

func (r *onRead) Read(p []byte) (int, error) {
	if r.once != nil {
		f := r.once
		r.once = nil
		f()
	}
	return r.Reader.Read(p)
}
func (r *onRead) Close() error { return nil }
func TestBodyLimitAndSigningHelperIsolation(t *testing.T) {
	f := makeFixture(t, nil)
	v := verifier(t, f)
	r := request(t, f)
	r.ContentLength = MaxBodyBytes + 1
	if _, err := v.Verify(r); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	r = request(t, f)
	r.Body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), MaxBodyBytes+1)))
	if _, err := v.Verify(r); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	body := bytes.Clone(testBody)
	r, err := NewSignedRequest(context.Background(), testOrigin, f.pair, 1, time.Now(), body)
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 'x'
	if _, err = v.Verify(r); err != nil {
		t.Fatal("signer retained caller's mutable body")
	}
	bad := f.pair
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad.PrivateKey = key
	if _, err = NewSignedRequest(context.Background(), testOrigin, bad, 1, time.Now(), testBody); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("mismatched signing key accepted")
	}
}
func TestCanonicalOriginConfiguration(t *testing.T) {
	f := makeFixture(t, nil)
	for _, origin := range []string{"", "https://127.0.0.1:9001", "http://user@127.0.0.1:9001", "http://127.0.0.1:9001/", "http://127.0.0.1:9001?", "http://127.0.0.1:9001#x", "http://UPPER.local", "http://manager.local:80", "http://manager.local:09001", "http://manager.local:", "http://bad..local", "http://[fe80::1%25eth0]", "http://[0:0:0:0:0:0:0:1]"} {
		if _, err := New(Config{Origin: origin, Registry: f.registry}); !errors.Is(err, ErrConfiguration) {
			t.Errorf("origin %q: %v", origin, err)
		}
	}
	for _, origin := range []string{testOrigin, "http://manager.local", "http://[::1]:9001"} {
		if _, err := New(Config{Origin: origin, Registry: f.registry}); err != nil {
			t.Errorf("valid origin %q: %v", origin, err)
		}
	}
}
func TestLoopbackHTTPAndDurableReplayRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.db")
	store, err := lanstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f := makeFixture(t, store)
	var v *Verifier
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := v.Verify(r)
		if err != nil {
			http.Error(w, "denied", 403)
			return
		}
		w.Header().Set("X-Verified-Agent", got.Agent.ID)
		w.WriteHeader(204)
	}))
	defer server.Close()
	v, err = New(Config{Origin: server.URL, Registry: f.registry})
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewSignedRequest(context.Background(), server.URL, f.pair, 1, time.Now(), testBody)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	defer c.CloseIdleConnections()
	response, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 || response.Header.Get("X-Verified-Agent") != f.agent.ID {
		t.Fatal("real HTTP signing boundary failed")
	}
	// Exercise the required atomic commit seam with an entirely synthetic body and
	// model. Application integration independently owns strict frame validation.
	now := time.Now().UTC()
	device := model.Device{LastSeen: now}
	first, err := store.SaveObservation(context.Background(), f.agent, 1, now, device, testBody, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = lanstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	f.registry, err = lantrust.NewRegistry(context.Background(), f.caPEM, store)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier(t, f).Verify(request(t, f))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.SaveObservation(context.Background(), got.Agent, got.Sequence, now, device, got.Body, now.Add(time.Second))
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatal("restart retry refreshed observation age")
	}
	if _, err = store.SaveObservation(context.Background(), got.Agent, 1, now, device, append(got.Body, ' '), now); !errors.Is(err, lanstore.ErrReplay) {
		t.Fatal("same sequence changed body accepted after restart")
	}
	if err = f.registry.Revoke(context.Background(), f.agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SaveObservation(context.Background(), got.Agent, 2, now, device, got.Body, now); !errors.Is(err, lanstore.ErrBinding) {
		t.Fatal("durable revoke did not block previously verified snapshot")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = lanstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	f.registry, err = lantrust.NewRegistry(context.Background(), f.caPEM, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(t, f).Verify(request(t, f)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("restart lost revocation")
	}
}
func TestConcurrentVerificationAndRevocation(t *testing.T) {
	f := makeFixture(t, nil)
	v := verifier(t, f)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, err := v.Verify(request(t, f))
				if err != nil && !errors.Is(err, ErrUnauthorized) {
					t.Error(err)
				}
			}
		}()
	}
	if err := f.registry.Revoke(context.Background(), f.agent.ID); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := v.Verify(request(t, f)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("post-revocation request accepted")
	}
}
