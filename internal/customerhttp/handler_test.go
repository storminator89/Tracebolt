package customerhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
)

type fixtureService struct {
	pool       *customerchallenge.Pool
	now        time.Time
	context    customerclaim.Context
	peer       string
	guardErr   error
	issueErr   error
	admitCalls int
	issueCalls int
	forceZero  bool
	editRecord func(*customerpending.Record)
	admitErr   error
}

func (f *fixtureService) WithClaimChallenge(_ context.Context, peer, customer, profile, claim string, emit func(customerclaim.Context, func() error) error) error {
	f.peer = peer
	f.issueCalls++
	if f.issueErr != nil {
		return f.issueErr
	}
	c, e := f.pool.Issue(peer, customer, profile, claim)
	if e != nil {
		return e
	}
	f.context = c
	return emit(c, func() error { return f.guardErr })
}
func (f *fixtureService) Admit(_ context.Context, nonce string, raw []byte) (customerpending.Record, error) {
	f.admitCalls++
	if f.forceZero {
		return customerpending.Record{}, nil
	}
	c, e := f.pool.Take(nonce)
	if e != nil {
		return customerpending.Record{}, e
	}
	v, e := customerclaim.Verify(raw, c, f.now)
	if e != nil {
		return customerpending.Record{}, e
	}
	m := v.Metadata()
	record := customerpending.Record{Version: "tracebolt.customer-pending.v1", ManagerID: m.ManagerID, CustomerID: m.CustomerID, InstallerProfileID: m.InstallerProfileID, Origin: m.Origin, AgentOrigin: m.AgentOrigin, IssuerFingerprint: m.IssuerFingerprint, ClaimID: m.ClaimID, RequestID: m.RequestID, KeyFingerprint: m.KeyFingerprint, CSRHash: m.CSRHash, ClaimHash: m.ClaimHash, ComparisonCode: m.ComparisonCode, PublicKeyDER: v.PublicKeyDER(), CreatedAt: f.now.Unix(), DeadlineAt: f.now.Add(customerpending.PendingLifetime).Unix()}
	if f.editRecord != nil {
		f.editRecord(&record)
	}
	return record, f.admitErr
}
func fixture(t *testing.T) (*Handler, *fixtureService, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	binding := customerchallenge.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), Origin: "https://manager.example.test:8443", AgentOrigin: "https://agent.example.test:8444", IssuerFingerprint: strings.Repeat("a", 64)}
	pool, e := customerchallenge.New(binding, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	f := &fixtureService{pool: pool, now: now}
	h, e := New(binding.ManagerID, binding.Origin, binding.AgentOrigin, binding.IssuerFingerprint, f, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	return h, f, now
}
func request(path string, raw []byte) *http.Request {
	r := httptest.NewRequest("POST", "https://manager.example.test:8443"+path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	return r
}
func input() []byte {
	b, _ := json.Marshal(challengeInput{"customer_" + strings.Repeat("2", 32), "profile_" + strings.Repeat("3", 32), "claim_" + strings.Repeat("4", 32)})
	return b
}

func TestChallengeAndClaimFlowIsPendingOnly(t *testing.T) {
	h, f, now := fixture(t)
	r := request(prefix+"challenge", input())
	r.RemoteAddr = "[::ffff:192.0.2.3]:9123"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || f.peer != "192.0.2.3" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("challenge rejected", w.Code)
	}
	var wire struct {
		SchemaVersion string           `json:"schemaVersion"`
		Context       challengeContext `json:"context"`
	}
	if json.Unmarshal(w.Body.Bytes(), &wire) != nil || wire.SchemaVersion != "tracebolt.customer-windows-challenge.v1" || wire.Context.Challenge != f.context.Challenge || wire.Context.CustomerID != f.context.CustomerID {
		t.Fatal("challenge response mismatch")
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal(e)
	}
	requestID := "request_" + strings.Repeat("5", 32)
	message, e := customerclaim.SigningMessage(f.context, requestID, csr, now)
	if e != nil {
		t.Fatal(e)
	}
	body, e := customerclaim.Encode(f.context, requestID, csr, ed25519.Sign(key, message), now)
	if e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(prefix+"claim", body))
	want := `{"state":"pending","deadlineAt":` + strconv.FormatInt(now.Add(customerpending.PendingLifetime).Unix(), 10) + `}`
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != want {
		t.Fatal("claim was not pending", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(prefix+"claim", body))
	if w.Code != 401 || strings.Contains(w.Body.String(), "deadlineAt") || strings.Contains(w.Body.String(), "pending") {
		t.Fatal("replayed challenge accepted", w.Code)
	}
}

func TestListenerRejectsAmbiguousOrUntrustedRequests(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"http":                                func(r *http.Request) { r.TLS = nil },
		"unfinished":                          func(r *http.Request) { r.TLS.HandshakeComplete = false },
		"old TLS":                             func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 },
		"wrong host":                          func(r *http.Request) { r.Host = "other.example.test" },
		"method":                              func(r *http.Request) { r.Method = "GET" },
		"query":                               func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"encoded path":                        func(r *http.Request) { r.URL.RawPath = "/v3/customer-enrollment/%63hallenge" },
		"transfer encoding":                   func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		"unknown length":                      func(r *http.Request) { r.ContentLength = -1 },
		"bad length":                          func(r *http.Request) { r.ContentLength++ },
		"content type":                        func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"duplicate content type":              func(r *http.Request) { r.Header.Add("Content-Type", "application/json") },
		"noncanonical duplicate content type": func(r *http.Request) { r.Header["content-type"] = []string{"application/json"} },
		"cookie":                              func(r *http.Request) { r.Header.Set("Cookie", "x=y") },
		"origin":                              func(r *http.Request) { r.Header.Set("Origin", "https://manager.example.test:8443") },
		"authorization":                       func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") },
		"forwarded":                           func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") },
		"encoding":                            func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"bad peer":                            func(r *http.Request) { r.RemoteAddr = "example.test:443" },
		"status path":                         func(r *http.Request) { r.URL.Path = prefix + "status" },
	} {
		t.Run(name, func(t *testing.T) {
			h, f, _ := fixture(t)
			r := request(prefix+"challenge", input())
			change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == 200 || f.peer != "" || f.admitCalls != 0 {
				t.Fatal("request reached service", w.Code)
			}
		})
	}
}

func TestChallengeInputIsStrictAndErrorsAreUniform(t *testing.T) {
	cases := [][]byte{[]byte(`{"customerId":"x","customerId":"y","installerProfileId":"z","claimId":"q"}`), []byte(`{"customerId":null,"installerProfileId":"z","claimId":"q"}`), append(bytes.Clone(input())[:len(input())-1], []byte(`,"extra":"x"}`)...), append(bytes.Clone(input()), []byte(` {}`)...)}
	for _, raw := range cases {
		h, f, _ := fixture(t)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(prefix+"challenge", raw))
		if w.Code != 400 || f.peer != "" {
			t.Fatal("invalid input accepted")
		}
	}
	for _, e := range []error{errors.New("unknown customer"), errors.New("retired profile"), errors.New("storage unavailable")} {
		h, f, _ := fixture(t)
		f.issueErr = e
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(prefix+"challenge", input()))
		if w.Code != 503 || strings.TrimSpace(w.Body.String()) != `{"error":"request_unavailable"}` {
			t.Fatal("backend error disclosed", w.Code)
		}
	}
	h, f, _ := fixture(t)
	f.guardErr = errors.New("authority expired")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(prefix+"challenge", input()))
	if w.Code != 503 {
		t.Fatal("authority failure not rejected", w.Code)
	}
}

func TestClaimCannotConfirmMissingCommittedRecord(t *testing.T) {
	h, f, _ := fixture(t)
	f.forceZero = true
	body := []byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","customerId":"customer_22222222222222222222222222222222","installerProfileId":"profile_33333333333333333333333333333333","claimId":"claim_44444444444444444444444444444444"}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(prefix+"claim", body))
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "deadlineAt") || strings.Contains(w.Body.String(), "pending") {
		t.Fatal("missing pending record acknowledged", w.Code)
	}
}

func TestClaimNeverReturnsDeadlineForInvalidOrUnconfirmedRecord(t *testing.T) {
	for name, change := range map[string]func(*fixtureService){
		"missing deadline": func(f *fixtureService) {
			f.editRecord = func(r *customerpending.Record) { r.DeadlineAt = 0 }
		},
		"extended deadline": func(f *fixtureService) {
			f.editRecord = func(r *customerpending.Record) { r.DeadlineAt++ }
		},
		"expired": func(f *fixtureService) {
			f.editRecord = func(r *customerpending.Record) {
				r.DeadlineAt = f.now.Unix()
				r.CreatedAt = r.DeadlineAt - int64(customerpending.PendingLifetime/time.Second)
			}
		},
		"future creation": func(f *fixtureService) {
			f.editRecord = func(r *customerpending.Record) {
				r.CreatedAt++
				r.DeadlineAt++
			}
		},
		"wrong claim": func(f *fixtureService) {
			f.editRecord = func(r *customerpending.Record) { r.ClaimID = "claim_" + strings.Repeat("a", 32) }
		},
		"invalid key": func(f *fixtureService) {
			f.editRecord = func(r *customerpending.Record) { r.PublicKeyDER = nil }
		},
		"unconfirmed commit": func(f *fixtureService) { f.admitErr = errors.New("commit outcome unknown") },
	} {
		t.Run(name, func(t *testing.T) {
			h, f, now := fixture(t)
			change(f)
			challenge := httptest.NewRecorder()
			h.ServeHTTP(challenge, request(prefix+"challenge", input()))
			if challenge.Code != http.StatusOK {
				t.Fatal("challenge failed", challenge.Code)
			}
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				t.Fatal(err)
			}
			id := "request_" + strings.Repeat("5", 32)
			message, err := customerclaim.SigningMessage(f.context, id, csr, now)
			if err != nil {
				t.Fatal(err)
			}
			body, err := customerclaim.Encode(f.context, id, csr, ed25519.Sign(key, message), now)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(prefix+"claim", body))
			if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"error":"request_unavailable"}` {
				t.Fatal("invalid or unconfirmed record acknowledged", w.Code, w.Body.String())
			}
		})
	}
}

func TestClaimRetryReturnsOriginalPersistedDeadline(t *testing.T) {
	h, f, originalNow := fixture(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	var persisted customerpending.Record
	f.editRecord = func(r *customerpending.Record) {
		if persisted.Version == "" {
			persisted = *r
		} else {
			// Fixture models the admission store returning its immutable record
			// after a fresh, verified challenge for the same original claim.
			*r = persisted
		}
	}
	claim := func(now time.Time) *httptest.ResponseRecorder {
		t.Helper()
		challenge := httptest.NewRecorder()
		h.ServeHTTP(challenge, request(prefix+"challenge", input()))
		if challenge.Code != http.StatusOK {
			t.Fatal("challenge failed", challenge.Code)
		}
		id := "request_" + strings.Repeat("5", 32)
		message, e := customerclaim.SigningMessage(f.context, id, csr, now)
		if e != nil {
			t.Fatal(e)
		}
		body, e := customerclaim.Encode(f.context, id, csr, ed25519.Sign(key, message), now)
		if e != nil {
			t.Fatal(e)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(prefix+"claim", body))
		return w
	}
	first := claim(originalNow)
	later := originalNow.Add(5 * time.Second)
	f.now = later
	h.clock = func() time.Time { return later }
	second := claim(later)
	want := `{"state":"pending","deadlineAt":` + strconv.FormatInt(originalNow.Add(customerpending.PendingLifetime).Unix(), 10) + `}`
	if first.Code != http.StatusOK || second.Code != http.StatusOK || strings.TrimSpace(first.Body.String()) != want || strings.TrimSpace(second.Body.String()) != want {
		t.Fatal("retry changed original deadline", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
}

type blockingService struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (s *blockingService) WithClaimChallenge(_ context.Context, _, _, _, _ string, _ func(customerclaim.Context, func() error) error) error {
	s.calls.Add(1)
	s.entered <- struct{}{}
	<-s.release
	return errors.New("fixture rejected")
}
func (s *blockingService) Admit(context.Context, string, []byte) (customerpending.Record, error) {
	return customerpending.Record{}, errors.New("unused")
}

func TestConcurrentUnauthenticatedWorkIsBoundedBeforeService(t *testing.T) {
	_, _, now := fixture(t)
	s := &blockingService{entered: make(chan struct{}, maxWork), release: make(chan struct{})}
	h, e := New("manager_"+strings.Repeat("1", 32), "https://manager.example.test:8443", "https://agent.example.test:8444", strings.Repeat("a", 64), s, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < maxWork; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.ServeHTTP(httptest.NewRecorder(), request(prefix+"challenge", input())) }()
	}
	for i := 0; i < maxWork; i++ {
		select {
		case <-s.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("workers did not reach service")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(prefix+"challenge", input()))
	if w.Code != http.StatusTooManyRequests || s.calls.Load() != maxWork {
		t.Fatal("concurrency cap missed", w.Code, s.calls.Load())
	}
	close(s.release)
	wg.Wait()
}

func TestPeerQuotaRunsBeforeAuthorityLookup(t *testing.T) {
	h, f, _ := fixture(t)
	f.issueErr = errors.New("fixture unavailable")
	for i := 0; i < maxPeerPerMinute; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(prefix+"challenge", input()))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatal("unexpected earlier rejection", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(prefix+"challenge", input()))
	if w.Code != http.StatusTooManyRequests || f.issueCalls != maxPeerPerMinute {
		t.Fatal("rate limit did not precede lookup", w.Code, f.issueCalls)
	}
}
