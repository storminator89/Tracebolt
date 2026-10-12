package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsupdatejob"
)

type windowsUpdateJobsFixture struct {
	f                       *fixture
	h                       *Ingress
	manager                 *windowsupdatejob.Manager
	managerKey, executorKey ed25519.PrivateKey
	actor, job              string
	selection               windowsupdatejob.Selection
}

func newWindowsUpdateJobsFixture(t *testing.T) *windowsUpdateJobsFixture {
	t.Helper()
	f := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileWindowsInventory, true)
	return configureWindowsUpdateJobsFixture(t, f)
}

func configureWindowsUpdateJobsFixture(t *testing.T, f *fixture) *windowsUpdateJobsFixture {
	t.Helper()
	x := &windowsUpdateJobsFixture{f: f, actor: id("operator", 51), job: id("update", 51), selection: windowsupdatejob.Selection{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 3}}
	_, x.managerKey = key(t)
	_, x.executorKey = key(t)
	binding := windowsupdatejob.Binding{ManagerID: f.config.Binding.InstanceID, DeviceID: f.snapshot.Approval.DeviceID, IncarnationDigest: "sha256:" + f.cert.CertificateHash(), ExecutorID: id("executor", 51), ExecutorKeyID: actionpermit.Digest(x.executorKey.Public().(ed25519.PublicKey)), GrantID: id("grant", 51), KeyID: actionpermit.Digest(x.managerKey.Public().(ed25519.PublicKey))}
	consent := windowsupdatejob.Consent{Version: windowsupdatejob.ConsentVersion, Scope: windowsupdatejob.Scope, Binding: binding, Enabled: true, Acknowledged: true, ExpiresAt: f.now.Add(time.Hour).Unix()}
	if err := f.store.SetupWindowsUpdateJobsCreateOnly(context.Background(), x.managerKey.Public().(ed25519.PublicKey), x.executorKey.Public().(ed25519.PublicKey), consent, f.now); err != nil {
		t.Fatal(err)
	}
	var err error
	x.manager, err = windowsupdatejob.OpenTransactional(context.Background(), f.store, binding, x.managerKey, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	if err = x.manager.ConfigureOperatorPolicy(func(actor string) bool { return actor == x.actor }); err != nil {
		t.Fatal(err)
	}
	x.h, err = New(f.store, f.issuer.IssuerDER(), f.config.Binding.Origin)
	if err != nil {
		t.Fatal(err)
	}
	x.h.now = func() time.Time { return f.now }
	if err = x.h.ConfigureWindowsUpdateJobs(x.manager); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *windowsUpdateJobsFixture) request(t *testing.T, path string, raw []byte) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, x.h.origin+windowsUpdateJobsPrefix+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	leaf, err := x509.ParseCertificate(x.f.cert.DER())
	if err != nil {
		t.Fatal(err)
	}
	r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, x.h.issuer}}}
	return r
}
func (x *windowsUpdateJobsFixture) serve(t *testing.T, r *http.Request, want int) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	x.h.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("missing private JSON response headers")
	}
	return w.Body.Bytes()
}
func (x *windowsUpdateJobsFixture) claim(t *testing.T, path string, want int) []byte {
	t.Helper()
	raw := []byte(`{"jobId":"` + x.job + `"}`)
	return x.serve(t, x.request(t, path, raw), want)
}
func (x *windowsUpdateJobsFixture) start(t *testing.T) {
	t.Helper()
	if err := x.manager.Request(context.Background(), x.manager.Binding().DeviceID, x.actor, x.job, x.selection); err != nil {
		t.Fatal(err)
	}
}
func (x *windowsUpdateJobsFixture) readiness(t *testing.T, challenge []byte) []byte {
	t.Helper()
	c, err := windowsupdatejob.VerifyChallenge(challenge, x.managerKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	r := windowsupdatejob.Readiness{Selection: x.selection, CapturedAt: x.f.now.Unix(), Software: windowsupdatejob.Yes, Installed: windowsupdatejob.No, Hidden: windowsupdatejob.No, Downloaded: windowsupdatejob.Yes, EULAAccepted: windowsupdatejob.Yes, CanRequestUserInput: windowsupdatejob.No, CanRequireSource: windowsupdatejob.No, RequiresNetwork: windowsupdatejob.No, BundledCount: 0, InstallerBusy: windowsupdatejob.No, RebootRequiredBefore: windowsupdatejob.No, RebootBehavior: "can", OfflineVerified: windowsupdatejob.Yes}
	s := windowsupdatejob.Statement{Version: windowsupdatejob.RelayVersion, Kind: "readiness", Binding: x.manager.Binding(), JobID: x.job, ReferenceDigest: actionpermit.Digest(challenge), Deadline: c.Deadline, IssuedAt: x.f.now.Unix(), ExpiresAt: x.f.now.Unix() + 60, Readiness: &r}
	raw, err := windowsupdatejob.SignStatement(s, x.executorKey)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWindowsUpdateJobsUnsetAndConfiguration(t *testing.T) {
	x := newWindowsUpdateJobsFixture(t)
	if err := x.h.ConfigureWindowsUpdateJobs(x.manager); !errors.Is(err, ErrConfiguration) {
		t.Fatal("duplicate configuration", err)
	}
	h, err := New(x.f.store, x.f.issuer.IssuerDER(), x.h.origin)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.ConfigureWindowsUpdateJobs(nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil manager", err)
	}
	if err = h.ConfigureWindowsUpdateJobs(&windowsupdatejob.Manager{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("fixture manager", err)
	}
	unboundPolicy, err := windowsupdatejob.OpenTransactional(context.Background(), x.f.store, x.manager.Binding(), x.managerKey, func() time.Time { return x.f.now })
	if err != nil {
		t.Fatal(err)
	}
	if err = h.ConfigureWindowsUpdateJobs(unboundPolicy); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing operator policy admitted", err)
	}
	x.h = h
	for _, path := range []string{"poll", "readiness-claim", "install-claim", "retire-claim", "report"} {
		x.serve(t, x.request(t, path, []byte("{}")), 404)
	}
	sameDatabase, err := enrollmentstore.Open(x.f.path, x.f.config, x.f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	defer sameDatabase.Close()
	h, err = New(sameDatabase, x.f.issuer.IssuerDER(), x.h.origin)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.ConfigureWindowsUpdateJobs(x.manager); !errors.Is(err, ErrConfiguration) {
		t.Fatal("different handle for same database admitted", err)
	}
	other := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileWindowsInventory, true)
	h, err = New(other.store, other.issuer.IssuerDER(), other.config.Binding.Origin)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.ConfigureWindowsUpdateJobs(x.manager); !errors.Is(err, ErrConfiguration) {
		t.Fatal("foreign store admitted", err)
	}
	for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileWindowsInventory} {
		f := newCollectionFixture(t, "http-test", collection, true)
		h, err := New(f.store, f.issuer.IssuerDER(), f.config.Binding.Origin)
		if err != nil {
			t.Fatal(err)
		}
		if err = h.ConfigureWindowsUpdateJobs(x.manager); !errors.Is(err, ErrConfiguration) {
			t.Fatal("HTTP configured", err)
		}
		r, _ := http.NewRequest(http.MethodPost, h.origin+windowsUpdateJobsPrefix+"poll", strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("HTTP fallback admitted", w.Code)
		}
	}
}

func TestWindowsUpdateJobsCanonicalShapeAndTLSOnly(t *testing.T) {
	x := newWindowsUpdateJobsFixture(t)
	changes := map[string]func(*http.Request){
		"host":                 func(r *http.Request) { r.Host = "other.test" },
		"query":                func(r *http.Request) { r.URL.RawQuery = "extra=1" },
		"force-query":          func(r *http.Request) { r.URL.ForceQuery = true },
		"raw-path":             func(r *http.Request) { r.URL.RawPath = windowsUpdateJobsPrefix + "%70oll" },
		"absolute-request-uri": func(r *http.Request) { r.RequestURI = r.URL.String() },
		"get":                  func(r *http.Request) { r.Method = http.MethodGet },
		"http-scheme":          func(r *http.Request) { r.URL.Scheme = "http" },
		"encoding":             func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"transfer":             func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		"trailer":              func(r *http.Request) { r.Trailer = http.Header{"X-Extra": []string{"x"}} },
		"type":                 func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") },
		"duplicate-type":       func(r *http.Request) { r.Header["content-type"] = []string{"application/json"} },
		"duplicate-length":     func(r *http.Request) { r.Header["Content-Length"] = []string{"2", "2"} },
		"bad-length":           func(r *http.Request) { r.Header.Set("Content-Length", "02") },
		"short-body":           func(r *http.Request) { r.ContentLength = 1 },
		"unknown-length":       func(r *http.Request) { r.ContentLength = -1 },
		"cookie":               func(r *http.Request) { r.Header["Cookie"] = []string{""} },
		"authorization":        func(r *http.Request) { r.Header.Set("Authorization", "Bearer unused") },
		"signed-http":          func(r *http.Request) { r.Header.Set("X-Tracebolt-Certificate", "unused") },
		"forwarded":            func(r *http.Request) { r.Header.Set("Forwarded", "host=other.test") },
		"browser":              func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) { r := x.request(t, "poll", []byte("{}")); mutate(r); x.serve(t, r, 400) })
	}
	for _, raw := range [][]byte{[]byte("[]"), []byte("{ "), []byte("{}\n")} {
		want := 400
		if len(raw) > 2 {
			want = 413
		}
		x.serve(t, x.request(t, "poll", raw), want)
	}
	for _, raw := range []string{`{"jobId":"` + x.job + `","extra":1}`, `{"jobId":"` + x.job + `","jobId":"` + x.job + `"}`, `{ "jobId":"` + x.job + `"}`, `{"jobId":null}`} {
		x.serve(t, x.request(t, "readiness-claim", []byte(raw)), 400)
	}
	x.serve(t, x.request(t, "unknown", []byte("{}")), 404)
	x.serve(t, x.request(t, "report", bytes.Repeat([]byte("x"), windowsupdatejob.MaxRelayBytes+1)), 413)
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.TLS = nil }, func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }, func(r *http.Request) { r.TLS.VerifiedChains = nil }} {
		r := x.request(t, "poll", []byte("{}"))
		mutate(r)
		x.serve(t, r, 403)
	}
}

func TestWindowsUpdateJobsMetadataClaimsAndExecutorSignatures(t *testing.T) {
	x := newWindowsUpdateJobsFixture(t)
	if got := x.serve(t, x.request(t, "poll", []byte("{}")), 200); !bytes.Equal(got, []byte("null")) {
		t.Fatal("empty poll", string(got))
	}
	x.start(t)
	pending := x.serve(t, x.request(t, "poll", []byte("{}")), 200)
	var meta windowsupdatejob.Pending
	if json.Unmarshal(pending, &meta) != nil || meta.JobID != x.job || meta.Kind != "readiness" || bytes.Contains(pending, []byte("signature")) || bytes.Contains(pending, []byte("challenge")) || bytes.Contains(pending, []byte("selection")) {
		t.Fatal("poll leaked envelope or wrong metadata", string(pending))
	}
	challenge := x.claim(t, "readiness-claim", 200)
	if _, err := windowsupdatejob.VerifyChallenge(challenge, x.managerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if got := x.claim(t, "readiness-claim", 409); bytes.Contains(got, []byte("signature")) {
		t.Fatal("repeat claim leaked envelope")
	}
	report := x.readiness(t, challenge)
	// The observer owns its enrollment key. Even signing the exact statement
	// with that key must not let it invent executor readiness or outcomes.
	var forged struct {
		Statement windowsupdatejob.Statement `json:"statement"`
		Signature string                     `json:"signature"`
	}
	if err := json.Unmarshal(report, &forged); err != nil {
		t.Fatal(err)
	}
	statement, _ := json.Marshal(forged.Statement)
	forged.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(x.f.key, append([]byte("Tracebolt dedicated WUA executor statement v1\x00"), statement...)))
	raw, _ := json.Marshal(forged)
	x.serve(t, x.request(t, "report", raw), 403)
	x.serve(t, x.request(t, "report", statement), 400)
	x.serve(t, x.request(t, "report", append(bytes.Clone(report), '\n')), 400)
	x.serve(t, x.request(t, "report", report), 200)
	view, err := x.manager.View(context.Background(), x.manager.Binding().DeviceID, x.actor)
	if err != nil || view.Job == nil || view.Job.Preview == nil {
		t.Fatal("signed readiness not retained", err)
	}
	if err = x.manager.Approve(context.Background(), x.manager.Binding().DeviceID, x.actor, x.job, view.Job.Preview.Digest, true); err != nil {
		t.Fatal(err)
	}
	pending = x.serve(t, x.request(t, "poll", []byte("{}")), 200)
	if json.Unmarshal(pending, &meta) != nil || meta.Kind != "install" || bytes.Contains(pending, []byte("signature")) {
		t.Fatal("install poll", string(pending))
	}
	permit := x.claim(t, "install-claim", 200)
	if _, err = windowsupdatejob.Verify(permit, x.managerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if got := x.claim(t, "install-claim", 409); bytes.Contains(got, []byte("signature")) {
		t.Fatal("duplicate install envelope")
	}
	result := windowsupdatejob.Result{JobID: x.job, EnvelopeDigest: actionpermit.Digest(permit), Attempted: true, Outcome: "succeeded", OperationResult: 2, RebootRequired: windowsupdatejob.No, CompletedAt: x.f.now.Unix()}
	outcome := windowsupdatejob.Statement{Version: windowsupdatejob.RelayVersion, Kind: "result", Binding: x.manager.Binding(), JobID: x.job, ReferenceDigest: actionpermit.Digest(permit), Deadline: view.Job.Preview.ExpiresAt, IssuedAt: x.f.now.Unix(), ExpiresAt: x.f.now.Unix() + 60, Result: &result}
	report, err = windowsupdatejob.SignStatement(outcome, x.executorKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(report, &forged); err != nil {
		t.Fatal(err)
	}
	statement, _ = json.Marshal(forged.Statement)
	forged.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(x.f.key, append([]byte("Tracebolt dedicated WUA executor statement v1\x00"), statement...)))
	raw, _ = json.Marshal(forged)
	x.serve(t, x.request(t, "report", raw), 403)
	x.serve(t, x.request(t, "report", report), 200)
	x.serve(t, x.request(t, "report", report), 200)
	view, err = x.manager.View(context.Background(), x.manager.Binding().DeviceID, x.actor)
	if err != nil || view.Job == nil || view.Job.State != "complete" || view.Job.Result == nil || *view.Job.Result != result {
		t.Fatal("signed result not retained", err)
	}
}

type windowsUpdateJobsBody struct {
	io.ReadCloser
	before func()
}

func (b *windowsUpdateJobsBody) Read(p []byte) (int, error) {
	if b.before != nil {
		f := b.before
		b.before = nil
		f()
	}
	return b.ReadCloser.Read(p)
}

func TestWindowsUpdateJobsBodyAndCertificateAdmissionBoundaries(t *testing.T) {
	for _, change := range []string{"revoked", "expired"} {
		t.Run(change, func(t *testing.T) {
			x := newWindowsUpdateJobsFixture(t)
			x.start(t)
			r := x.request(t, "readiness-claim", []byte(`{"jobId":"`+x.job+`"}`))
			r.Body = &windowsUpdateJobsBody{ReadCloser: r.Body, before: func() {
				if change == "revoked" {
					x.f.revoke(t)
				} else {
					x.h.now = func() time.Time { return time.Unix(x.f.snapshot.Intent.NotAfter, 0) }
				}
			}}
			got := x.serve(t, r, 403)
			if bytes.Contains(got, []byte("signature")) {
				t.Fatal("post-body rejection leaked challenge")
			}
		})
	}
	x := newWindowsUpdateJobsFixture(t)
	release, ok := x.h.admitCertificate(x.f.cert.DER())
	if !ok {
		t.Fatal("admission fixture")
	}
	defer release()
	x.serve(t, x.request(t, "poll", []byte("{}")), 429)
}

func TestWindowsUpdateJobsFinalExpiryDoesNotRestoreClaim(t *testing.T) {
	calls := 0
	x := newWindowsUpdateJobsFixture(t)
	x.start(t)
	x.h.now = func() time.Time { calls++; return x.f.now }
	x.claim(t, "readiness-claim", 200)
	finalCall := calls
	if finalCall < 4 {
		t.Fatal("final checks not observed", finalCall)
	}
	x = newWindowsUpdateJobsFixture(t)
	x.start(t)
	calls = 0
	x.h.now = func() time.Time {
		calls++
		if calls == finalCall {
			return time.Unix(x.f.snapshot.Intent.NotAfter, 0)
		}
		return x.f.now
	}
	got := x.claim(t, "readiness-claim", 403)
	if bytes.Contains(got, []byte("signature")) {
		t.Fatal("expired final response leaked challenge")
	}
	x.h.now = func() time.Time { return x.f.now }
	x.claim(t, "readiness-claim", 409)
}

func TestWindowsUpdateJobsForeignEnrolledObserver(t *testing.T) {
	x := newWindowsUpdateJobsFixture(t)
	x.start(t)
	foreign := enrollWindowsUpdateJobObserver(t, x.f, 72)
	original := x.f
	x.f = foreign
	for _, path := range []string{"poll", "readiness-claim", "install-claim", "retire-claim", "report"} {
		raw := []byte("{}")
		if strings.HasSuffix(path, "-claim") {
			raw = []byte(`{"jobId":"` + x.job + `"}`)
		}
		r := x.request(t, path, raw)
		read := false
		r.Body = &windowsUpdateJobsBody{ReadCloser: r.Body, before: func() { read = true }}
		x.serve(t, r, 403)
		if read {
			t.Fatal("foreign observer reached request body", path)
		}
	}
	x.f = original
	x.claim(t, "readiness-claim", 200)
}

func TestWindowsUpdateJobsCurrentAndRetiredLeaf(t *testing.T) {
	f := newWindowsUpdateJobRenewableObserver(t)
	x := configureWindowsUpdateJobsFixture(t, f)
	x.start(t)
	anchor := f.cert
	candidate := prepareWindowsUpdateJobRenewal(t, f)
	// The signed but unactivated successor has no relay authority.
	f.cert = candidate
	x.serve(t, x.request(t, "poll", []byte("{}")), 403)
	f.cert = anchor
	r := x.request(t, "readiness-claim", []byte(`{"jobId":"`+x.job+`"}`))
	// Activate the successor after ingress authenticated the old leaf but
	// before its claim transaction. The actual transport leaf must survive
	// as independent context rather than being replaced by the stable anchor.
	r.Body = &windowsUpdateJobsBody{ReadCloser: r.Body, before: func() {
		proof := windowsUpdateJobRenewalProof(t, f, candidate.CertificateHash(), enrollmentcrypto.PurposeRenewalActivate, 802)
		if _, err := f.store.ActivateRenewal(context.Background(), proof, func() time.Time { return f.now }); err != nil {
			t.Fatal(err)
		}
	}}
	if got := x.serve(t, r, 403); bytes.Contains(got, []byte("signature")) {
		t.Fatal("retired in-flight leaf leaked challenge")
	}
	x.serve(t, x.request(t, "poll", []byte("{}")), 403)
	f.cert = candidate
	challenge := x.claim(t, "readiness-claim", 200)
	c, err := windowsupdatejob.VerifyChallenge(challenge, x.managerKey.Public().(ed25519.PublicKey))
	if err != nil || c.Binding.IncarnationDigest != "sha256:"+anchor.CertificateHash() {
		t.Fatal("renewal changed stable binding", err)
	}
	x.claim(t, "readiness-claim", 409)
}

func TestWindowsUpdateJobsExpiredClaimWithholdsEnvelope(t *testing.T) {
	x := newWindowsUpdateJobsFixture(t)
	x.start(t)
	x.f.now = x.f.now.Add(2 * time.Minute)
	if got := x.claim(t, "readiness-claim", 409); bytes.Contains(got, []byte("signature")) {
		t.Fatal("expired claim leaked challenge")
	}
	for _, err := range []error{windowsupdatejob.ErrUncertain, windowsupdatejob.ErrIntegrity} {
		w := httptest.NewRecorder()
		windowsUpdateJobFailure(w, err)
		if w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte("signature")) {
			t.Fatal("unsafe persistence failure response", w.Code)
		}
	}
}

func TestWindowsUpdateRetirementClaimFramingAndLegacyDenial(t *testing.T) {
	x := newWindowsUpdateJobsFixture(t)
	body := []byte(`{"jobId":"` + x.job + `"}`)
	r := x.request(t, "retire-claim", body)
	if windowsUpdateJobBodyLimit(r.URL.Path) != 128 || !validWindowsUpdateJobRequest(r, x.h.authority) {
		t.Fatal("retirement route has wrong framing")
	}
	x.serve(t, r, http.StatusForbidden)
	r = x.request(t, "retire-claim", []byte(`{"jobId":"`+x.job+`","install":true}`))
	x.serve(t, r, http.StatusBadRequest)
}
