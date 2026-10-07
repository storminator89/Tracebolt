package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/model"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompleteOverviewOperatorGuardsAndNotConfigured(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	id := "agent_" + strings.Repeat("1", 32)
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + id + "/inventory/overview"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous overview exposed")
	}
	o.login(t)
	r, value := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || value["schemaVersion"] != "tracebolt.complete-overview-view.v1" || value["deviceId"] != id || value["status"] != "not_configured" {
		t.Fatal("unsafe unavailable DTO", r.StatusCode, value)
	}
	for _, section := range []string{"processes", "volumes"} {
		v, ok := value[section].(map[string]any)
		if !ok || v["status"] != "not_configured" || v["complete"] != nil || v["transfer"] != nil || v["failure"] != nil {
			t.Fatal("unconfigured overview manufactured observations")
		}
	}
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{
		{"POST", path, nil, 405}, {"GET", path + "?search=private", nil, 400}, {"GET", path + "?", nil, 400}, {"GET", path + "/extra", nil, 404}, {"GET", path + "/query", nil, 405},
		{"GET", strings.Replace(path, id, "reported-host", 1), nil, 404}, {"POST", path + "/query", nil, 409},
		{"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"GET", path, func(r *http.Request) { r.Host = "other.invalid" }, 403},
		{"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
	} {
		r, _ = o.call(t, tc.method, tc.path, nil, "", tc.change)
		if r.StatusCode != tc.want {
			t.Fatalf("guard %s %s got %d want %d", tc.method, tc.path, r.StatusCode, tc.want)
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("overview response cacheable")
		}
	}
}
func TestCompleteOverviewNotConfiguredRechecksSessionAfterRead(t *testing.T) {
	app := setup(t)
	id := "agent_" + strings.Repeat("2", 32)
	var active atomic.Bool
	active.Store(true)
	app.mu.Lock()
	app.lanDevices = func() ([]model.Device, error) { active.Store(false); return []model.Device{{ID: id}}, nil }
	app.mu.Unlock()
	h := operatorHandler{app: app}
	r := httptest.NewRequest("GET", "/api/devices/"+id+"/inventory/overview", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active.Load}))
	w := httptest.NewRecorder()
	h.completeOverview(w, r)
	if w.Code != 401 || strings.Contains(w.Body.String(), "tracebolt.complete-overview-view") {
		t.Fatal("expired session exposed metadata")
	}
}
func TestCompleteOverviewQueryExactSectionAndBounds(t *testing.T) {
	base := `{"section":"processes","generationId":"sample_11111111111111111111111111111111","cursor":"","search":"","limit":100}`
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"processes", base, true}, {"volumes", strings.Replace(base, "processes", "volumes", 1), true},
		{"unknown section", strings.Replace(base, "processes", "services", 1), false}, {"section case", strings.Replace(base, "processes", "Processes", 1), false},
		{"duplicate section", strings.Replace(base, `"section":"processes"`, `"section":"volumes","section":"processes"`, 1), false},
		{"unknown field", strings.Replace(base, `"limit":100`, `"limit":100,"command":"x"`, 1), false},
		{"missing section", strings.Replace(base, `"section":"processes",`, "", 1), false},
		{"null", strings.Replace(base, `"search":""`, `"search":null`, 1), false},
		{"wrong generation", strings.Replace(base, "sample_", "agent_", 1), false},
		{"too many", strings.Replace(base, `"limit":100`, `"limit":101`, 1), false}, {"zero", strings.Replace(base, `"limit":100`, `"limit":0`, 1), false},
		{"negative", strings.Replace(base, `"limit":100`, `"limit":-1`, 1), false}, {"fraction", strings.Replace(base, `"limit":100`, `"limit":1.5`, 1), false},
		{"search oversized", strings.Replace(base, `"search":""`, `"search":"`+strings.Repeat("x", overviewledger.MaxSearchBytes+1)+`"`, 1), false},
		{"cursor oversized", strings.Replace(base, `"cursor":""`, `"cursor":"`+strings.Repeat("x", overviewledger.MaxCursorBytes+1)+`"`, 1), false},
		{"body oversized", base + strings.Repeat(" ", 4096), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/overview/query", strings.NewReader(tc.body))
			got, ok := readOverviewQuery(w, r)
			if ok != tc.want {
				t.Fatalf("accepted=%v want=%v, code=%d", ok, tc.want, w.Code)
			}
			if ok && (got.Limit != 100 || got.GenerationID != "sample_11111111111111111111111111111111") {
				t.Fatal("query mutated")
			}
		})
	}
}

type overviewRevokingReader struct {
	io.Reader
	revoke func()
}

func (b overviewRevokingReader) Read(p []byte) (int, error) { b.revoke(); return b.Reader.Read(p) }
func TestCompleteOverviewQueryRechecksSessionAfterBody(t *testing.T) {
	var active atomic.Bool
	active.Store(true)
	body := `{"section":"processes","generationId":"sample_11111111111111111111111111111111","cursor":"","search":"","limit":100}`
	r := httptest.NewRequest("POST", "/overview/query", overviewRevokingReader{strings.NewReader(body), func() { active.Store(false) }})
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active.Load}))
	w := httptest.NewRecorder()
	if _, ok := readOverviewQuery(w, r); ok || w.Code != 401 {
		t.Fatal("body outran session revocation")
	}
}
func overviewMetadataFixture(t *testing.T, section string, at time.Time) (overviewgeneration.Manifest, enrollmentstore.OverviewBinding) {
	t.Helper()
	s := completeoverview.Empty("sample_"+strings.Repeat("2", 32), at, completeoverview.ReasonReadFailed)
	s.CaptureFinishedAt = at.Add(time.Second)
	count := uint64(0)
	meta := completeoverview.SectionMeta{GenerationID: s.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true}
	if section == "processes" {
		s.Processes.Meta = meta
	} else {
		s.Volumes.Meta = meta
	}
	generation := "sample_" + strings.Repeat("3", 32)
	m, _, err := overviewgeneration.Build(context.Background(), s, section, generation, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := overviewgeneration.ManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	return m, enrollmentstore.OverviewBinding{Section: section, Sequence: 1, GenerationID: generation, ManifestHash: hash}
}
func TestCompleteOverviewDTOIndependentTimesAndFailure(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	m, b := overviewMetadataFixture(t, "processes", at)
	complete := &overviewledger.GenerationStatus{Manifest: m, State: "complete", CompletedAt: at.Add(2 * time.Second), ExpiresAt: at.Add(overviewledger.ObservationTTL)}
	input := enrollmentstore.OverviewStatus{DeviceID: "agent_" + strings.Repeat("1", 32), ServerNow: at.Add(3 * time.Second), Processes: enrollmentstore.OverviewSectionStatus{CompleteBinding: b, Complete: complete}, Volumes: enrollmentstore.OverviewSectionStatus{Failure: &enrollmentstore.OverviewFailureReceipt{Failure: enrollmentstore.OverviewFailureReport{Section: "volumes", Sequence: 1, GenerationID: b.GenerationID, AttemptedAt: at, Reason: "collection_failed"}, ReceivedAt: at.Add(time.Second)}}}
	got, err := overviewView(input)
	if err != nil || got.Status != "available" || got.Processes.Complete == nil || got.Volumes.Complete != nil || got.Volumes.Failure == nil || !got.Processes.Complete.Manifest.CaptureStartedAt.Equal(at) || !got.Processes.Complete.Manifest.CaptureFinishedAt.Equal(at.Add(time.Second)) {
		t.Fatal("independent section facts lost", err)
	}
	page := overviewPage(input.DeviceID, "processes", input.ServerNow, enrollmentstore.OverviewPageResult{Binding: b, PageResult: overviewledger.PageResult{Manifest: m, CompletedAt: complete.CompletedAt, Items: []overviewgeneration.Row{}, Exhausted: true}})
	raw, err := json.Marshal(page)
	if err != nil || !strings.Contains(string(raw), `"items":[]`) || !page.RetainedUntil.Equal(at.Add(overviewledger.ObservationTTL)) || !page.Manifest.CaptureFinishedAt.Equal(m.CaptureFinishedAt) {
		t.Fatal("empty generation/source time lost", err)
	}
	bad := input
	bad.Processes.CompleteBinding.Section = "volumes"
	if _, err := overviewView(bad); !errors.Is(err, enrollmentstore.ErrStorage) {
		t.Fatal("cross-section binding accepted")
	}
	bad = input
	bad.Processes.CompleteBinding.ManifestHash = strings.Repeat("0", 64)
	if _, err := overviewView(bad); !errors.Is(err, enrollmentstore.ErrStorage) {
		t.Fatal("wrong manifest binding accepted")
	}
	complete.State = "expired"
	got, err = overviewView(input)
	if err != nil || got.Status != "expired" || got.Processes.Status != "expired" {
		t.Fatal("expired generation advertised current")
	}
}
func TestCompleteOverviewOperatorErrorsRemainBounded(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{inventoryledger.ErrQuota, 409}, {overviewledger.ErrQuota, 409}, {enrollmentstore.ErrOverviewNotConfigured, 409}, {enrollmentstate.ErrNotFound, 404}, {enrollmentstore.ErrOverviewBusy, 429}, {overviewledger.ErrCursor, 409}, {overviewledger.ErrCursorExpired, 409}, {overviewledger.ErrExpired, 409}, {overviewledger.ErrNotFound, 409}, {enrollmentstate.ErrProof, 409}, {overviewledger.ErrInvalid, 400}, {errors.New("synthetic-private-storage-detail"), 503},
	} {
		w := httptest.NewRecorder()
		completeOverviewError(w, tc.err)
		if w.Code != tc.code || strings.Contains(w.Body.String(), "synthetic-private-storage-detail") {
			t.Fatal("unsafe error mapping", w.Code)
		}
		if tc.code == 429 && w.Header().Get("Retry-After") != "2" {
			t.Fatal("missing busy backoff")
		}
	}
}

// The configured query test uses a disposable issuer/database, no endpoint key
// provisioning or collection. Unknown device responses prove the query reached
// the current authority only after request validation and operator authorization.
func overviewServiceFixture(t *testing.T, origin string) *enrollmentservice.Service {
	t.Helper()
	return overviewServiceFixtureWithClock(t, origin, nil)
}
func overviewServiceFixtureWithClock(t *testing.T, origin string, clock func() time.Time) *enrollmentservice.Service {
	t.Helper()
	return overviewServiceFixtureAt(t, origin, time.Now().UTC(), clock)
}

func overviewServiceFixtureAt(t *testing.T, origin string, now time.Time, clock func() time.Time) *enrollmentservice.Service {
	t.Helper()
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic overview root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("overview-root")}
	rawRoot, err := x509.CreateCertificate(rand.Reader, rt, rt, rp, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	ip, ik, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic overview issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("overview-issuer")}
	rawIssuer, err := x509.CreateCertificate(rand.Reader, it, root, ip, rk)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(rawIssuer)
	issuer, err := enrollmentissuer.New(rawIssuer, rawRoot, ik, hex.EncodeToString(hash[:]), now)
	if err != nil {
		t.Fatal(err)
	}
	binding := enrollmentstate.Binding{InstanceID: "manager_" + strings.Repeat("1", 32), Profile: "tls", Origin: origin, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, IssuerFingerprint: issuer.Fingerprint()}
	cfg := enrollmentstate.DefaultConfig(binding)
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
	store, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "enrollment.db"), cfg, rawIssuer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err = store.InitializeOverview(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := enrollmentservice.New(store, issuer, clock)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func TestCompleteOverviewConfiguredQueryRequiresOperatorCSRF(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	h := o.server.Config.Handler.(*operatorHandler)
	h.enrollment = overviewServiceFixture(t, o.server.URL)
	_, logged := o.login(t)
	csrf := logged["csrfToken"].(string)
	path := "/api/devices/agent_" + strings.Repeat("1", 32) + "/inventory/overview/query"
	input := map[string]any{"section": "processes", "generationId": "sample_" + strings.Repeat("1", 32), "cursor": "", "search": "", "limit": 100}
	for _, tc := range []struct {
		name, token string
		change      func(*http.Request)
		want        int
	}{
		{"missing CSRF", "", nil, 403}, {"wrong CSRF", "incorrect", nil, 403},
		{"missing origin", csrf, func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"duplicate CSRF", csrf, func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) }, 403},
		{"wrong content type", csrf, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"authorized unknown device", csrf, nil, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := o.call(t, "POST", path, input, tc.token, tc.change)
			if r.StatusCode != tc.want {
				t.Fatalf("got %d want %d", r.StatusCode, tc.want)
			}
		})
	}
	input["section"] = "services"
	if r, _ := o.call(t, "POST", path, input, csrf, nil); r.StatusCode != 400 {
		t.Fatal("arbitrary section reached store")
	}
}
