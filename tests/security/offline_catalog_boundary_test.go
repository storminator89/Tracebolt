//go:build linux

package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/offlinecatalog"
	"localrmm/internal/operational"
	"localrmm/internal/operatorauth"
)

// Only synthetic JSON and ordinary generated-key loopback fixtures are used.
// The Linux build tag follows operationalAPIHTTPFixture; other platforms must
// still compile the remaining independent boundary package without this helper.
const reviewCatalogJSON = `{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["review-private-source"],"rules":[{"sourcePackage":"review-private-source","advisoryId":"CVE-2099-99990001","release":"trixie","status":"resolved","fixedVersion":"2.0-1","qualifications":[],"archiveVersions":[]}]}`

func TestIndependentOfflineCatalogExportedCoreBoundary(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	raw := []byte(reviewCatalogJSON)
	hash := sha256.Sum256(raw)
	candidate, err := offlinecatalog.Parse(ctx, raw, at)
	if err != nil {
		t.Fatal("valid synthetic candidate rejected")
	}
	clear(raw)
	store := offlinecatalog.New()
	initial := store.View(at)
	loaded, err := store.Replace(ctx, initial.Revision, candidate, at.Add(time.Minute))
	if err != nil || loaded.Catalog == nil {
		t.Fatal("candidate promotion failed")
	}
	m := loaded.Catalog
	if m.SHA256 != hex.EncodeToString(hash[:]) || m.OriginAssurance != "unverified" || m.Freshness != "unknown" || m.PublishedAt != nil || !m.ImportedAt.Equal(at.Add(time.Minute)) || m.RuleCount != 1 || m.CoveredSourceCount != 1 || !loaded.ResetsOnRestart || loaded.Storage != "memory-only" {
		t.Fatal("import inferred authority, lost byte identity, or used parse time as commit time")
	}
	for _, object := range []any{candidate, &candidate, *store, store, loaded} {
		encoded, err := json.Marshal(object)
		if err != nil {
			t.Fatal("safe serialization failed")
		}
		for _, output := range []string{string(encoded), fmt.Sprintf("%+v", object), fmt.Sprintf("%#v", object)} {
			if strings.Contains(output, "review-private-source") || strings.Contains(output, "CVE-2099") {
				t.Fatal("opaque diagnostics leaked imported content")
			}
		}
	}
	loaded.Catalog.OriginAssurance = "fixture-mutation"
	if store.View(at).Catalog.OriginAssurance != "unverified" {
		t.Fatal("view mutation changed stored authority")
	}
	before := store.View(at)
	ctxCanceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = store.Replace(ctxCanceled, before.Revision, candidate, at); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled replacement accepted")
	}
	if _, err = store.Clear(ctxCanceled, before.Revision, at); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled clear accepted")
	}
	if _, err = store.Replace(ctx, initial.Revision, candidate, at); !errors.Is(err, offlinecatalog.ErrChanged) {
		t.Fatal("stale CAS accepted")
	}
	if _, err = store.Replace(ctx, before.Revision, offlinecatalog.Candidate{}, at); !errors.Is(err, offlinecatalog.ErrInvalid) {
		t.Fatal("zero candidate accepted")
	}
	if after := store.View(at); after.Revision != before.Revision || *after.Catalog != *before.Catalog {
		t.Fatal("failed operation changed last-good metadata")
	}
	if fresh := offlinecatalog.New().View(at); fresh.Catalog != nil || fresh.Revision == before.Revision {
		t.Fatal("new process-local store recovered previous catalog")
	}
}

func TestIndependentOfflineCatalogStrictUntrustedDocument(t *testing.T) {
	mutate := func(old, replacement string) []byte {
		return []byte(strings.Replace(reviewCatalogJSON, old, replacement, 1))
	}
	cases := map[string][]byte{
		"root null": []byte(`null`), "XML": []byte(`<!DOCTYPE root [<!ENTITY x SYSTEM "file:///fixture">]><root>&x;</root>`),
		"authority field":   mutate(`"schema":`, `"trust":"vendor_signature_verified","schema":`),
		"publication field": mutate(`"schema":`, `"publishedAt":"2099-01-01T00:00:00Z","schema":`),
		"synthetic null":    mutate(`"synthetic":true`, `"synthetic":null`), "synthetic string": mutate(`"synthetic":true`, `"synthetic":"true"`),
		"root duplicate": mutate(`"synthetic":true`, `"synthetic":true,"synthetic":true`), "root case": mutate(`"synthetic":`, `"Synthetic":`),
		"rules null": []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["review-private-source"],"rules":null}`), "missing rules": []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["review-private-source"]}`),
		"coverage null": mutate(`"coveredSources":["review-private-source"]`, `"coveredSources":null`), "empty coverage": mutate(`"coveredSources":["review-private-source"]`, `"coveredSources":[]`),
		"rule null string": mutate(`"fixedVersion":"2.0-1"`, `"fixedVersion":null`), "rule null array": mutate(`"qualifications":[]`, `"qualifications":null`),
		"rule null element": mutate(`"archiveVersions":[]`, `"archiveVersions":[null]`), "rule duplicate": mutate(`"release":"trixie"`, `"release":"trixie","release":"trixie"`),
		"release alias": mutate(`"release":"trixie"`, `"release":"13"`), "release case": mutate(`"release":"trixie"`, `"release":"Trixie"`),
		"another release": mutate(`"release":"trixie"`, `"release":"noble"`), "trailing value": append([]byte(reviewCatalogJSON), []byte(`{}`)...),
		"too many bytes": bytes.Repeat([]byte(" "), offlinecatalog.MaxBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := offlinecatalog.Parse(context.Background(), raw, time.Now())
			if err == nil {
				t.Fatal("untrusted or ambiguous catalog accepted")
			}
			if err != offlinecatalog.ErrInvalid && err != offlinecatalog.ErrTooLarge && err != offlinecatalog.ErrUnsupportedRelease {
				t.Fatal("diagnostic exposed parser details")
			}
		})
	}
	for _, synthetic := range []string{"true", "false"} {
		candidate, err := offlinecatalog.Parse(context.Background(), mutate(`"synthetic":true`, `"synthetic":`+synthetic), time.Now())
		if err != nil {
			t.Fatal("valid interchange variant rejected")
		}
		store := offlinecatalog.New()
		view, err := store.Replace(context.Background(), store.View(time.Now()).Revision, candidate, time.Now())
		if err != nil || view.Catalog.OriginAssurance != "unverified" || view.Catalog.Freshness != "unknown" {
			t.Fatal("synthetic flag promoted authority")
		}
	}
}

func reviewCatalogRead(t *testing.T, h *independentEnrollmentHTTP, session operatorauth.Session) offlinecatalog.View {
	t.Helper()
	code, raw, _ := h.request(t, "/api/security/catalog", nil, func(r *http.Request) { h.browser(session)(r); r.Method = http.MethodGet })
	var view offlinecatalog.View
	if code != 200 || json.Unmarshal(raw, &view) != nil {
		t.Fatal("catalog read failed")
	}
	return view
}

func reviewCatalogPost(t *testing.T, h *independentEnrollmentHTTP, session operatorauth.Session, revision string, raw []byte) (int, []byte) {
	t.Helper()
	code, body, _ := h.request(t, "/api/security/catalog", raw, func(r *http.Request) { h.browser(session)(r); r.Header.Set("X-Tracebolt-Catalog-Revision", revision) })
	return code, body
}

func TestIndependentOfflineCatalogManagedProfileAndHTTPPreservation(t *testing.T) {
	for _, httpTest := range []bool{false, true} {
		for _, profile := range []string{enrollmentcrypto.CollectionProfile, operational.CollectionProfile} {
			t.Run(fmt.Sprintf("httpTest=%t/%s", httpTest, profile), func(t *testing.T) {
				h, _ := operationalAPIHTTPFixture(t, httpTest, profile)
				session := h.session(t)
				before := reviewCatalogRead(t, h, session)
				if profile != operational.CollectionProfile {
					if before.Enabled || before.Catalog != nil || before.Revision != "" {
						t.Fatal("basic profile enabled catalog")
					}
					if status, _ := reviewCatalogPost(t, h, session, "revision_"+strings.Repeat("a", 32), []byte(reviewCatalogJSON)); status != 404 {
						t.Fatal("basic profile imported catalog")
					}
					return
				}
				if !before.Enabled || before.Catalog != nil || before.Limits.MaxInFlight != 1 {
					t.Fatal("managed profile enablement failed")
				}
				if status, _ := reviewCatalogPost(t, h, session, before.Revision, []byte(reviewCatalogJSON)); status != 200 {
					t.Fatal("managed import failed")
				}
				before = reviewCatalogRead(t, h, session)
				for _, raw := range [][]byte{[]byte(strings.Replace(reviewCatalogJSON, `"release":"trixie"`, `"release":"noble"`, 1)), []byte(`{"privateBodyMustNotAppear":true}`), bytes.Repeat([]byte(" "), offlinecatalog.MaxBytes+1)} {
					status, body := reviewCatalogPost(t, h, session, before.Revision, raw)
					if status != 400 && status != 413 {
						t.Fatal("invalid body was not rejected")
					}
					if bytes.Contains(body, []byte("privateBodyMustNotAppear")) || bytes.Contains(body, []byte("review-private-source")) {
						t.Fatal("invalid body echoed")
					}
					if after := reviewCatalogRead(t, h, session); after.Revision != before.Revision || *after.Catalog != *before.Catalog {
						t.Fatal("rejection replaced active catalog")
					}
				}
				for _, change := range []func(*http.Request){
					func(r *http.Request) { r.Header.Del("Origin") }, func(r *http.Request) { r.Header.Add("Origin", h.origin) },
					func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Add("X-CSRF-Token", session.CSRFToken) },
					func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, func(r *http.Request) { r.Header.Add("Content-Type", "application/json") },
					func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, func(r *http.Request) { r.Header.Add("X-Tracebolt-Catalog-Revision", before.Revision) },
				} {
					status, _, _ := h.request(t, "/api/security/catalog", []byte(reviewCatalogJSON), func(r *http.Request) {
						h.browser(session)(r)
						r.Header.Set("X-Tracebolt-Catalog-Revision", before.Revision)
						change(r)
					})
					if status != 400 && status != 403 && status != 415 {
						t.Fatal("ambiguous mutation headers accepted")
					}
				}
				if after := reviewCatalogRead(t, h, session); after.Revision != before.Revision {
					t.Fatal("header rejection changed catalog")
				}
			})
		}
	}
}

type reviewCatalogReader struct {
	read   io.Reader
	once   sync.Once
	before func()
}

func (r *reviewCatalogReader) Read(p []byte) (int, error) { r.once.Do(r.before); return r.read.Read(p) }

func TestIndependentOfflineCatalogAdmissionAndSessionCommitBoundary(t *testing.T) {
	h, _ := operationalAPIHTTPFixture(t, true, operational.CollectionProfile)
	session := h.session(t)
	before := reviewCatalogRead(t, h, session)
	request := func(action func()) *http.Request {
		r := httptest.NewRequest("POST", h.origin+"/api/security/catalog", &reviewCatalogReader{read: strings.NewReader(reviewCatalogJSON), before: action})
		r.ContentLength = int64(len(reviewCatalogJSON))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Tracebolt-Catalog-Revision", before.Revision)
		h.browser(session)(r)
		return r
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	first := httptest.NewRecorder()
	go func() { h.handler.ServeHTTP(first, request(func() { close(entered); <-release })); close(done) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("body not admitted")
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, request(func() { t.Error("busy request body was read") }))
	if w.Code != 429 {
		t.Fatal("concurrent body parser admitted")
	}
	// Logout must finish while the admitted body is held; parsing cannot hold the
	// mutation lease, and the late authenticated body must not commit afterward.
	h.auth.Logout(session.Token)
	unblock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("held body did not finish")
	}
	if first.Code != 401 {
		t.Fatal("revoked session committed after body read")
	}
	freshSession := h.session(t)
	if after := reviewCatalogRead(t, h, freshSession); after.Revision != before.Revision || after.Catalog != nil {
		t.Fatal("post-logout import changed catalog")
	}
	if status, _ := reviewCatalogPost(t, h, freshSession, before.Revision, []byte(reviewCatalogJSON)); status != 200 {
		t.Fatal("failed import leaked admission slot")
	}
}

func TestIndependentOfflineCoverageUnknownPartialRetainedAndExpired(t *testing.T) {
	h, _ := operationalAPIHTTPFixture(t, true, operational.CollectionProfile)
	identity := operationalStoreActivate(t, h.f)
	session := h.session(t)
	path := "/api/devices/" + identity.Approval.DeviceID + "/security"
	read := func() map[string]any {
		t.Helper()
		status, raw, _ := h.request(t, path, nil, func(r *http.Request) { h.browser(session)(r); r.Method = "GET" })
		var view map[string]any
		if status != 200 || json.Unmarshal(raw, &view) != nil {
			t.Fatal("coverage read failed")
		}
		vulnerabilities, updates := view["vulnerabilities"].(map[string]any), view["offeredUpdates"].(map[string]any)
		if vulnerabilities["coverage"] != "unknown" || vulnerabilities["affectedCves"] != nil || vulnerabilities["reviewCandidates"] != nil || updates["coverage"] != "unknown" || updates["offeredCount"] != nil {
			t.Fatal("missing source facts became assessment or offered-update zeros")
		}
		if bytes.Contains(raw, []byte("fixture-package")) || bytes.Contains(raw, []byte("review-private-source")) || bytes.Contains(raw, []byte("CVE-2099")) {
			t.Fatal("coverage response exposed package/rule content")
		}
		return view
	}
	view := read()
	inv := view["inventory"].(map[string]any)
	if view["collectionStatus"] != "awaiting" || inv["coverage"] != "unknown" || inv["installedCount"] != nil || inv["reportedItemCount"] != nil {
		t.Fatal("manager inventory substituted for awaiting device")
	}
	catalog := reviewCatalogRead(t, h, session)
	if status, _ := reviewCatalogPost(t, h, session, catalog.Revision, []byte(reviewCatalogJSON)); status != 200 {
		t.Fatal("catalog fixture rejected")
	}
	view = read()
	if view["catalog"].(map[string]any)["originAssurance"] != "unverified" || view["catalog"].(map[string]any)["freshness"] != "unknown" || view["vulnerabilities"].(map[string]any)["reasonCodes"].([]any)[0] != "advisory_authority_unverified" {
		t.Fatal("import gained endpoint/vendor authority")
	}
	save := func(seq uint64, snapshot operational.Snapshot) {
		t.Helper()
		_, err := h.f.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, operationalStoreFrame(t, seq, h.f.clock(), &snapshot), h.f.clock())
		if err != nil {
			t.Fatal("synthetic observation rejected")
		}
	}
	completeEmpty := operationalStoreSnapshot(h.f.clock(), "software")
	completeEmpty.Sections.Software.Items = []operational.Software{}
	completeEmpty.Sections.Software.Meta.ObservedCount = 0
	save(1, completeEmpty)
	view = read()
	inv = view["inventory"].(map[string]any)
	if inv["coverage"] != "observed" || inv["installedCount"] != float64(0) || inv["freshness"] != "fresh" {
		t.Fatal("legitimate complete empty binary observation lost its explicit scope")
	}
	h.f.now.Add(1)
	snapshot := operationalStoreSnapshot(h.f.clock(), "software")
	snapshot.Sections.Software.Meta.Complete = false
	snapshot.Sections.Software.Meta.Truncated = true
	snapshot.Sections.Software.Meta.Reason = operational.ReasonItemLimit
	snapshot.Sections.Software.Meta.ObservedCount = 500
	save(2, snapshot)
	view = read()
	inv = view["inventory"].(map[string]any)
	if inv["coverage"] != "partial" || inv["freshness"] != "fresh" || inv["reportedItemCount"] != float64(1) || inv["observedCount"] != float64(500) || inv["installedCount"] != nil {
		t.Fatal("partial reported inventory became installed total")
	}
	originalTime, originalGeneration := inv["collectedAt"], inv["generationId"]
	h.f.now.Add(1)
	save(3, operational.Empty(h.f.clock(), operational.ReasonPermissionDenied))
	view = read()
	inv = view["inventory"].(map[string]any)
	if inv["coverage"] != "partial" || inv["freshness"] != "stale" || inv["collectedAt"] != originalTime || inv["generationId"] != originalGeneration || inv["installedCount"] != nil {
		t.Fatal("retained partial source lost age or became complete")
	}
	h.f.now.Add(121)
	view = read()
	inv = view["inventory"].(map[string]any)
	if view["collectionStatus"] != "stale" || inv["freshness"] != "stale" {
		t.Fatal("expired collection became fresh")
	}
	_, err := h.f.store.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identity.InvitationID, RequestID: h.f.nextRequest(), ExpectedRevision: identity.Revision, Now: h.f.clock().Unix()}, State: enrollmentstate.Revoked})
	if err != nil {
		t.Fatal("synthetic identity revocation failed")
	}
	view = read()
	inv = view["inventory"].(map[string]any)
	if view["collectionStatus"] != "revoked" || inv["freshness"] != "stale" {
		t.Fatal("revoked source became fresh")
	}
	h.f.now.Add(24 * 60 * 60)
	view = read()
	inv = view["inventory"].(map[string]any)
	if inv["coverage"] != "unknown" || inv["freshness"] != "unknown" || inv["installedCount"] != nil || inv["reportedItemCount"] != nil || inv["collectedAt"] != nil || inv["generationId"] != nil {
		t.Fatal("expired retention revived observation or zero inventory")
	}
}
