package api

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/debianversion"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/linuxcve"
	"localrmm/internal/linuxcveprogress"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func readCVEDetailFixture(t *testing.T, f *cveInventoryFixture, state *linuxCVEState, kind string, input any, modify func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	app := setup(t)
	app.linuxCVE = state
	h := operatorHandler{app: app}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/devices/"+f.view.DeviceID+"/security/cves/"+kind+"/query", strings.NewReader(string(raw)))
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", app.csrf)
	if modify != nil {
		modify(r)
	}
	w := httptest.NewRecorder()
	h.linuxCVEAPI(w, r)
	return w
}
func completeCVEFixture(t *testing.T, f *cveInventoryFixture, state *linuxCVEState) linuxCVEView {
	t.Helper()
	for i := 0; i < 100; i++ {
		w, v := readCVEFixture(t, f, state, nil)
		if w.Code != 200 || v.Report == nil {
			t.Fatal("summary", w.Code, w.Body.String())
		}
		if v.Report.Coverage.EvaluationComplete {
			_, cached := readCVEFixture(t, f, state, nil)
			return cached
		}
	}
	t.Fatal("assessment did not finish")
	return linuxCVEView{}
}
func cveFindingsInput(v linuxCVEView, from uint64, limit int) linuxcve.FindingsQuery {
	return linuxcve.FindingsQuery{AssessmentID: v.Report.Continuation.AssessmentID, AssessmentRevision: v.Report.Continuation.Revision, FromCheck: from, Limit: limit}
}
func cveBinariesInput(v linuxCVEView, check, from uint64) linuxcve.BinariesQuery {
	return linuxcve.BinariesQuery{AssessmentID: v.Report.Continuation.AssessmentID, AssessmentRevision: v.Report.Continuation.Revision, CheckIndex: check, FromBinary: from, Limit: 20}
}

type cveDetailScenario struct {
	QueryLimit int                     `json:"queryLimit"`
	Summary    linuxCVEView            `json:"summary"`
	Findings   []linuxcve.FindingsPage `json:"findings"`
	Binaries   []linuxcve.BinariesPage `json:"binaries"`
}

func detailFixtureBundle(t *testing.T, now time.Time, sources map[string]any) string {
	t.Helper()
	raw, e := json.Marshal(map[string]any{"schemaVersion": linuxcve.BundleSchemaVersion, "provider": linuxcve.DebianProvider, "fetchedAt": now.Add(-time.Hour), "payload": sources})
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func detailFixtureRecords(start, count, gaps int, fix func(int) string) map[string]any {
	entries := map[string]any{}
	for i := 0; i < count; i++ {
		status, fixed := "resolved", fix(i)
		if i < gaps {
			status, fixed = "open", ""
		}
		entries[fmt.Sprintf("CVE-2026-%05d", start+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": status, "fixed_version": fixed}}}
	}
	return entries
}
func sortedCVERows(rows []linuxpackages.PackageRow) []linuxpackages.PackageRow {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Architecture < rows[j].Architecture
	})
	return rows
}
func TestLinuxCVEDetailsGoFixture(t *testing.T) {
	now := time.Date(2026, 10, 5, 7, 0, 0, 0, time.UTC)
	scenarios := map[string]cveDetailScenario{}
	for _, name := range []string{"manyFindingsMixedVersions", "manyBinaries", "emptyScan", "maximumFieldsMissingMiddle"} {
		t.Run(name, func(t *testing.T) {
			rows := fixtureCVEPackages()
			sources := map[string]any{}
			limit := 100
			switch name {
			case "manyFindingsMixedVersions":
				limit = 10
				rows = nil
				for i := 1; i <= 3; i++ {
					p := fixtureCVEPackages()[0]
					p.Name = fmt.Sprintf("fixture-bin-%d", i)
					p.SourceVersion = fmt.Sprintf("1.0-%d", i)
					rows = append(rows, p)
				}
				multi := rows[0]
				multi.Architecture = "arm64"
				rows = append(rows, multi)
				sources["fixture"] = detailFixtureRecords(10000, 145, 0, func(i int) string { return fmt.Sprintf("9.0-%d", i+1) })
			case "manyBinaries":
				rows = nil
				for i := 0; i < 145; i++ {
					p := fixtureCVEPackages()[0]
					p.Name = fmt.Sprintf("fixture-bin-%03d", i)
					rows = append(rows, p)
				}
				multi := rows[0]
				multi.Architecture = "arm64"
				rows = append(rows, multi)
				for _, kind := range []string{"other-version", "other-source", "incomplete", "local"} {
					p := fixtureCVEPackages()[0]
					p.Name = "zz-" + kind
					switch kind {
					case "other-version":
						p.SourceVersion = "2:1.0-9"
					case "other-source":
						p.SourcePackage = "fixture-extra"
					case "incomplete":
						p.InstallState = "incomplete"
					case "local":
						p.Version += "+local"
					}
					rows = append(rows, p)
				}
				sources["fixture"] = detailFixtureRecords(10000, 1, 0, func(int) string { return "3:1.0-1" })
			case "emptyScan":
				sources["fixture"] = detailFixtureRecords(10000, 4001, 4000, func(int) string { return "3:1.0-1" })
			case "maximumFieldsMissingMiddle":
				source := "source" + strings.Repeat("a", 250)
				p := fixtureCVEPackages()[0]
				p.Name = strings.Repeat("b", 256)
				p.Architecture = strings.Repeat("a", 64)
				p.SourcePackage = source
				p.Version = "1." + strings.Repeat("a", 510)
				p.SourceVersion = p.Version
				z := fixtureCVEPackages()[0]
				z.Name = "zz"
				z.SourcePackage = "zz"
				z.SourceVersion = "1.0-1"
				rows = []linuxpackages.PackageRow{p, z}
				sources[source] = detailFixtureRecords(10000, 2000, 0, func(i int) string { return fmt.Sprintf("2.%04d", i) + strings.Repeat("a", 506) })
				sources["zz"] = detailFixtureRecords(12000, 17, 0, func(int) string { return "2.0-1" })
			}
			f := cveFixture(t, now, sortedCVERows(rows))
			state := newTestLinuxCVEState(t, f, func() time.Time { return now })
			importContinuation(t, state, detailFixtureBundle(t, now, sources), now)
			summary := completeCVEFixture(t, f, state)
			store := &failingCVEProgress{inner: state.progress}
			state.progress = store
			scenario := cveDetailScenario{QueryLimit: limit, Summary: summary, Findings: []linuxcve.FindingsPage{}, Binaries: []linuxcve.BinariesPage{}}
			for from := uint64(0); ; {
				w := readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(summary, from, limit), nil)
				var p linuxcve.FindingsPage
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
					t.Fatal("finding page", w.Code, w.Body.String())
				}
				scenario.Findings = append(scenario.Findings, p)
				if p.Exhausted {
					break
				}
				if p.NextCheck <= from {
					t.Fatal("nonadvancing fixture")
				}
				from = p.NextCheck
				if name == "maximumFieldsMissingMiddle" && len(scenario.Findings) == 2 {
					from = 1990
				}
			}
			if name == "manyBinaries" {
				for from := uint64(0); ; {
					w := readCVEDetailFixture(t, f, state, "binaries", cveBinariesInput(summary, 0, from), nil)
					var p linuxcve.BinariesPage
					if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
						t.Fatal("binary page", w.Code, w.Body.String())
					}
					scenario.Binaries = append(scenario.Binaries, p)
					if p.Exhausted {
						break
					}
					from = p.NextBinary
				}
			}
			if name == "maximumFieldsMissingMiddle" {
				small := cveDetailScenario{QueryLimit: 10, Summary: summary, Findings: []linuxcve.FindingsPage{}, Binaries: []linuxcve.BinariesPage{}}
				for from := uint64(0); from < 120; {
					w := readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(summary, from, 10), nil)
					var p linuxcve.FindingsPage
					if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.NextCheck <= from {
						t.Fatal("small maximum page", w.Code)
					}
					small.Findings = append(small.Findings, p)
					from = p.NextCheck
				}
				scenarios["maximumFieldsMissingMiddleSmallPages"] = small
			}
			if store.saves != 0 {
				t.Fatal("detail read saved checkpoint")
			}
			_, after := readCVEFixture(t, f, state, nil)
			if !reflect.DeepEqual(summary, after) {
				t.Fatal("detail reads changed completed summary")
			}
			scenarios[name] = scenario
		})
	}
	verifyCVEFixtureFile(t, "linux-cve-go-fixture-details.json", scenarios)
}

func TestLinuxCVEDetailsStrictInputAndExactNamedReadScope(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, cveBundle(now.Add(-time.Hour)), now)
	v := completeCVEFixture(t, f, state)
	input := cveFindingsInput(v, 0, 100)
	valid, _ := json.Marshal(input)
	for _, body := range []string{`{}`, `null`, strings.Replace(string(valid), `"fromCheck":0`, `"fromCheck":-1`, 1), strings.Replace(string(valid), `"fromCheck":0`, `"fromCheck":0.1`, 1), strings.Replace(string(valid), `"fromCheck":0`, `"fromCheck":1e0`, 1), strings.Replace(string(valid), `"fromCheck":0`, `"fromCheck":null`, 1), strings.Replace(string(valid), `"fromCheck":0`, `"fromCheck":18446744073709551616`, 1), strings.Replace(string(valid), `"limit":100`, `"limit":101`, 1), strings.Replace(string(valid), `"limit":100`, `"limit":0`, 1), strings.Replace(string(valid), `"fromCheck":0`, `"fromCheck":2`, 1), `{"fromCheck":0,` + string(valid[1:]), `{"extra":0,` + string(valid[1:])} {
		w := readCVEDetailFixture(t, f, state, "findings", json.RawMessage(body), nil)
		if w.Code != 400 {
			t.Fatal("malformed accepted", w.Code, body)
		}
	}
	binaryValid, _ := json.Marshal(cveBinariesInput(v, 0, 0))
	for _, body := range []string{
		strings.Replace(string(binaryValid), `"fromBinary":0`, `"fromBinary":-1`, 1),
		strings.Replace(string(binaryValid), `"fromBinary":0`, `"fromBinary":0.5`, 1),
		strings.Replace(string(binaryValid), `"checkIndex":0`, `"checkIndex":1`, 1),
		strings.Replace(string(binaryValid), `"fromBinary":0`, `"fromBinary":2`, 1),
		strings.Replace(string(binaryValid), `"limit":20`, `"limit":21`, 1),
		`{"sourcePackage":"fixture",` + string(binaryValid[1:]),
		`{"checkIndex":0,` + string(binaryValid[1:]),
	} {
		w := readCVEDetailFixture(t, f, state, "binaries", json.RawMessage(body), nil)
		if w.Code != 400 {
			t.Fatal("malformed binary query accepted", w.Code)
		}
	}
	for _, change := range []string{"origin", "csrf", "duplicate-origin", "content-type", "encoding", "transfer", "query", "method", "suffix", "case", "revoked"} {
		t.Run(change, func(t *testing.T) {
			w := readCVEDetailFixture(t, f, state, "findings", input, func(r *http.Request) {
				switch change {
				case "origin":
					r.Header.Set("Origin", "https://elsewhere.invalid")
				case "csrf":
					r.Header.Del("X-CSRF-Token")
				case "duplicate-origin":
					r.Header.Add("Origin", r.Header.Get("Origin"))
				case "content-type":
					r.Header.Set("Content-Type", "text/plain")
				case "encoding":
					r.Header.Set("Content-Encoding", "gzip")
				case "transfer":
					r.TransferEncoding = []string{"chunked"}
				case "query":
					r.URL.RawQuery = "offset=0"
				case "method":
					r.Method = "GET"
				case "suffix":
					r.URL.Path += "/extra"
				case "case":
					r.URL.Path = strings.Replace(r.URL.Path, "findings", "Findings", 1)
				case "revoked":
					*r = *r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{origin: r.Header.Get("Origin"), session: operatorauth.Session{CSRFToken: r.Header.Get("X-CSRF-Token")}, active: func() bool { return false }}))
				}
			})
			if w.Code == 200 {
				t.Fatal("invalid request accepted", change)
			}
		})
	}
	for _, kind := range []string{"findings", "binaries"} {
		path := "/api/devices/" + f.view.DeviceID + "/security/cves/" + kind + "/query"
		if !namedReadRoute(httptest.NewRequest("POST", path, nil)) {
			t.Fatal("named reader denied")
		}
		for _, bad := range []string{path + "/extra", path + "/", strings.Replace(path, "/query", "/save", 1), strings.Replace(path, "/cves/", "/cves-extra/", 1), strings.Replace(path, f.view.DeviceID, "invalid", 1)} {
			if namedReadRoute(httptest.NewRequest("POST", bad, nil)) {
				t.Fatal("named read scope expanded", bad)
			}
		}
		for _, method := range []string{"PUT", "DELETE", "PATCH"} {
			if namedReadRoute(httptest.NewRequest(method, path, nil)) {
				t.Fatal("write method classified read")
			}
		}
	}
}

func TestLinuxCVEDetailsRevalidateAuthorityEvidenceClockAndCache(t *testing.T) {
	for _, change := range []string{"generation", "manifest", "feed", "authority", "expiry", "clock", "cancel", "cache-io", "cache-uncertain", "cache-corrupt", "cache-changed"} {
		t.Run(change, func(t *testing.T) {
			now := time.Now().UTC()
			clock := now
			active := true
			f := cveFixture(t, now, fixtureCVEPackages())
			state := newTestLinuxCVEState(t, f, func() time.Time { return clock })
			importContinuation(t, state, cveBundle(now.Add(-time.Hour)), now)
			v := completeCVEFixture(t, f, state)
			store := &detailProgressProbe{inner: state.progress}
			state.progress = store
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state.comparator = &callbackCVEComparator{delegate: debianversion.Comparator{}, once: func() {
				switch change {
				case "generation":
					f.view.CompleteBinding.Sequence++
				case "manifest":
					f.view.Complete.Manifest.CollectedAt = f.view.Complete.Manifest.CollectedAt.Add(time.Second)
				case "feed":
					importContinuation(t, state, cveBundle(now), now)
				case "authority":
					active = false
				case "expiry":
					clock = f.view.Complete.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
				case "clock":
					clock = now.Add(-time.Nanosecond)
				case "cancel":
					cancel()
				case "cache-io":
					store.failure = linuxcveprogress.ErrIO
				case "cache-uncertain":
					store.failure = linuxcveprogress.ErrUncertain
				case "cache-corrupt":
					store.failure = linuxcveprogress.ErrCorrupt
				case "cache-changed":
					store.changed = true
				}
			}}
			w := readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(v, 0, 100), func(r *http.Request) {
				*r = *r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{origin: r.Header.Get("Origin"), session: operatorauth.Session{CSRFToken: r.Header.Get("X-CSRF-Token")}, active: func() bool { return active }}))
			})
			if w.Code == 200 || strings.Contains(w.Body.String(), `"items"`) || store.saves != 0 {
				t.Fatal("invalidated page leaked or saved", change, w.Code, w.Body.String())
			}
		})
	}
}

type detailProgressProbe struct {
	inner   cveProgressStore
	failure error
	changed bool
	saves   int
}

func (s *detailProgressProbe) Load(key string, now time.Time) ([]byte, error) {
	if s.failure != nil {
		return nil, s.failure
	}
	raw, e := s.inner.Load(key, now)
	if s.changed {
		return []byte(`{}`), nil
	}
	return raw, e
}
func (s *detailProgressProbe) Save(key string, expiry, now time.Time, raw []byte) error {
	s.saves++
	return s.inner.Save(key, expiry, now, raw)
}

func TestLinuxCVEDetailsIncompleteMissingWrongBindingAndContention(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, continuationBundle(t, now, 2001), now)
	_, pending := readCVEFixture(t, f, state, nil)
	w := readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(pending, 0, 100), nil)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "cve_assessment_incomplete") {
		t.Fatal("incomplete trusted", w.Code, w.Body.String())
	}
	v := completeCVEFixture(t, f, state)
	q := cveFindingsInput(v, 0, 100)
	q.AssessmentRevision++
	w = readCVEDetailFixture(t, f, state, "findings", q, nil)
	if w.Code != 409 {
		t.Fatal("wrong revision")
	}
	q = cveFindingsInput(v, 0, 100)
	q.AssessmentID = strings.Repeat("a", 64)
	w = readCVEDetailFixture(t, f, state, "findings", q, nil)
	if w.Code != 409 {
		t.Fatal("wrong binding")
	}
	state.assessments <- struct{}{}
	w = readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(v, 0, 100), nil)
	<-state.assessments
	if w.Code != 429 || w.Header().Get("Retry-After") != "2" {
		t.Fatal("admission unbounded")
	}
	state.progress = nil
	w = readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(v, 0, 100), nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "cve_progress_unavailable") {
		t.Fatal("missing cache trusted")
	}
}

// Exercise the full named-account routing/session/CSRF boundary using in-memory
// HTTP recorders, without opening a listener or launching a browser.
func TestLinuxCVEDetailsNamedReadSessionBoundaryWithoutSocket(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, cveBundle(now.Add(-time.Hour)), now)
	v := completeCVEFixture(t, f, state)
	auth, e := operatorauth.New(operatorauth.Config{Now: func() time.Time { return now }, Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if e != nil {
		t.Fatal(e)
	}
	app := setup(t)
	app.linuxCVE = state
	h := operatorHandler{app: app, origin: "http://127.0.0.1:8787", authority: "127.0.0.1:8787", insecureHTTPTest: true, cookieName: "tracebolt-http-test-session", auth: auth}
	for _, kind := range []string{"findings", "binaries"} {
		var input any = cveFindingsInput(v, 0, 100)
		if kind == "binaries" {
			input = cveBinariesInput(v, 0, 0)
		}
		raw, _ := json.Marshal(input)
		for _, variant := range []string{"valid", "no-csrf", "no-session", "suffix", "sync"} {
			path := "/api/devices/" + f.view.DeviceID + "/security/cves/" + kind + "/query"
			if variant == "suffix" {
				path += "/extra"
			}
			if variant == "sync" {
				path = "/api/security/cves/sync"
			}
			r := httptest.NewRequest("POST", h.origin+path, strings.NewReader(string(raw)))
			r.Header.Set("Origin", h.origin)
			r.Header.Set("Content-Type", "application/json")
			if variant != "no-csrf" {
				r.Header.Set("X-CSRF-Token", session.CSRFToken)
			}
			if variant != "no-session" {
				r.AddCookie(&http.Cookie{Name: h.cookieName, Value: session.Token})
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 403
			if variant == "valid" {
				want = 200
			}
			if variant == "no-session" {
				want = 401
			}
			if w.Code != want {
				t.Fatal("named scope/session boundary", kind, variant, w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		}
	}
	now = session.ExpiresAt
	raw, _ := json.Marshal(cveFindingsInput(v, 0, 100))
	expired := httptest.NewRequest("POST", h.origin+"/api/devices/"+f.view.DeviceID+"/security/cves/findings/query", strings.NewReader(string(raw)))
	expired.Header.Set("Origin", h.origin)
	expired.Header.Set("Content-Type", "application/json")
	expired.Header.Set("X-CSRF-Token", session.CSRFToken)
	expired.AddCookie(&http.Cookie{Name: h.cookieName, Value: session.Token})
	expiredResponse := httptest.NewRecorder()
	h.ServeHTTP(expiredResponse, expired)
	if expiredResponse.Code != 401 || strings.Contains(expiredResponse.Body.String(), `"items"`) {
		t.Fatal("detail reads renewed original session expiry", expiredResponse.Code)
	}
	auth.Logout(session.Token)
}

func TestLinuxCVEDetailsTimeoutFailsWholeRead(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, cveBundle(now.Add(-time.Hour)), now)
	v := completeCVEFixture(t, f, state)
	store := &failingCVEProgress{inner: state.progress}
	state.progress = store
	state.comparator = deadlineCVEComparator{}
	w := readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(v, 0, 100), nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "cve_assessment_interrupted") || strings.Contains(w.Body.String(), `"items"`) || store.saves != 0 {
		t.Fatal("timeout became an accepted partial page", w.Code, w.Body.String())
	}
}
func TestLinuxCVEDetailsReadLeaseKeepsOriginalEvidenceAndRetention(t *testing.T) {
	now := time.Now().UTC()
	clock := now
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return clock })
	importContinuation(t, state, cveBundle(now.Add(-time.Hour)), now)
	v := completeCVEFixture(t, f, state)
	store := &failingCVEProgress{inner: state.progress}
	state.progress = store
	for _, elapsed := range []time.Duration{time.Hour, 23 * time.Hour} {
		clock = now.Add(elapsed)
		w := readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(v, 0, 100), nil)
		var p linuxcve.FindingsPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || !p.ServerNow.Equal(clock) {
			t.Fatal("page clock anchor did not advance", w.Code)
		}
		_, after := readCVEFixture(t, f, state, nil)
		if after.Report.AssessedAt != v.Report.AssessedAt || after.Inventory.CollectedAt != v.Inventory.CollectedAt || after.Report.Feed.FetchedAt != v.Report.Feed.FetchedAt || after.Report.Continuation.Revision != v.Report.Continuation.Revision {
			t.Fatal("evidence age/revision renewed")
		}
	}
	clock = f.view.Complete.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
	w := readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(v, 0, 100), nil)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "inventory_generation_expired") || store.saves != 0 {
		t.Fatal("detail browsing renewed original retention", w.Code)
	}
}
func TestLinuxCVEDetailsConcurrentReadsShareAssessmentAdmission(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, cveBundle(now.Add(-time.Hour)), now)
	v := completeCVEFixture(t, f, state)
	store := &failingCVEProgress{inner: state.progress}
	state.progress = store
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan *httptest.ResponseRecorder, 1)
	state.comparator = &callbackCVEComparator{delegate: debianversion.Comparator{}, once: func() { close(entered); <-release }}
	go func() { done <- readCVEDetailFixture(t, f, state, "findings", cveFindingsInput(v, 0, 100), nil) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("first detail did not enter")
	}
	second := readCVEDetailFixture(t, f, state, "binaries", cveBinariesInput(v, 0, 0), nil)
	close(release)
	first := <-done
	if first.Code != 200 || second.Code != 429 || second.Header().Get("Retry-After") != "2" || store.saves != 0 {
		t.Fatal("shared admission unbounded", first.Code, second.Code)
	}
}
