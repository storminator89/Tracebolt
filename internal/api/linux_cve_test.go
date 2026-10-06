package api

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/linuxcve"
	"localrmm/internal/linuxcvefeed"
	"localrmm/internal/linuxcveprogress"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type cveInventoryFixture struct {
	view   enrollmentstore.InventoryStatus
	rows   []linuxpackages.PackageRow
	pages  int
	onRead func(int)
	onPage func(*enrollmentstore.InventoryPageResult)
	reads  int
}

func (f *cveInventoryFixture) CompleteInventoryView(_ context.Context, _ string, now time.Time) (enrollmentstore.InventoryStatus, error) {
	f.reads++
	if f.onRead != nil {
		f.onRead(f.reads)
	}
	view := f.view
	view.ServerNow = now
	return view, nil
}
func (f *cveInventoryFixture) CompleteInventoryPage(_ context.Context, _ string, request inventoryledger.PageRequest, _ time.Time) (enrollmentstore.InventoryPageResult, error) {
	f.pages++
	start, _ := strconv.Atoi(request.Cursor)
	end := start + request.Limit
	if end > len(f.rows) {
		end = len(f.rows)
	}
	page := enrollmentstore.InventoryPageResult{Binding: f.view.CompleteBinding, PageResult: inventoryledger.PageResult{Manifest: f.view.Complete.Manifest, TotalRows: uint64(len(f.rows)), ScannedRows: end - start, Items: append([]linuxpackages.PackageRow{}, f.rows[start:end]...), Exhausted: end == len(f.rows)}}
	if !page.Exhausted {
		page.NextCursor = strconv.Itoa(end)
	}
	if f.onPage != nil {
		f.onPage(&page)
	}
	return page, nil
}

func cveFixture(t *testing.T, now time.Time, rows []linuxpackages.PackageRow) *cveInventoryFixture {
	t.Helper()
	id := "agent_" + strings.Repeat("4", 32)
	distro, version, code := "debian", "13", "trixie"
	release := linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: &distro, VersionID: &version, VersionCodename: &code}}
	m, _, err := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: "sample_" + strings.Repeat("5", 32), CollectedAt: now.Add(-time.Minute), Release: release, Rows: rows}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := fullinventory.ManifestDigest(m)
	binding := enrollmentstore.InventoryBinding{Sequence: 1, GenerationID: m.GenerationID, ManifestHash: hash}
	return &cveInventoryFixture{rows: rows, view: enrollmentstore.InventoryStatus{DeviceID: id, ServerNow: now, CompleteBinding: binding, Complete: &inventoryledger.GenerationStatus{Manifest: m, State: "complete", CompletedAt: now.Add(-30 * time.Second), ExpiresAt: m.CollectedAt.Add(inventoryledger.ObservationTTL)}}}
}

func cveBundle(at time.Time) string {
	return `{"schemaVersion":"linux-cve-bundle-1","provider":"debian-security-tracker","fetchedAt":"` + at.Format(time.RFC3339Nano) + `","payload":{"fixture":{"CVE-2026-999999":{"releases":{"trixie":{"status":"resolved","fixed_version":"2:1.0-2"}}}}}}`
}
func fixtureCVEPackages() []linuxpackages.PackageRow {
	return []linuxpackages.PackageRow{{Name: "libfixture", Version: "2:1.0-1+b1", Architecture: "amd64", SourcePackage: "fixture", SourceVersion: "2:1.0-1", SourceMapping: "source-field", InstallState: "installed"}}
}
func newTestLinuxCVEState(t *testing.T, f linuxCVEInventorySource, now func() time.Time) *linuxCVEState {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	cache, err := linuxcveprogress.Open(filepath.Join(parent, "cve-assessments"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	state := newLinuxCVEState(f, now)
	state.progress = cache
	return state
}

func readCVEFixture(t *testing.T, f *cveInventoryFixture, state *linuxCVEState, active func() bool) (*httptest.ResponseRecorder, linuxCVEView) {
	t.Helper()
	app := setup(t)
	app.linuxCVE = state
	h := operatorHandler{app: app}
	r := httptest.NewRequest("GET", "/api/devices/"+f.view.DeviceID+"/security/cves", nil)
	if active != nil {
		r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active}))
	}
	w := httptest.NewRecorder()
	h.linuxCVEAPI(w, r)
	var view linuxCVEView
	if w.Code == 200 && json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal("invalid response JSON")
	}
	return w, view
}

func TestLinuxCVEVerticalSliceUsesCompleteSourceVersions(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	if _, err := state.feeds.Import(context.Background(), strings.NewReader(cveBundle(now.Add(-time.Hour))), now); err != nil {
		t.Fatal(err)
	}
	w, out := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || out.Status != "evaluated" || out.Report == nil || out.Report.Status != "partial" || len(out.Report.Findings) != 1 || f.pages != 1 || f.reads != 3 {
		t.Fatal("vertical slice", w.Code, w.Body.String())
	}
	finding := out.Report.Findings[0]
	if finding.InstalledSourceVersion != "2:1.0-1" || finding.PublishedFixedVersion != "2:1.0-2" || finding.Binaries[0].Version != "2:1.0-1+b1" || finding.Basis != "distribution_package_version_match" {
		t.Fatal("source version or basis lost")
	}
	if len(w.Body.Bytes()) > 256<<10 || strings.Contains(w.Body.String(), `"payload"`) {
		t.Fatal("unbounded/raw feed response")
	}
}

func TestLinuxCVEMissingAndEmptyRemainDifferent(t *testing.T) {
	now := time.Now().UTC()
	for _, kind := range []string{"missing_inventory", "missing_feed", "empty_inventory"} {
		t.Run(kind, func(t *testing.T) {
			rows := fixtureCVEPackages()
			if kind == "empty_inventory" {
				rows = []linuxpackages.PackageRow{}
			}
			f := cveFixture(t, now, rows)
			state := newTestLinuxCVEState(t, f, func() time.Time { return now })
			if kind == "missing_inventory" {
				f.view.Complete = nil
			}
			if kind == "empty_inventory" {
				if _, err := state.feeds.Import(context.Background(), strings.NewReader(cveBundle(now)), now); err != nil {
					t.Fatal(err)
				}
			}
			w, out := readCVEFixture(t, f, state, nil)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if kind == "empty_inventory" {
				if out.Status != "evaluated" || out.Report == nil || out.Report.Findings == nil || len(out.Report.Findings) != 0 {
					t.Fatal("empty source")
				}
			} else if out.Report != nil || f.pages != 0 {
				t.Fatal("missing became empty assessment")
			}
		})
	}
}

func TestLinuxCVERejectsMixedOrTruncatedInventory(t *testing.T) {
	now := time.Now().UTC()
	for _, kind := range []string{"binding", "count", "prefix", "changed_generation", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			f := cveFixture(t, now, fixtureCVEPackages())
			state := newTestLinuxCVEState(t, f, func() time.Time { return now })
			if _, err := state.feeds.Import(context.Background(), strings.NewReader(cveBundle(now)), now); err != nil {
				t.Fatal(err)
			}
			var active atomic.Bool
			active.Store(true)
			f.onPage = func(p *enrollmentstore.InventoryPageResult) {
				switch kind {
				case "binding":
					p.Binding.Sequence++
				case "count":
					p.TotalRows++
				case "prefix":
					p.Items = nil
					p.ScannedRows = 0
				}
			}
			f.onRead = func(n int) {
				if n == 2 {
					if kind == "changed_generation" {
						f.view.CompleteBinding.Sequence++
					}
					if kind == "revoked" {
						active.Store(false)
					}
				}
			}
			w, _ := readCVEFixture(t, f, state, active.Load)
			if w.Code == 200 || strings.Contains(w.Body.String(), "CVE-2026-") {
				t.Fatal("inconsistent/revoked assessment escaped", w.Code)
			}
		})
	}
}

func TestLinuxCVEOperatorGuardsAndDisabledProfile(t *testing.T) {
	o := newOperatorFixture(t, 0)
	id := "agent_" + strings.Repeat("1", 32)
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + id + "/security/cves"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous data")
	}
	_, login := o.login(t)
	if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["status"] != "not_configured" || v["report"] != nil {
		t.Fatal("disabled scope")
	}
	for _, tc := range []struct {
		method, path string
		edit         func(*http.Request)
		want         int
	}{
		{"POST", path, nil, 405}, {"GET", path + "/extra", nil, 404}, {"GET", path + "?q=x", nil, 400}, {"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.invalid") }, 403},
	} {
		if r, _ := o.call(t, tc.method, tc.path, nil, "", tc.edit); r.StatusCode != tc.want {
			t.Fatal(tc.path, r.StatusCode)
		}
	}
	if r, _ := o.call(t, "POST", "/api/security/cves/import", json.RawMessage(cveBundle(time.Now().UTC())), login["csrfToken"].(string), nil); r.StatusCode != 404 {
		t.Fatal("disabled profile imported")
	}
}

func TestLinuxCVEImportSessionAndFailureRetainLastGood(t *testing.T) {
	o := newOperatorFixture(t, 0)
	now := time.Now().UTC()
	state := newLinuxCVEState(nil, func() time.Time { return now })
	o.app.mu.Lock()
	o.app.linuxCVE = state
	o.app.mu.Unlock()
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	path := "/api/security/cves/import"
	if r, _ := o.call(t, "POST", path, json.RawMessage(cveBundle(now)), "", nil); r.StatusCode != 403 {
		t.Fatal("missing csrf")
	}
	if r, _ := o.call(t, "POST", path, json.RawMessage(cveBundle(now)), csrf, nil); r.StatusCode != 200 {
		t.Fatal("valid import", r.StatusCode)
	}
	before := state.feeds.View(now).Snapshots[0]
	if r, _ := o.call(t, "POST", path, json.RawMessage(`{"schemaVersion":"wrong"}`), csrf, nil); r.StatusCode != 400 {
		t.Fatal("invalid import")
	}
	after := state.feeds.View(now)
	if len(after.Snapshots) != 1 || after.Snapshots[0].SHA256 != before.SHA256 || after.Outcome != "failed" {
		t.Fatal("last good changed")
	}
	if r, _ := o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("logout")
	}
	if r, _ := o.call(t, "POST", path, json.RawMessage(cveBundle(now)), csrf, nil); r.StatusCode != 401 {
		t.Fatal("revoked import")
	}
}

// These cross-language fixtures contain handwritten advisory records only,
// emitted through the actual API projection. They never download a vendor feed.
func TestLinuxCVEGoFixtures(t *testing.T) {
	now := time.Date(2026, 10, 5, 7, 0, 0, 0, time.UTC)
	for _, provenance := range []string{"manual", "official"} {
		t.Run(provenance, func(t *testing.T) {
			f := cveFixture(t, now, fixtureCVEPackages())
			state := newTestLinuxCVEState(t, f, func() time.Time { return now })
			raw := cveBundle(now.Add(-time.Hour))
			if provenance == "manual" {
				if _, err := state.feeds.Import(context.Background(), strings.NewReader(raw), now); err != nil {
					t.Fatal(err)
				}
			} else {
				var envelope struct {
					Payload json.RawMessage `json:"payload"`
				}
				if json.Unmarshal([]byte(raw), &envelope) != nil {
					t.Fatal("fixture payload")
				}
				snapshot, err := linuxcve.ParseOfficialDebian(context.Background(), strings.NewReader(string(envelope.Payload)), now.Add(-time.Hour), now)
				if err != nil {
					t.Fatal(err)
				}
				if err = state.feeds.Replace(snapshot, now); err != nil {
					t.Fatal(err)
				}
			}
			w, out := readCVEFixture(t, f, state, nil)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			encoded, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, '\n')
			path := filepath.Join("..", "..", "web", "src", "linux-cve-go-fixture-"+provenance+".json")
			if os.Getenv("TRACEBOLT_WRITE_CVE_FIXTURES") == "1" {
				if err = os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
			stored, err := os.ReadFile(path)
			if err != nil || string(stored) != string(encoded) {
				t.Fatal("CVE cross-language fixture differs; regenerate with TRACEBOLT_WRITE_CVE_FIXTURES=1", err)
			}
		})
	}
}

func TestLinuxCVERecomputesOutgoingFeedAge(t *testing.T) {
	now := time.Now().UTC()
	clock := now
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return clock })
	if _, err := state.feeds.Import(context.Background(), strings.NewReader(cveBundle(now.Add(-linuxcve.FeedTTL+time.Second))), now); err != nil {
		t.Fatal(err)
	}
	f.onRead = func(n int) {
		if n == 2 {
			clock = now.Add(2 * time.Second)
		}
	}
	w, out := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || out.Report == nil || out.Report.Status != "stale" || out.Report.Feed.Freshness != "stale" || out.Feeds.Snapshots[0].Freshness != "stale" || !out.Report.AssessedAt.Equal(now) || !out.ServerNow.Equal(clock) {
		t.Fatal("feed age boundary", w.Code, w.Body.String())
	}
}

func TestLinuxCVEAdmissionIsBounded(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	state.assessments <- struct{}{}
	w, _ := readCVEFixture(t, f, state, nil)
	if w.Code != 429 || f.reads != 0 || w.Header().Get("Retry-After") != "2" {
		t.Fatal("unbounded admission")
	}
}

func TestLinuxCVEImportedFeedPersistsThroughAPIAndRestart(t *testing.T) {
	o := newOperatorFixture(t, 0)
	now := time.Now().UTC()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "security-data")
	cache, err := linuxcvefeed.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	state.cache = cache
	if err = cache.Load(context.Background(), &state.feeds, now); err != nil {
		t.Fatal(err)
	}
	o.app.mu.Lock()
	o.app.linuxCVE = state
	o.app.mu.Unlock()
	_, login := o.login(t)
	if r, v := o.call(t, "POST", "/api/security/cves/import", json.RawMessage(cveBundle(now.Add(-time.Hour))), login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal("persistent import", r.StatusCode, v)
	}
	before := state.feeds.View(now).Snapshots[0]
	if err = cache.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := linuxcvefeed.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state = newTestLinuxCVEState(t, f, func() time.Time { return now })
	state.cache = reopened
	if err = reopened.Load(context.Background(), &state.feeds, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after := state.feeds.View(now.Add(time.Minute)).Snapshots[0]
	if before.SHA256 != after.SHA256 || !before.FetchedAt.Equal(after.FetchedAt) || !before.ExpiresAt.Equal(after.ExpiresAt) || after.Trust != "operator_imported_unverified" {
		t.Fatal("restart reset source identity, age or trust")
	}
}

func TestLinuxCVECoverageUsesEveryInventoryPageWithoutConflatingDisplayLimits(t *testing.T) {
	now := time.Now().UTC()
	rows := make([]linuxpackages.PackageRow, 1396)
	for i := range rows {
		rows[i] = linuxpackages.PackageRow{Name: "fixture-binary-" + fmt.Sprintf("%04d", i), Version: "2:1.0-1+b1", Architecture: "amd64", SourcePackage: "fixture", SourceVersion: "2:1.0-1", SourceMapping: "source-field", InstallState: "installed"}
	}
	f := cveFixture(t, now, rows)
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	if _, err := state.feeds.Import(context.Background(), strings.NewReader(cveBundle(now.Add(-time.Hour))), now); err != nil {
		t.Fatal(err)
	}
	w, out := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || out.Report == nil || out.Inventory == nil || out.Inventory.RowCount != 1396 || f.pages != (1396+inventoryledger.MaxPageRows-1)/inventoryledger.MaxPageRows {
		t.Fatal("complete generation was not read", w.Code, f.pages)
	}
	r := out.Report
	if r.SchemaVersion != "tracebolt.linux-cve-result.v3" || !r.Coverage.EvaluationComplete || r.Coverage.TotalCheckCount != 1 || r.Coverage.CompletedCheckCount != 1 || r.Coverage.MatchedWarningCount != 1 || !r.Truncated || len(r.Findings) != 1 || !r.Findings[0].BinariesTruncated || r.UnassessedRecordCount != 0 {
		t.Fatalf("binary display limit changed processing coverage: %+v", r)
	}
	if len(w.Body.Bytes()) > 256<<10 || f.reads != 3 {
		t.Fatal("response budget or authority recheck changed")
	}
}
