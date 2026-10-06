package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/linuxcve"
	"localrmm/internal/linuxcveprogress"
	"localrmm/internal/linuxpackages"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func continuationBundle(t *testing.T, now time.Time, records int) string {
	t.Helper()
	entries := map[string]any{}
	for i := 0; i < records; i++ {
		entries[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": "resolved", "fixed_version": fmt.Sprintf("3:1.0-%d", i+1)}}}
	}
	raw, err := json.Marshal(map[string]any{"schemaVersion": linuxcve.BundleSchemaVersion, "provider": linuxcve.DebianProvider, "fetchedAt": now.Add(-time.Hour), "payload": map[string]any{"fixture": entries}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func importContinuation(t *testing.T, state *linuxCVEState, bundle string, now time.Time) {
	t.Helper()
	if _, e := state.feeds.Import(context.Background(), strings.NewReader(bundle), now); e != nil {
		t.Fatal(e)
	}
}
func verifyCVEFixtureFile(t *testing.T, name string, value any) {
	t.Helper()
	encoded, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("..", "..", "web", "src", name)
	if os.Getenv("TRACEBOLT_WRITE_CVE_FIXTURES") == "1" {
		if e = os.WriteFile(path, encoded, 0600); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(path)
	if e != nil || string(raw) != string(encoded) {
		t.Fatal("CVE continuation fixture differs; regenerate with TRACEBOLT_WRITE_CVE_FIXTURES=1", e)
	}
}

func TestLinuxCVEContinuationGoFixture(t *testing.T) {
	now := time.Date(2026, 10, 5, 7, 0, 0, 0, time.UTC)
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, continuationBundle(t, now, 2017), now)
	sequence := []linuxCVEView{}
	for i := 0; i < 3; i++ {
		w, out := readCVEFixture(t, f, state, nil)
		if w.Code != 200 || out.Report == nil {
			t.Fatal("bounded step", w.Code, w.Body.String())
		}
		sequence = append(sequence, out)
	}
	a, b, c := sequence[0].Report, sequence[1].Report, sequence[2].Report
	if a.Continuation.State != "pending" || a.Coverage.CompletedCheckCount != 2000 || a.Coverage.ComparisonCount != 2000 || a.Coverage.MatchedWarningCount != 2000 || a.Continuation.Revision != 1 || b.Continuation.State != "complete" || b.Coverage.CompletedCheckCount != 2017 || b.Coverage.MatchedWarningCount != 2017 || b.Continuation.Revision != 2 || c.Continuation.AdvancedCheckCount != 0 || c.Continuation.Revision != 2 || c.Coverage.ComparisonCount != 0 || a.Continuation.AssessmentID != c.Continuation.AssessmentID {
		t.Fatal("API did not durably continue", a.Continuation, b.Continuation, c.Continuation)
	}
	verifyCVEFixtureFile(t, "linux-cve-go-fixture-continuation.json", sequence)
}

func TestLinuxCVEDurableContinuationSurvivesManagerAndFeedReparse(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(parent, "cve-assessments")
	cache, e := linuxcveprogress.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer cache.Close()
	state := newLinuxCVEState(f, func() time.Time { return now })
	state.progress = cache
	bundle := continuationBundle(t, now, 2017)
	importContinuation(t, state, bundle, now)
	w, first := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || first.Report == nil || first.Report.Continuation.State != "pending" {
		t.Fatal("initial continuation", w.Code)
	}
	if e = cache.Close(); e != nil {
		t.Fatal(e)
	}
	cache, e = linuxcveprogress.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer cache.Close()
	later := now.Add(time.Minute)
	state = newLinuxCVEState(f, func() time.Time { return later })
	state.progress = cache
	importContinuation(t, state, bundle, later)
	w, out := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || out.Report == nil || out.Report.Continuation.State != "complete" || out.Report.Continuation.AssessmentID != first.Report.Continuation.AssessmentID || out.Report.Continuation.AdvancedCheckCount != 17 || out.Report.Coverage.ComparisonCount != 17 || out.Report.Coverage.MatchedWarningCount != 2017 || !out.Report.Feed.ValidatedAt.Equal(later) || !out.Inventory.CollectedAt.Equal(first.Inventory.CollectedAt) {
		t.Fatal("restart reprocessed prefix or renewed evidence", w.Code, w.Body.String())
	}
}

type failingCVEProgress struct {
	inner            cveProgressStore
	loadErr, saveErr error
	saves            int
	afterSave        func()
}

func (s *failingCVEProgress) Load(key string, now time.Time) ([]byte, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.inner.Load(key, now)
}
func (s *failingCVEProgress) Save(key string, expiry, now time.Time, raw []byte) error {
	s.saves++
	if s.saveErr != nil {
		return s.saveErr
	}
	e := s.inner.Save(key, expiry, now, raw)
	if e == nil && s.afterSave != nil {
		s.afterSave()
	}
	return e
}

func TestLinuxCVEProgressSaveFailureNeverAcknowledgesAdvancement(t *testing.T) {
	for _, failure := range []error{linuxcveprogress.ErrIO, linuxcveprogress.ErrUncertain, linuxcveprogress.ErrCorrupt, linuxcveprogress.ErrUnsafe} {
		t.Run(failure.Error(), func(t *testing.T) {
			now := time.Now().UTC()
			f := cveFixture(t, now, fixtureCVEPackages())
			state := newTestLinuxCVEState(t, f, func() time.Time { return now })
			importContinuation(t, state, continuationBundle(t, now, 2017), now)
			broken := &failingCVEProgress{inner: state.progress, saveErr: failure}
			state.progress = broken
			w, _ := readCVEFixture(t, f, state, nil)
			if w.Code != 503 || strings.Contains(w.Body.String(), "CVE-2026-") || strings.Contains(w.Body.String(), "completedCheckCount") {
				t.Fatal("failed save leaked trusted progress", w.Code, w.Body.String())
			}
			if errors.Is(failure, linuxcveprogress.ErrUncertain) && !strings.Contains(w.Body.String(), "cve_progress_uncertain") {
				t.Fatal("uncertain save was hidden")
			}
			broken.saveErr = nil
			w, out := readCVEFixture(t, f, state, nil)
			if w.Code != 200 || out.Report.Coverage.CompletedCheckCount != 2000 || out.Report.Continuation.Revision != 1 {
				t.Fatal("failed save was counted as progress", w.Code)
			}
		})
	}
}

func TestLinuxCVEProgressRejectsCorruptCheckpointAndMissingPrivateCache(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, continuationBundle(t, now, 2017), now)
	key, e := linuxcve.AssessmentID(state.feeds.Snapshot(linuxpackages.Debian13), f.view.Complete.Manifest, linuxcve.AssessmentIdentity{DeviceID: f.view.DeviceID, Sequence: 1})
	if e != nil {
		t.Fatal(e)
	}
	if e = state.progress.Save(key, f.view.Complete.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL), now, []byte(`{"not":"a checkpoint"}`)); e != nil {
		t.Fatal(e)
	}
	w, _ := readCVEFixture(t, f, state, nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "cve_progress_unavailable") {
		t.Fatal("corrupt engine checkpoint trusted", w.Code, w.Body.String())
	}
	state.progress = nil
	w, _ = readCVEFixture(t, f, state, nil)
	if w.Code != 503 {
		t.Fatal("private cache absence silently downgraded")
	}
}

func TestLinuxCVEContinuationRechecksBindingAfterSave(t *testing.T) {
	for _, change := range []string{"generation", "feed", "operator", "expiry"} {
		t.Run(change, func(t *testing.T) {
			now := time.Now().UTC()
			clock := now
			f := cveFixture(t, now, fixtureCVEPackages())
			state := newTestLinuxCVEState(t, f, func() time.Time { return clock })
			importContinuation(t, state, continuationBundle(t, now, 2017), now)
			active := true
			store := &failingCVEProgress{inner: state.progress}
			state.progress = store
			store.afterSave = func() {
				switch change {
				case "generation":
					f.view.CompleteBinding.Sequence++
				case "feed":
					importContinuation(t, state, cveBundle(now.Add(time.Second)), now.Add(time.Second))
				case "operator":
					active = false
				case "expiry":
					clock = f.view.Complete.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
				}
			}
			w, _ := readCVEFixture(t, f, state, func() bool { return active })
			if w.Code == 200 || strings.Contains(w.Body.String(), "completedCheckCount") || strings.Contains(w.Body.String(), "CVE-2026-") {
				t.Fatal("post-save authority/binding loss leaked progress", change, w.Code, w.Body.String())
			}
		})
	}
}

func TestLinuxCVEContinuationChangedSequenceStartsFreshBinding(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, continuationBundle(t, now, 2017), now)
	w, first := readCVEFixture(t, f, state, nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	f.view.CompleteBinding.Sequence++
	w, second := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || second.Report.Continuation.AssessmentID == first.Report.Continuation.AssessmentID || second.Report.Continuation.Revision != 1 || second.Report.Coverage.CompletedCheckCount != 2000 || second.Report.Coverage.MatchedWarningCount != 2000 {
		t.Fatal("new binding reused old totals", w.Code)
	}
}

type callbackCVEComparator struct {
	once     func()
	delegate assessment.VersionComparator
}

func (c *callbackCVEComparator) Compare(ctx context.Context, a, b string) (int, error) {
	if c.once != nil {
		callback := c.once
		c.once = nil
		callback()
	}
	return c.delegate.Compare(ctx, a, b)
}
func TestLinuxCVECanceledAssessmentDoesNotCommit(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, continuationBundle(t, now, 2017), now)
	store := &failingCVEProgress{inner: state.progress}
	state.progress = store
	ctx, cancel := context.WithCancel(context.Background())
	state.comparator = &callbackCVEComparator{once: cancel, delegate: debianversion.Comparator{}}
	app := setup(t)
	app.linuxCVE = state
	handler := operatorHandler{app: app}
	request := httptest.NewRequest("GET", "/api/devices/"+f.view.DeviceID+"/security/cves", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.linuxCVEAPI(w, request)
	if w.Code == 200 || store.saves != 0 || strings.Contains(w.Body.String(), "completedCheckCount") {
		t.Fatal("canceled request acknowledged progress", w.Code, store.saves)
	}
}

func TestLinuxCVEContinuation1396RowsSixWarnings627Gaps(t *testing.T) {
	now := time.Now().UTC()
	rows := make([]linuxpackages.PackageRow, 1396)
	for i := range rows {
		rows[i] = fixtureCVEPackages()[0]
		rows[i].Name = fmt.Sprintf("fixture-binary-%04d", i)
	}
	entries := map[string]any{}
	for i := 0; i < 633; i++ {
		status, fixed := "open", ""
		if i < 6 {
			status, fixed = "resolved", "3:1.0-2"
		}
		entries[fmt.Sprintf("CVE-2026-%05d", 10000+i)] = map[string]any{"releases": map[string]any{"trixie": map[string]string{"status": status, "fixed_version": fixed}}}
	}
	raw, _ := json.Marshal(map[string]any{"schemaVersion": linuxcve.BundleSchemaVersion, "provider": linuxcve.DebianProvider, "fetchedAt": now.Add(-time.Hour), "payload": map[string]any{"fixture": entries}})
	f := cveFixture(t, now, rows)
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, string(raw), now)
	for i := 0; i < 2; i++ {
		w, out := readCVEFixture(t, f, state, nil)
		if w.Code != 200 || out.Report == nil {
			t.Fatal("full fixture", w.Code)
		}
		r := out.Report
		if r.Continuation.State != "complete" || r.Coverage.CompletedCheckCount != 633 || r.Coverage.MatchedWarningCount != 6 || r.UnassessedRecordCount != 627 || len(r.Findings) != 6 || !r.Truncated || r.Continuation.Revision != 1 || i == 1 && r.Continuation.AdvancedCheckCount != 0 {
			t.Fatal("cached full fixture counts", r.Coverage, r.UnassessedRecordCount)
		}
	}
}

func TestLinuxCVEConcurrentContinuationReadIsExplicitlyBusy(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, continuationBundle(t, now, 2017), now)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	state.comparator = &callbackCVEComparator{once: func() { close(entered); <-release }, delegate: debianversion.Comparator{}}
	app := setup(t)
	app.linuxCVE = state
	handler := operatorHandler{app: app}
	path := "/api/devices/" + f.view.DeviceID + "/security/cves"
	first := httptest.NewRecorder()
	go func() { defer close(done); handler.linuxCVEAPI(first, httptest.NewRequest("GET", path, nil)) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("first assessment did not enter comparator")
	}
	second := httptest.NewRecorder()
	handler.linuxCVEAPI(second, httptest.NewRequest("GET", path, nil))
	close(release)
	<-done
	if second.Code != 429 || second.Header().Get("Retry-After") != "2" || first.Code != 200 {
		t.Fatal("concurrent assessment was not bounded", first.Code, second.Code)
	}
	w, out := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || out.Report == nil || out.Report.Continuation.State != "complete" || out.Report.Coverage.CompletedCheckCount != 2017 || out.Report.Continuation.Revision != 2 {
		t.Fatal("busy read consumed or duplicated progress", w.Code)
	}
}

type deadlineCVEComparator struct{}

func (deadlineCVEComparator) Compare(ctx context.Context, _, _ string) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}
func TestLinuxCVEBlockedStepRetainsCommittedPrefixWithoutResaving(t *testing.T) {
	now := time.Now().UTC()
	f := cveFixture(t, now, fixtureCVEPackages())
	state := newTestLinuxCVEState(t, f, func() time.Time { return now })
	importContinuation(t, state, continuationBundle(t, now, 2017), now)
	store := &failingCVEProgress{inner: state.progress}
	state.progress = store
	w, first := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || first.Report == nil || store.saves != 1 {
		t.Fatal("initial prefix", w.Code)
	}
	state.comparator = deadlineCVEComparator{}
	w, blocked := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || blocked.Report == nil || blocked.Report.Continuation.State != "blocked" || blocked.Report.Continuation.AdvancedCheckCount != 0 || blocked.Report.Continuation.Revision != 1 || blocked.Report.Continuation.Reason != "evaluation_canceled_or_timed_out" || blocked.Report.Coverage.CompletedCheckCount != 2000 || blocked.Report.Coverage.MatchedWarningCount != 2000 || len(blocked.Report.Findings) != 100 || store.saves != 1 {
		t.Fatal("blocked step dropped or claimed new progress", w.Code, w.Body.String())
	}
	state.comparator = debianversion.Comparator{}
	w, complete := readCVEFixture(t, f, state, nil)
	if w.Code != 200 || complete.Report == nil || complete.Report.Continuation.State != "complete" || complete.Report.Continuation.Revision != 2 || complete.Report.Coverage.CompletedCheckCount != 2017 || store.saves != 2 {
		t.Fatal("explicit refresh could not resume blocked step", w.Code)
	}
}
