package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/linuxcve"
	"localrmm/internal/linuxcvefeed"
	"localrmm/internal/linuxpackages"
	"net/http"
	"strings"
	"time"
)

type linuxCVEInventorySource interface {
	CompleteInventoryView(context.Context, string, time.Time) (enrollmentstore.InventoryStatus, error)
	CompleteInventoryPage(context.Context, string, inventoryledger.PageRequest, time.Time) (enrollmentstore.InventoryPageResult, error)
}

type linuxCVEState struct {
	feeds                linuxcve.Store
	cache                *linuxcvefeed.Cache
	source               linuxCVEInventorySource
	now                  func() time.Time
	imports, assessments chan struct{}
	comparator           assessment.VersionComparator
}

func newLinuxCVEState(source linuxCVEInventorySource, now func() time.Time) *linuxCVEState {
	return &linuxCVEState{source: source, now: now, imports: make(chan struct{}, 1), assessments: make(chan struct{}, 1), comparator: debianversion.Comparator{}}
}

type linuxCVEInventory struct {
	GenerationID string    `json:"generationId"`
	CollectedAt  time.Time `json:"collectedAt"`
	RowCount     uint64    `json:"rowCount"`
	Freshness    string    `json:"freshness"`
}

type linuxCVEView struct {
	SchemaVersion string             `json:"schemaVersion"`
	DeviceID      string             `json:"deviceId"`
	ServerNow     time.Time          `json:"serverNow"`
	Status        string             `json:"status"`
	ReasonCodes   []string           `json:"reasonCodes"`
	Inventory     *linuxCVEInventory `json:"inventory"`
	Feeds         linuxcve.StoreView `json:"feeds"`
	Report        *linuxcve.Result   `json:"report"`
}

// This operator-only surface reads an already authorized complete generation.
// Imports do not fetch remote URLs; explicit sync uses one fixed official URL.
// The protected persistent cache is separate from the older offline catalog.
// Neither path schedules work, runs endpoint commands, or updates packages.
func (h *operatorHandler) linuxCVEAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_query", "Query parameters are unsupported.")
		return
	}
	h.app.mu.RLock()
	state := h.app.linuxCVE
	h.app.mu.RUnlock()
	if r.URL.Path == "/api/security/cves/sync" {
		if r.Method != "POST" {
			fail(w, 405, "method_not_allowed", "Method is unsupported.")
			return
		}
		if state == nil || state.cache == nil {
			fail(w, 404, "cve_not_configured", "Security data sync is unavailable for this profile.")
			return
		}
		h.syncLinuxCVE(w, r, state)
		return
	}
	if r.URL.Path == "/api/security/cves/import" {
		if r.Method != "POST" {
			fail(w, 405, "method_not_allowed", "Method is unsupported.")
			return
		}
		if state == nil {
			fail(w, 404, "cve_not_configured", "CVE imports require the complete Linux inventory profile.")
			return
		}
		h.importLinuxCVE(w, r, state)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "security" || parts[5] != "cves" {
		fail(w, 404, "not_found", "CVE assessment is unavailable.")
		return
	}
	if r.Method != "GET" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_request", "This read does not accept a body.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	now := time.Now().UTC()
	if state != nil {
		now = state.now().UTC()
	}
	out := linuxCVEView{SchemaVersion: "tracebolt.linux-cve-view.v1", DeviceID: parts[3], ServerNow: now, Status: "not_configured", ReasonCodes: []string{"complete_inventory_required"}, Feeds: (&linuxcve.Store{}).View(now)}
	if state == nil {
		devices, err := h.app.devices()
		if err != nil {
			h.app.internal(w)
			return
		}
		for _, d := range devices {
			if d.ID == parts[3] {
				writeLinuxCVE(w, r, out, nil)
				return
			}
		}
		fail(w, 404, "not_found", "Device is unavailable.")
		return
	}
	select {
	case state.assessments <- struct{}{}:
		defer func() { <-state.assessments }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "storage_busy", "CVE assessment is busy; retry shortly.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
	defer cancel()
	out.Feeds = state.feeds.View(now)
	view, err := state.source.CompleteInventoryView(ctx, parts[3], state.now().UTC())
	if err != nil {
		if operatorStillActive(w, r) {
			completeInventoryError(w, err)
		}
		return
	}
	if view.DeviceID != parts[3] {
		h.app.internal(w)
		return
	}
	if view.Complete == nil || view.Complete.State != "complete" {
		out.Status = "inventory_unavailable"
		out.ReasonCodes = []string{"current_complete_inventory_required"}
		writeLinuxCVE(w, r, out, state)
		return
	}
	m := view.Complete.Manifest
	if _, err = completeView(view); err != nil {
		h.app.internal(w)
		return
	}
	now = state.now().UTC()
	out.Inventory = &linuxCVEInventory{GenerationID: m.GenerationID, CollectedAt: m.CollectedAt, RowCount: m.ObservedCount, Freshness: linuxcve.InventoryFreshness(m.CollectedAt, now)}
	if out.Inventory.Freshness != "fresh" {
		out.Status = "inventory_unavailable"
		out.ReasonCodes = []string{"current_complete_inventory_required"}
		writeLinuxCVE(w, r, out, state)
		return
	}
	target := m.Release.Fields.Target()
	if m.Release.Quality != linuxpackages.Healthy || target != linuxpackages.Debian13 && target != linuxpackages.Ubuntu2404 {
		out.Status = "unsupported"
		out.ReasonCodes = []string{"release_not_supported"}
		writeLinuxCVE(w, r, out, state)
		return
	}
	snapshot, feedView := state.feeds.SnapshotView(target, now)
	out.Feeds = feedView
	if snapshot == nil {
		out.Status = "feed_missing"
		out.ReasonCodes = []string{"distribution_feed_missing"}
		writeLinuxCVE(w, r, out, state)
		return
	}
	rows, err := readLinuxCVERows(ctx, state, parts[3], view)
	if err != nil {
		if operatorStillActive(w, r) {
			completeInventoryError(w, err)
		}
		return
	}
	now = state.now().UTC()
	result := linuxcve.Evaluate(ctx, snapshot, m, rows, state.comparator, now)
	out.Status = "evaluated"
	out.ReasonCodes = []string{}
	out.Report = &result
	if result.Status == "unavailable" {
		out.Status = "unavailable"
		out.ReasonCodes = append([]string{}, result.ReasonCodes...)
	}
	// Recheck endpoint authority/current generation after all pages/comparisons.
	latest, err := state.source.CompleteInventoryView(ctx, parts[3], state.now().UTC())
	if err != nil {
		if operatorStillActive(w, r) {
			completeInventoryError(w, err)
		}
		return
	}
	if latest.DeviceID != parts[3] || latest.Complete == nil || latest.Complete.State != "complete" || latest.CompleteBinding != view.CompleteBinding {
		fail(w, 409, "inventory_generation_expired", "The package generation changed; refresh the assessment.")
		return
	}
	writeLinuxCVE(w, r, out, state)
}

func readLinuxCVERows(ctx context.Context, state *linuxCVEState, id string, view enrollmentstore.InventoryStatus) ([]linuxpackages.PackageRow, error) {
	m := view.Complete.Manifest
	if m.ObservedCount > fullinventory.MaxGenerationRows {
		return nil, inventoryledger.ErrInvalid
	}
	rows := make([]linuxpackages.PackageRow, 0, int(m.ObservedCount))
	cursor := ""
	seen := map[string]bool{}
	for pages := 0; pages <= fullinventory.MaxGenerationRows/inventoryledger.MaxPageRows; pages++ {
		if ctx.Err() != nil {
			return nil, inventoryledger.ErrExpired
		}
		page, err := state.source.CompleteInventoryPage(ctx, id, inventoryledger.PageRequest{GenerationID: m.GenerationID, Cursor: cursor, Limit: inventoryledger.MaxPageRows}, state.now().UTC())
		if err != nil {
			return nil, err
		}
		hash, err := fullinventory.ManifestDigest(page.Manifest)
		if err != nil || hash != view.CompleteBinding.ManifestHash || page.Binding != view.CompleteBinding || page.TotalRows != m.ObservedCount || page.SearchIncomplete || page.ScannedRows != len(page.Items) || len(page.Items) > inventoryledger.MaxPageRows || len(rows)+len(page.Items) > int(m.ObservedCount) {
			return nil, enrollmentstore.ErrStorage
		}
		rows = append(rows, page.Items...)
		if page.Exhausted {
			if uint64(len(rows)) != m.ObservedCount || page.NextCursor != "" {
				return nil, enrollmentstore.ErrStorage
			}
			return rows, nil
		}
		if len(page.Items) == 0 || page.NextCursor == "" || seen[page.NextCursor] {
			return nil, enrollmentstore.ErrStorage
		}
		seen[page.NextCursor] = true
		cursor = page.NextCursor
	}
	return nil, enrollmentstore.ErrStorage
}

func (h *operatorHandler) importLinuxCVE(w http.ResponseWriter, r *http.Request, state *linuxCVEState) {
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	if len(r.Header.Values("Origin")) != 1 || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 || r.ContentLength <= 0 || len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_cve_bundle", "A bounded unencoded JSON bundle is required.")
		return
	}
	if r.ContentLength > linuxcve.MaxBundleBytes {
		fail(w, 413, "cve_bundle_too_large", "The advisory bundle exceeds the fixed limit.")
		return
	}
	select {
	case state.imports <- struct{}{}:
		defer func() { <-state.imports }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "storage_busy", "Advisory import is busy; retry shortly.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	// A separate bounded import deadline avoids changing global request policy.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
	var candidate *linuxcve.Snapshot
	var durable *linuxcvefeed.Candidate
	var err error
	if state.cache != nil {
		durable, err = state.cache.PrepareImport(ctx, http.MaxBytesReader(w, r.Body, linuxcve.MaxBundleBytes), state.now().UTC())
	} else {
		candidate, err = linuxcve.Parse(ctx, http.MaxBytesReader(w, r.Body, linuxcve.MaxBundleBytes), state.now().UTC())
	}
	if !operatorStillActive(w, r) {
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	now := state.now().UTC()
	if err == nil && ctx.Err() == nil {
		if state.cache != nil {
			err = state.cache.Commit(durable, &state.feeds, now)
		} else {
			err = state.feeds.Replace(candidate, now)
		}
	}
	if err == nil && ctx.Err() != nil {
		err = linuxcve.ErrCanceled
	}
	if err != nil {
		reason := err.Error()
		if errors.Is(err, linuxcvefeed.ErrUncertain) || errors.Is(err, linuxcvefeed.ErrNotLoaded) {
			reason = "cache_commit_uncertain"
		}
		state.feeds.RecordFailure(now, reason)
		release()
		switch {
		case errors.Is(err, linuxcvefeed.ErrUncertain), errors.Is(err, linuxcvefeed.ErrNotLoaded):
			fail(w, 503, "cve_cache_uncertain", "The security-data save could not be confirmed. Restart the manager to reload its persisted snapshot before updating again.")
		case errors.Is(err, linuxcvefeed.ErrIO), errors.Is(err, linuxcvefeed.ErrUnsafe), errors.Is(err, linuxcvefeed.ErrLocked):
			fail(w, 503, "cve_cache_unavailable", "The security-data cache is unavailable; the existing in-memory snapshot was retained.")
		case errors.Is(err, linuxcve.ErrLimit):
			fail(w, 413, "cve_bundle_too_large", "The advisory bundle exceeds fixed limits.")
		case errors.Is(err, linuxcve.ErrRollback):
			fail(w, 409, "cve_bundle_older", "An older snapshot cannot replace the retained advisory snapshot.")
		case errors.Is(err, linuxcve.ErrCanceled):
			fail(w, 503, "cve_import_interrupted", "Advisory import was interrupted; the prior snapshot was retained.")
		default:
			fail(w, 400, "invalid_cve_bundle", "The advisory bundle is invalid; the prior snapshot was retained.")
		}
		return
	}
	release()
	if operatorStillActive(w, r) {
		write(w, 200, state.feeds.View(state.now().UTC()))
	}
}

func (h *operatorHandler) syncLinuxCVE(w http.ResponseWriter, r *http.Request, state *linuxCVEState) {
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var input struct{}
	if !readObject(w, r, 256, []string{}, &input) {
		return
	}
	select {
	case state.imports <- struct{}{}:
		defer func() { <-state.imports }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "storage_busy", "Security data is already updating; retry shortly.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(60 * time.Second))
	candidate, err := state.cache.FetchDebian(ctx, state.now().UTC())
	if !operatorStillActive(w, r) {
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	now := state.now().UTC()
	if err == nil && ctx.Err() == nil {
		err = state.cache.Commit(candidate, &state.feeds, now)
	}
	if err == nil && ctx.Err() != nil {
		err = linuxcve.ErrCanceled
	}
	if err != nil {
		reason := "sync_failed"
		uncertain := errors.Is(err, linuxcvefeed.ErrUncertain) || errors.Is(err, linuxcvefeed.ErrNotLoaded)
		if uncertain {
			reason = "cache_commit_uncertain"
		}
		state.feeds.RecordFailure(now, reason)
		release()
		if uncertain {
			fail(w, 503, "cve_cache_uncertain", "The security-data save could not be confirmed. Restart the manager to reload its persisted snapshot before updating again.")
			return
		}
		fail(w, 503, "cve_sync_failed", "Security data could not be updated. The last validated snapshot was retained.")
		return
	}
	release()
	if operatorStillActive(w, r) {
		write(w, 200, state.feeds.View(state.now().UTC()))
	}
}

func writeLinuxCVE(w http.ResponseWriter, r *http.Request, out linuxCVEView, state *linuxCVEState) {
	if state != nil {
		out.ServerNow = state.now().UTC()
	}
	// Refresh age labels against one outgoing clock without advancing the
	// original download, inventory or assessment timestamps, or changing which
	// immutable advisory snapshot was used during evaluation.
	feedFreshness := func(m *linuxcve.FeedMetadata) {
		m.Freshness = "fresh"
		if out.ServerNow.Before(m.FetchedAt) || out.ServerNow.Before(m.ValidatedAt) || !m.ExpiresAt.After(m.FetchedAt) {
			m.Freshness = "unknown"
		} else if !out.ServerNow.Before(m.ExpiresAt) {
			m.Freshness = "stale"
		}
	}
	for i := range out.Feeds.Snapshots {
		feedFreshness(&out.Feeds.Snapshots[i])
	}
	if out.Inventory != nil {
		out.Inventory.Freshness = linuxcve.InventoryFreshness(out.Inventory.CollectedAt, out.ServerNow)
	}
	if out.Report != nil {
		if out.Report.AssessedAt.After(out.ServerNow) {
			fail(w, 503, "cve_clock_changed", "The manager clock changed; refresh the assessment.")
			return
		}
		if out.Report.Feed != nil {
			feedFreshness(out.Report.Feed)
			out.Report.Freshness = out.Report.Feed.Freshness
		}
		if out.Inventory != nil {
			out.Report.InventoryFreshness = out.Inventory.Freshness
		}
		if out.Report.Freshness == "unknown" || out.Report.InventoryFreshness == "unknown" {
			fail(w, 503, "cve_clock_changed", "The manager clock changed; refresh the assessment.")
			return
		}
		if out.Report.Status != "unavailable" && (out.Report.Freshness == "stale" || out.Report.InventoryFreshness == "stale") {
			out.Report.Status = "stale"
			if out.Report.Freshness == "stale" {
				out.Report.ReasonCodes = appendCVEReason(out.Report.ReasonCodes, "feed_stale")
			}
			if out.Report.InventoryFreshness == "stale" {
				out.Report.ReasonCodes = appendCVEReason(out.Report.ReasonCodes, "inventory_stale")
			}
		}
	}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > 256<<10 {
		fail(w, 503, "cve_response_unavailable", "The bounded CVE result is unavailable.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	if state != nil && out.Report != nil && out.Inventory != nil && !state.now().UTC().Before(out.Inventory.CollectedAt.Add(inventoryledger.ObservationTTL)) {
		fail(w, 409, "inventory_generation_expired", "Refresh the package inventory before continuing.")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}

func appendCVEReason(reasons []string, value string) []string {
	for _, reason := range reasons {
		if reason == value {
			return reasons
		}
	}
	return append(reasons, value)
}
