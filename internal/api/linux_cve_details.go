package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/linuxcve"
	"net/http"
	"strings"
	"time"
)

// These exact POST routes are read-only. They deliberately do not acquire the
// shared-admin mutation grant, nor call progress.Save or EvaluateStep.
func (h *operatorHandler) queryLinuxCVEDetails(w http.ResponseWriter, r *http.Request, state *linuxCVEState, id, kind string) {
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(7 * time.Second))
	if len(r.Header.Values("Origin")) != 1 || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 || r.ContentLength <= 0 || len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_request", "A bounded unencoded JSON query is required.")
		return
	}
	fq := linuxcve.FindingsQuery{}
	bq := linuxcve.BinariesQuery{}
	assessmentID := ""
	revision := uint64(0)
	if kind == "findings" {
		if !readObject(w, r, 1024, []string{"assessmentId", "assessmentRevision", "fromCheck", "limit"}, &fq) {
			return
		}
		assessmentID, revision = fq.AssessmentID, fq.AssessmentRevision
		if fq.Limit < 1 || fq.Limit > linuxcve.MaxFindings {
			cveDetailError(w, linuxcve.ErrDetailQuery)
			return
		}
	} else {
		if !readObject(w, r, 1024, []string{"assessmentId", "assessmentRevision", "checkIndex", "fromBinary", "limit"}, &bq) {
			return
		}
		assessmentID, revision = bq.AssessmentID, bq.AssessmentRevision
		if bq.Limit < 1 || bq.Limit > linuxcve.MaxBinariesPerFinding {
			cveDetailError(w, linuxcve.ErrDetailQuery)
			return
		}
	}
	decoded, err := hex.DecodeString(assessmentID)
	if err != nil || len(decoded) != 32 || assessmentID != strings.ToLower(assessmentID) || revision == 0 {
		cveDetailError(w, linuxcve.ErrDetailQuery)
		return
	}
	if state == nil || state.source == nil {
		fail(w, 409, "inventory_unavailable", "A current complete inventory is required.")
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
	started := state.now().UTC()
	view, err := state.source.CompleteInventoryView(ctx, id, started)
	if err != nil {
		if operatorStillActive(w, r) {
			completeInventoryError(w, err)
		}
		return
	}
	if view.DeviceID != id {
		h.app.internal(w)
		return
	}
	if view.Complete == nil || view.Complete.State != "complete" {
		fail(w, 409, "inventory_unavailable", "A current complete inventory is required.")
		return
	}
	if _, err = completeView(view); err != nil {
		h.app.internal(w)
		return
	}
	m := view.Complete.Manifest
	if linuxcve.InventoryFreshness(m.CollectedAt, started) != "fresh" {
		fail(w, 409, "inventory_generation_expired", "Refresh the package inventory before continuing.")
		return
	}
	target := m.Release.Fields.Target()
	snapshot := state.feeds.Snapshot(target)
	if snapshot == nil {
		fail(w, 409, "cve_feed_changed", "Security data changed; refresh the assessment.")
		return
	}
	identity := linuxcve.AssessmentIdentity{DeviceID: id, Sequence: view.CompleteBinding.Sequence}
	key, err := linuxcve.AssessmentID(snapshot, m, identity)
	if err != nil {
		cveDetailError(w, linuxcve.ErrDetailUnavailable)
		return
	}
	if key != assessmentID {
		cveDetailError(w, linuxcve.ErrDetailBinding)
		return
	}
	if state.progress == nil {
		cveProgressError(w, linuxcve.ErrCheckpoint)
		return
	}
	rows, err := readLinuxCVERows(ctx, state, id, view)
	if err != nil {
		if operatorStillActive(w, r) {
			if ctx.Err() != nil {
				cveDetailError(w, linuxcve.ErrCanceled)
			} else {
				completeInventoryError(w, err)
			}
		}
		return
	}
	prior, err := state.progress.Load(key, state.now().UTC())
	if err != nil {
		cveProgressError(w, err)
		return
	}
	now := state.now().UTC()
	if now.Before(started) {
		fail(w, 503, "cve_clock_changed", "The manager clock changed; refresh the assessment.")
		return
	}
	var out any
	if kind == "findings" {
		page, e := linuxcve.QueryFindings(ctx, snapshot, m, rows, state.comparator, now, identity, prior, fq)
		err = e
		out = &page
	} else {
		page, e := linuxcve.QueryBinaries(ctx, snapshot, m, rows, state.comparator, now, identity, prior, bq)
		err = e
		out = &page
	}
	if !operatorStillActive(w, r) {
		return
	}
	if err != nil {
		cveDetailError(w, err)
		return
	}
	// Check current evidence and cache health again, without changing the original
	// checkpoint. An in-flight failure cannot refresh a client display lease.
	latest, err := state.source.CompleteInventoryView(ctx, id, state.now().UTC())
	if err != nil {
		if operatorStillActive(w, r) {
			completeInventoryError(w, err)
		}
		return
	}
	digest := ""
	if latest.Complete != nil {
		digest, _ = fullinventory.ManifestDigest(latest.Complete.Manifest)
	}
	if latest.DeviceID != id || latest.Complete == nil || latest.Complete.State != "complete" || latest.CompleteBinding != view.CompleteBinding || digest != view.CompleteBinding.ManifestHash {
		fail(w, 409, "inventory_generation_expired", "The package generation changed; refresh the assessment.")
		return
	}
	again, err := state.progress.Load(key, state.now().UTC())
	if err != nil {
		cveProgressError(w, err)
		return
	}
	if !bytes.Equal(prior, again) {
		cveProgressError(w, linuxcve.ErrCheckpoint)
		return
	}
	outgoing := state.now().UTC()
	metadata := snapshot.Metadata(outgoing)
	if outgoing.Before(now) || metadata.Freshness == "unknown" || metadata.ValidatedAt.After(outgoing) {
		fail(w, 503, "cve_clock_changed", "The manager clock changed; refresh the assessment.")
		return
	}
	if !outgoing.Before(m.CollectedAt.Add(inventoryledger.ObservationTTL)) {
		fail(w, 409, "inventory_generation_expired", "Refresh the package inventory before continuing.")
		return
	}
	if state.feeds.Snapshot(target) != snapshot {
		fail(w, 409, "cve_feed_changed", "Security data changed; refresh the assessment.")
		return
	}
	if ctx.Err() != nil {
		cveDetailError(w, linuxcve.ErrCanceled)
		return
	}
	switch page := out.(type) {
	case *linuxcve.FindingsPage:
		page.ServerNow = outgoing
	case *linuxcve.BinariesPage:
		page.ServerNow = outgoing
	}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > linuxcve.MaxResultBytes {
		fail(w, 503, "cve_response_unavailable", "The bounded CVE result is unavailable.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}

func cveDetailError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, linuxcve.ErrCheckpoint):
		cveProgressError(w, err)
	case errors.Is(err, linuxcve.ErrDetailQuery):
		fail(w, 400, "invalid_cve_detail_query", "The detail query is invalid.")
	case errors.Is(err, linuxcve.ErrDetailBinding):
		fail(w, 409, "cve_assessment_changed", "The assessment changed; refresh before reading details.")
	case errors.Is(err, linuxcve.ErrDetailIncomplete):
		fail(w, 409, "cve_assessment_incomplete", "Finish the assessment before reading all warning details.")
	case errors.Is(err, linuxcve.ErrCanceled):
		fail(w, 503, "cve_assessment_interrupted", "The detail read was interrupted; no page was accepted.")
	default:
		fail(w, 503, "cve_detail_unavailable", "The warning details could not be reconstructed from the completed assessment.")
	}
}
