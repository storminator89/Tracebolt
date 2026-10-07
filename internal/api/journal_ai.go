package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/analysis"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/health"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/proactivejournal"
	"localrmm/internal/store"
	"net/http"
	"strings"
	"time"
)

type journalAIState struct {
	source               proactivejournal.Source
	managerID, transport string
	blocked              bool
	results              map[string]*journalAIResult
	unrecordedCaptures   map[string]store.JournalAIAttempt
}
type journalAIResult struct {
	revision       string
	snapshotDigest string
	capture        proactivejournal.Capture
	result         analysis.Result
	timer          *time.Timer
}

func journalAIKey(device, incident string) string { return device + ":" + incident }
func (s *Server) journalAIReceiptCurrentLocked(r store.JournalAIReceipt) bool {
	j := s.journalAI
	a := s.ai
	if j == nil || j.blocked || !r.Enabled || r.ManagerID != j.managerID || r.Transport != j.transport || !a.config.Configured || a.config.Storage != "protected-file" || !a.persistenceCurrentLocked() {
		return false
	}
	snap, e := a.persistence.Snapshot()
	return e == nil && snap.Configured && snap.Provider.Revision == r.ProviderRevision && snap.Provider.CredentialGeneration == r.CredentialGeneration && snap.Provider.BaseURL == r.BaseURL && snap.Provider.Model == r.Model
}

// Cancellation is durable metadata, not another inference attempt. Only exact
// owned identities are retried, including after restart or receipt replacement.
func (s *Server) cancelJournalAttemptLocked(ctx context.Context, attempt store.JournalAIAttempt) error {
	if attempt.State == "canceled" || attempt.State == "expired" {
		return nil
	}
	if attempt.Capture == nil {
		return s.store.FinishJournalAI(ctx, attempt, "canceled")
	}
	if queued, err := s.store.QueueJournalAICancel(ctx, attempt); err != nil || !queued {
		return err
	}
	if s.journalAI.source.Now().Before(attempt.Capture.Description.ExpiresAt) {
		err := proactivejournal.Cancel(ctx, s.journalAI.source, *attempt.Capture)
		if err != nil && !errors.Is(err, journalrequest.ErrExpired) && !errors.Is(err, journalrequest.ErrConflict) && !errors.Is(err, journalrequest.ErrNotFound) {
			return err
		}
	}
	return s.store.ConfirmJournalAICancel(ctx, attempt)
}
func (s *Server) cancelJournalAILocked(parent context.Context, revision string) error {
	j := s.journalAI
	if j == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	unrecordedErr := s.retryUnrecordedJournalCapturesLocked(ctx)
	if s.ai.activeOwner == "journal" && s.ai.activeCancel != nil {
		s.ai.activeCancel()
	}
	for key, v := range j.results {
		if revision == "" || v.revision == revision {
			v.timer.Stop()
			delete(j.results, key)
		}
	}
	attempts, err := s.store.JournalAIAttempts(ctx)
	if err != nil {
		return err
	}
	first := unrecordedErr
	for _, attempt := range attempts {
		if revision != "" && attempt.Revision != revision && attempt.State != "cancel_pending" {
			continue
		}
		if err := s.cancelJournalAttemptLocked(ctx, attempt); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Source creation and attempt persistence are different stores. When the second
// write fails, keep the returned exact identity in RAM and retry cancellation.
// If both stores are unavailable, suppression cannot be promised across a crash.
func (s *Server) retryUnrecordedJournalCapturesLocked(ctx context.Context) error {
	j := s.journalAI
	var first error
	for key, attempt := range j.unrecordedCaptures {
		capture := *attempt.Capture
		var err error
		if j.source.Now().Before(capture.Description.ExpiresAt) {
			err = proactivejournal.Cancel(ctx, j.source, capture)
		}
		if err != nil && !errors.Is(err, journalrequest.ErrExpired) && !errors.Is(err, journalrequest.ErrConflict) && !errors.Is(err, journalrequest.ErrNotFound) {
			_ = s.store.RetainJournalAIFailedCapture(ctx, attempt, capture)
			if first == nil {
				first = err
			}
			continue
		}
		if err = s.store.ConfirmJournalAIFailedCaptureCanceled(ctx, attempt); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		delete(j.unrecordedCaptures, key)
	}
	return first
}
func (s *Server) drainJournalAICancellationsLocked(ctx context.Context) error {
	_ = s.store.ExpireJournalAIUnconfirmed(ctx, s.journalAI.source.Now().UTC())
	attempts, err := s.store.JournalAIAttempts(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, attempt := range attempts {
		if attempt.State != "cancel_pending" && !(attempt.State == "interrupted" && attempt.Capture != nil) {
			continue
		}
		if err := s.cancelJournalAttemptLocked(ctx, attempt); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Re-read authority after storage/page work. Neither a later certificate nor a
// clock rollback extends the original deadline that admitted this attempt.
func journalAIAuthority(ctx context.Context, m *healthMonitor, device string, floor, original time.Time) (time.Time, error) {
	started := time.Now()
	now := m.source.Now().UTC()
	inputs, err := m.source.HealthInputs(ctx, map[string][]string{}, now)
	allowed, valid := investigationAuthority(inputs)
	at := m.source.Now().UTC()
	if err != nil || ctx.Err() != nil || !valid || !allowed[device] || now.Before(floor) || at.Before(now) || at.Sub(now) > 5*time.Second || time.Since(started) > 5*time.Second {
		return time.Time{}, proactivejournal.ErrUnavailable
	}
	for _, input := range inputs {
		if input.DeviceID != device {
			continue
		}
		if !input.Authorized {
			return time.Time{}, proactivejournal.ErrUnavailable
		}
		deadline := input.AuthorityUntil
		if !original.IsZero() && original.Before(deadline) {
			deadline = original
		}
		if deadline.IsZero() || !at.Before(deadline) {
			return time.Time{}, proactivejournal.ErrUnavailable
		}
		return deadline, nil
	}
	return time.Time{}, proactivejournal.ErrUnavailable
}
func (h *operatorHandler) journalAIAPI(w http.ResponseWriter, r *http.Request) {
	j := h.app.journalAI
	if j == nil || h.app.health == nil {
		fail(w, 409, "journal_ai_unavailable", "Service log analysis requires complete Linux enrollment and an existing local journal grant.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Method == "GET" && r.ContentLength != 0 {
		fail(w, 400, "invalid_request", "Log analysis requires a bounded canonical request.")
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) == 6 && parts[4] == "source" && enrollmentcrypto.ValidID(parts[5], "agent_") {
		if r.Method != "GET" {
			fail(w, 405, "method_not_allowed", "Method is unsupported.")
			return
		}
		h.journalAISource(w, r, parts[5])
		return
	}
	if len(parts) == 6 && enrollmentcrypto.ValidID(parts[4], "agent_") && validID(parts[5]) {
		if r.Method != "GET" {
			fail(w, 405, "method_not_allowed", "Method is unsupported.")
			return
		}
		h.journalAIResult(w, r, parts[4], parts[5])
		return
	}
	if r.URL.Path != "/api/ai/journal" {
		fail(w, 404, "not_found", "Log analysis is unavailable.")
		return
	}
	if r.Method == "GET" {
		h.writeJournalAISettings(w, r)
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var in struct {
		DataScope            string          `json:"dataScope"`
		ExpectedRevision     string          `json:"expectedRevision"`
		ConfigRevision       string          `json:"configRevision"`
		Enabled              bool            `json:"enabled"`
		BaseURL              string          `json:"baseURL"`
		Model                string          `json:"model"`
		Targets              json.RawMessage `json:"targets"`
		LookbackMinutes      int             `json:"lookbackMinutes"`
		AcknowledgeCapture   bool            `json:"acknowledgeCapture"`
		AcknowledgeExport    bool            `json:"acknowledgeExport"`
		AcknowledgePlaintext bool            `json:"acknowledgePlaintext"`
	}
	if !readObject(w, r, 16384, []string{"dataScope", "expectedRevision", "configRevision", "enabled", "baseURL", "model", "targets", "lookbackMinutes", "acknowledgeCapture", "acknowledgeExport", "acknowledgePlaintext"}, &in) {
		return
	}
	var raws []json.RawMessage
	if in.DataScope != proactivejournal.DataScope || json.Unmarshal(in.Targets, &raws) != nil || raws == nil || len(raws) > proactivejournal.MaxTargets || len(in.ExpectedRevision) > 64 || len(in.ConfigRevision) > 64 || len(in.BaseURL) > 512 || len(in.Model) > 128 {
		fail(w, 400, "journal_ai_scope_invalid", "Choose a bounded exact service scope.")
		return
	}
	if in.Enabled && in.LookbackMinutes != 5 && in.LookbackMinutes != 15 {
		fail(w, 400, "journal_ai_scope_invalid", "Choose a 5 or 15 minute incident window.")
		return
	}
	targets := []proactivejournal.Target{}
	seen := map[string]bool{}
	for _, raw := range raws {
		var t proactivejournal.Target
		if !journalObject(raw, []string{"deviceId", "unit", "generation"}, &t) || !enrollmentcrypto.ValidID(t.DeviceID, "agent_") || !proactivejournal.ValidUnit(t.Unit) || journalgeneration.Validate(t.Generation) != nil || seen[t.DeviceID+":"+t.Unit] {
			fail(w, 400, "journal_ai_scope_invalid", "Exact device, service and policy generation are required.")
			return
		}
		seen[t.DeviceID+":"+t.Unit] = true
		targets = append(targets, t)
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	m := h.app.health
	m.mu.Lock()
	defer m.mu.Unlock()
	a := h.app.ai
	a.mu.Lock()
	defer a.mu.Unlock()
	old, e := h.app.store.JournalAIReceipt(r.Context())
	if e != nil {
		fail(w, 503, "journal_ai_unavailable", "Log analysis settings are unavailable.")
		return
	}
	if old.Revision != in.ExpectedRevision || a.config.Revision != in.ConfigRevision {
		fail(w, 409, "config_revision_mismatch", "Provider or log scope changed. Review it again.")
		return
	}
	rev, e := store.JournalAIRevision()
	if e != nil {
		fail(w, 503, "journal_ai_unavailable", "Settings are unavailable.")
		return
	}
	now := j.source.Now().UTC()
	next := store.JournalAIReceipt{Revision: rev, Targets: []proactivejournal.Target{}, DataScope: proactivejournal.DataScope, ManagerID: j.managerID, Transport: j.transport}
	if in.Enabled {
		if !in.AcknowledgeCapture || !in.AcknowledgeExport || j.transport == "http-test" && !in.AcknowledgePlaintext || !a.config.Configured || a.config.Storage != "protected-file" || !a.persistenceCurrentLocked() || len(targets) == 0 || in.BaseURL != a.config.BaseURL || in.Model != a.config.Model {
			fail(w, 400, "journal_ai_approval_required", "Approve future captures and sensitive log export to this exact saved provider; plaintext transport needs separate acknowledgement.")
			return
		}
		snap, e := a.persistence.Snapshot()
		if e != nil {
			fail(w, 503, "journal_ai_unavailable", "Saved provider cannot be verified.")
			return
		}
		inputs, e := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
		allowed, valid := investigationAuthority(inputs)
		if e != nil || !valid {
			fail(w, 503, "journal_ai_unavailable", "Device authority cannot be verified.")
			return
		}
		for _, input := range inputs {
			if input.AuthorityUntil.IsZero() || !now.Before(input.AuthorityUntil) {
				delete(allowed, input.DeviceID)
			}
		}
		for _, target := range targets {
			if !allowed[target.DeviceID] || proactivejournal.CheckTarget(r.Context(), j.source, target, now) != nil {
				fail(w, 409, "journal_ai_source_changed", "A selected local journal grant is unavailable or changed. Refresh its policy.")
				return
			}
		}
		next.Enabled = true
		next.ProviderRevision = snap.Provider.Revision
		next.CredentialGeneration = snap.Provider.CredentialGeneration
		next.BaseURL = snap.Provider.BaseURL
		next.Model = snap.Provider.Model
		next.Targets = targets
		next.LookbackMinutes = in.LookbackMinutes
		next.CaptureAcknowledged = true
		next.ExportAcknowledged = true
		next.PlaintextAcknowledged = in.AcknowledgePlaintext
		next.ApprovedBy = aiSettingsActor(r)
		next.ApprovedAt = now
	}
	if !operatorStillActive(w, r) {
		return
	}
	if e = h.app.store.SaveJournalAIReceipt(r.Context(), old.Revision, next); e != nil {
		if errors.Is(e, store.ErrJournalAIScope) || errors.Is(e, store.ErrJournalAIConflict) {
			fail(w, 409, "journal_ai_scope_invalid", "The selected scope cannot be saved. Review the window, services and current revision.")
			return
		}
		j.blocked = true
		h.app.cancelJournalAILocked(context.WithoutCancel(r.Context()), old.Revision)
		if errors.Is(e, store.ErrJournalAIFenceUnconfirmed) {
			fail(w, 503, "journal_ai_durable_stop_unconfirmed", "Log export is blocked in this process, but a durable stop could not be confirmed. Do not restart until storage and the saved scope have been reviewed.")
			return
		}
		fail(w, 503, "journal_ai_unavailable", "The saved change could not be confirmed. Log export is blocked; review storage before restarting.")
		return
	}
	cancelErr := h.app.cancelJournalAILocked(r.Context(), old.Revision)
	pending, pendingErr := h.app.store.JournalAICancellationPending(r.Context())
	unknown, unknownErr := h.app.store.JournalAIUnconfirmedCapture(r.Context())
	release()
	if len(j.unrecordedCaptures) != 0 || unknown || unknownErr != nil {
		fail(w, 503, "journal_ai_capture_stop_unconfirmed", "The scope change was saved, but local capture suppression and its durable metadata remain unconfirmed. Affected captures cannot be sent to AI. Keep this manager running for exact cancellation retries; review storage before restarting.")
		return
	}
	write(w, 200, map[string]any{"saved": true, "revision": rev, "enabled": next.Enabled, "cancellationPending": pending || cancelErr != nil || pendingErr != nil})
}
func (h *operatorHandler) journalAISource(w http.ResponseWriter, r *http.Request, id string) {
	m := h.app.health
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.source.Now().UTC()
	inputs, e := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
	allowed, valid := investigationAuthority(inputs)
	if e != nil || !valid || !allowed[id] {
		fail(w, 404, "journal_ai_unavailable", "Device is unavailable.")
		return
	}
	view, e := h.app.journalAI.source.JournalGenerationStatus(r.Context(), id, now)
	if e != nil {
		fail(w, 409, "journal_ai_source_changed", "A fresh local journal policy report is required.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, map[string]any{"deviceId": id, "generation": view, "serverNow": h.app.journalAI.source.Now().UTC()})
}
func (h *operatorHandler) writeJournalAISettings(w http.ResponseWriter, r *http.Request) {
	m := h.app.health
	m.mu.Lock()
	defer m.mu.Unlock()
	a := h.app.ai
	a.mu.Lock()
	defer a.mu.Unlock()
	j := h.app.journalAI
	receipt, e := h.app.store.JournalAIReceipt(r.Context())
	if e != nil {
		fail(w, 503, "journal_ai_unavailable", "Log scope cannot be read.")
		return
	}
	now := m.source.Now().UTC()
	inputs, e := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
	allowed, valid := investigationAuthority(inputs)
	if e != nil || !valid {
		fail(w, 503, "journal_ai_unavailable", "Device authority cannot be read.")
		return
	}
	devices := []string{}
	deadlines := map[string]time.Time{}
	for _, v := range inputs {
		if allowed[v.DeviceID] && !v.AuthorityUntil.IsZero() && now.Before(v.AuthorityUntil) {
			devices = append(devices, v.DeviceID)
			deadlines[v.DeviceID] = v.AuthorityUntil
		}
	}
	// A saved provider alone is not a ready log scope. In particular, a new
	// retained local generation must visibly pause the older exact approval.
	ready := h.app.journalAIReceiptCurrentLocked(receipt)
	if ready {
		for _, target := range receipt.Targets {
			if !j.source.Now().Before(deadlines[target.DeviceID]) || proactivejournal.CheckTarget(r.Context(), j.source, target, now) != nil || !j.source.Now().Before(deadlines[target.DeviceID]) {
				ready = false
				break
			}
		}
	}
	if !operatorStillActive(w, r) {
		return
	}
	providerSaved := a.config.Configured && a.config.Storage == "protected-file" && a.persistenceCurrentLocked()
	pending, pendingErr := h.app.store.JournalAICancellationPending(r.Context())
	lookback := receipt.LookbackMinutes
	if lookback == 0 {
		lookback = 5
	}
	write(w, 200, map[string]any{"cancellationPending": pending || pendingErr != nil || len(j.unrecordedCaptures) != 0, "schemaVersion": "tracebolt.journal-ai-settings.v1", "revision": receipt.Revision, "enabled": receipt.Enabled, "ready": ready, "configRevision": a.config.Revision, "providerSaved": providerSaved, "baseURL": a.config.BaseURL, "model": a.config.Model, "targets": receipt.Targets, "lookbackMinutes": lookback, "approvedAt": receipt.ApprovedAt, "devices": devices, "plaintext": j.transport == "http-test", "maxTargets": proactivejournal.MaxTargets, "maxAnalysesPerHour": proactivejournal.MaxAnalysesPerHour, "maxRows": proactivejournal.MaxRows, "maxMessageBytes": analysis.MaxJournalMessageBytes, "dataScope": proactivejournal.DataScope, "retention": "original-capture-expiry-memory-only", "blocked": j.blocked})
}
func findJournalTarget(r store.JournalAIReceipt, device, unit string) (proactivejournal.Target, bool) {
	for _, t := range r.Targets {
		if t.DeviceID == device && t.Unit == unit {
			return t, true
		}
	}
	return proactivejournal.Target{}, false
}

// runJournalAIStep is a bounded fixed workflow; a model cannot choose sources,
// issue queries or execute commands. Source and model content never enter SQLite.
func (s *Server) runJournalAIStep(parent context.Context, m *healthMonitor) error {
	j := s.journalAI
	if j == nil {
		return nil
	}
	step, stop := context.WithTimeout(parent, 5*time.Second)
	defer stop()
	m.mu.Lock()
	a := s.ai
	a.mu.Lock()
	unlock := func() { a.mu.Unlock(); m.mu.Unlock() }
	_ = s.retryUnrecordedJournalCapturesLocked(step)
	_ = s.drainJournalAICancellationsLocked(step)
	receipt, e := s.store.JournalAIReceipt(step)
	if e != nil {
		unlock()
		return e
	}
	if !s.journalAIReceiptCurrentLocked(receipt) {
		s.cancelJournalAILocked(step, "")
		unlock()
		return nil
	}
	admissionStarted := time.Now()
	now := j.source.Now().UTC()
	inputs, e := m.source.HealthInputs(step, map[string][]string{}, now)
	allowed, valid := investigationAuthority(inputs)
	if e != nil || !valid {
		unlock()
		return e
	}
	deadlines := map[string]time.Time{}
	for _, input := range inputs {
		if input.AuthorityUntil.IsZero() || !now.Before(input.AuthorityUntil) {
			delete(allowed, input.DeviceID)
		} else {
			deadlines[input.DeviceID] = input.AuthorityUntil
		}
	}
	attempts, e := s.store.JournalAIAttempts(step)
	if e != nil {
		unlock()
		return e
	}
	for _, attempt := range attempts {
		if attempt.State != "capturing" {
			continue
		}
		target, selected := findJournalTarget(receipt, attempt.DeviceID, attempt.Unit)
		if attempt.Revision != receipt.Revision || !selected || !allowed[attempt.DeviceID] || attempt.Capture == nil || attempt.ExpiresAt == nil || !now.Before(*attempt.ExpiresAt) {
			_ = s.cancelJournalAttemptLocked(step, attempt)
			continue
		}
		if a.busy {
			continue
		}
		page, err := proactivejournal.Read(step, j.source, target, *attempt.Capture, now)
		if errors.Is(err, proactivejournal.ErrPending) {
			continue
		}
		if err != nil {
			_ = s.cancelJournalAttemptLocked(step, attempt)
			continue
		}
		state, err := s.store.HealthState(step, attempt.DeviceID)
		if err != nil {
			unlock()
			return err
		}
		var incident health.Incident
		var check health.Check
		for _, x := range state.Incidents {
			if x.ID == attempt.IncidentID {
				incident = x
			}
		}
		for _, c := range state.View(attempt.DeviceID, j.source.Now()).Checks {
			if c.Key == incident.Key {
				check = c
			}
		}
		if !proactivejournal.MatchesWindow(*attempt.Capture, incident.OpenedAt, receipt.LookbackMinutes) || incident.ResolvedAt != nil || check.State != "open" || state.MaintenanceUntil != nil && now.Before(*state.MaintenanceUntil) {
			_ = s.cancelJournalAttemptLocked(step, attempt)
			continue
		}
		if !s.journalAIReceiptCurrentLocked(receipt) || !j.source.Now().Before(page.ExpiresAt) || !j.source.Now().Before(deadlines[attempt.DeviceID]) {
			_ = s.cancelJournalAttemptLocked(step, attempt)
			continue
		}
		sendAt := j.source.Now().UTC()
		started, err := s.store.StartJournalAIModel(step, attempt, sendAt)
		if err != nil {
			unlock()
			return err
		}
		if !started {
			continue
		}
		deadline, authorityErr := journalAIAuthority(step, m, attempt.DeviceID, now, deadlines[attempt.DeviceID])
		if authorityErr != nil || proactivejournal.CheckCapture(step, j.source, target, *attempt.Capture, page.SnapshotDigest, j.source.Now().UTC()) != nil || !s.journalAIReceiptCurrentLocked(receipt) {
			_ = s.cancelJournalAttemptLocked(step, attempt)
			continue
		}
		remaining := page.ExpiresAt.Sub(now) - time.Since(admissionStarted)
		if d := deadline.Sub(now) - time.Since(admissionStarted); d < remaining {
			remaining = d
		}
		checkedAt := j.source.Now().UTC()
		if d := page.ExpiresAt.Sub(checkedAt); d < remaining {
			remaining = d
		}
		if d := deadline.Sub(checkedAt); d < remaining {
			remaining = d
		}
		if remaining <= 0 || checkedAt.Before(now) || checkedAt.Sub(now) > 5*time.Second || time.Since(admissionStarted) > 5*time.Second {
			_ = s.cancelJournalAttemptLocked(step, attempt)
			continue
		}
		if remaining > analysis.MaxTimeout {
			remaining = analysis.MaxTimeout
		}
		ctx, cancel := context.WithTimeout(parent, remaining)
		a.busy = true
		a.activeID++
		run := a.activeID
		a.activeOwner = "journal"
		a.activeCancel = cancel
		service := a.service
		unlock()
		result, err := service.AnalyzeJournal(ctx, incident, check, page)
		cancel()
		finish, finishCancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
		defer finishCancel()
		m.mu.Lock()
		a.mu.Lock()
		defer unlock()
		defer func() {
			if a.activeID == run {
				a.busy = false
				a.activeCancel = nil
				a.activeOwner = ""
			}
		}()
		latest, readErr := s.store.JournalAIReceipt(finish)
		finalDeadline, authorityErr := journalAIAuthority(finish, m, attempt.DeviceID, now, deadline)
		if parent.Err() != nil || readErr != nil || latest.Revision != receipt.Revision || !s.journalAIReceiptCurrentLocked(latest) || authorityErr != nil || proactivejournal.CheckCapture(finish, j.source, target, *attempt.Capture, page.SnapshotDigest, j.source.Now().UTC()) != nil || !j.source.Now().Before(finalDeadline) {
			return s.cancelJournalAttemptLocked(finish, attempt)
		}
		if err != nil {
			return s.store.FinishJournalAI(finish, attempt, "invalid_response")
		}
		outcome := result.AI.Status
		if outcome == "not_configured" {
			outcome = "unavailable"
		}
		if e = s.store.FinishJournalAI(finish, attempt, outcome); e != nil {
			return e
		}
		if outcome == "completed" {
			key := journalAIKey(attempt.DeviceID, attempt.IncidentID)
			entry := &journalAIResult{revision: receipt.Revision, snapshotDigest: page.SnapshotDigest, capture: *attempt.Capture, result: result}
			entry.timer = time.AfterFunc(page.ExpiresAt.Sub(j.source.Now().UTC()), func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				if j.results[key] == entry {
					delete(j.results, key)
				}
			})
			j.results[key] = entry
		}
		return nil
	}
	// Claim before requesting any capture; an ambiguous creation is never retried.
	for _, target := range receipt.Targets {
		if !allowed[target.DeviceID] || proactivejournal.CheckTarget(step, j.source, target, now) != nil {
			continue
		}
		state, err := s.store.HealthState(step, target.DeviceID)
		if err != nil {
			unlock()
			return err
		}
		if state.MaintenanceUntil != nil && now.Before(*state.MaintenanceUntil) {
			continue
		}
		for _, x := range state.Incidents {
			if x.Kind != "service" || x.Target != target.Unit || x.ResolvedAt != nil || x.OpenedAt.Before(receipt.ApprovedAt) {
				continue
			}
			fresh := false
			for _, c := range state.View(target.DeviceID, now).Checks {
				if c.Key == x.Key && c.State == "open" {
					fresh = true
				}
			}
			if !fresh {
				continue
			}
			claimed, err := s.store.ClaimJournalAI(step, target.DeviceID, x, receipt.Revision, now)
			if err != nil {
				unlock()
				return err
			}
			if !claimed {
				continue
			}
			attempt := store.JournalAIAttempt{DeviceID: target.DeviceID, IncidentID: x.ID, Revision: receipt.Revision, Unit: x.Target, State: "preparing", CreatedAt: now}
			if _, err := journalAIAuthority(step, m, target.DeviceID, now, deadlines[target.DeviceID]); err != nil || !s.journalAIReceiptCurrentLocked(receipt) {
				_ = s.store.FinishJournalAI(step, attempt, "canceled")
				unlock()
				return nil
			}
			capture, err := proactivejournal.Begin(step, j.source, target, x.OpenedAt, receipt.LookbackMinutes, now)
			if err != nil {
				_ = s.store.FinishJournalAI(step, attempt, "unavailable")
				unlock()
				return nil
			}
			if err = s.store.SetJournalAICapture(step, attempt, capture); err != nil {
				j.blocked = true
				if j.unrecordedCaptures == nil {
					j.unrecordedCaptures = map[string]store.JournalAIAttempt{}
				}
				attempt.Capture = &capture
				attempt.ExpiresAt = &capture.Description.ExpiresAt
				j.unrecordedCaptures[journalAIKey(attempt.DeviceID, attempt.IncidentID)] = attempt
				cleanup, stopCleanup := context.WithTimeout(context.WithoutCancel(step), 5*time.Second)
				_ = s.store.RetainJournalAIFailedCapture(cleanup, attempt, capture)
				_ = s.retryUnrecordedJournalCapturesLocked(cleanup)
				stopCleanup()
				unlock()
				return err
			}
			unlock()
			return nil
		}
	}
	unlock()
	return nil
}
func (h *operatorHandler) journalAIResult(w http.ResponseWriter, r *http.Request, device, incident string) {
	m := h.app.health
	m.mu.Lock()
	defer m.mu.Unlock()
	a := h.app.ai
	a.mu.Lock()
	defer a.mu.Unlock()
	j := h.app.journalAI
	now := j.source.Now().UTC()
	deadline, e := journalAIAuthority(r.Context(), m, device, now, time.Time{})
	if e != nil {
		fail(w, 404, "journal_ai_unavailable", "Device is unavailable.")
		return
	}
	attempts, e := h.app.store.JournalAIAttempts(r.Context())
	if e != nil {
		fail(w, 503, "journal_ai_unavailable", "Log analysis is unavailable.")
		return
	}
	var found *store.JournalAIAttempt
	for i := range attempts {
		if attempts[i].DeviceID == device && attempts[i].IncidentID == incident {
			found = &attempts[i]
			break
		}
	}
	if found == nil {
		if !operatorStillActive(w, r) {
			return
		}
		write(w, 200, map[string]any{"schemaVersion": "tracebolt.journal-ai-result.v1", "state": "not_started", "serverNow": now, "expiresAt": nil, "result": nil})
		return
	}
	outcome := found.State
	var result *analysis.Result
	receipt, e := h.app.store.JournalAIReceipt(r.Context())
	entry := j.results[journalAIKey(device, incident)]
	target, selected := findJournalTarget(receipt, device, found.Unit)
	if e == nil && entry != nil && found.State == "completed" && h.app.journalAIReceiptCurrentLocked(receipt) && entry.revision == receipt.Revision && selected && proactivejournal.CheckCapture(r.Context(), j.source, target, entry.capture, entry.snapshotDigest, j.source.Now().UTC()) == nil {
		result = &entry.result
	}
	if result == nil && outcome == "completed" {
		outcome = "unavailable"
		if found.ExpiresAt != nil && !now.Before(*found.ExpiresAt) {
			outcome = "expired"
		}
	}
	raw, e := json.Marshal(map[string]any{"schemaVersion": "tracebolt.journal-ai-result.v1", "state": outcome, "serverNow": j.source.Now().UTC(), "expiresAt": found.ExpiresAt, "result": result})
	if e != nil || len(raw) > 64<<10 {
		fail(w, 503, "journal_ai_unavailable", "Log analysis response is unavailable.")
		return
	}
	defer clear(raw)
	if result != nil {
		deadline, e = journalAIAuthority(r.Context(), m, device, now, deadline)
		if e != nil || !h.app.journalAIReceiptCurrentLocked(receipt) || proactivejournal.CheckCapture(r.Context(), j.source, target, entry.capture, entry.snapshotDigest, j.source.Now().UTC()) != nil || !j.source.Now().Before(deadline) {
			fail(w, 409, "journal_ai_unavailable", "Log-backed analysis authority changed or expired.")
			return
		}
	}
	if !operatorStillActive(w, r) {
		return
	}
	if result != nil && (!j.source.Now().Before(entry.capture.Description.ExpiresAt) || !j.source.Now().Before(deadline)) {
		fail(w, 409, "journal_ai_unavailable", "Log-backed analysis expired.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
