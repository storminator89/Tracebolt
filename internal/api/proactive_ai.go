package api

import (
	"context"
	"errors"
	"localrmm/internal/analysis"
	"localrmm/internal/enrollmentcrypto"
	"net/http"
	"sort"
	"time"
)

// This approval is deliberately separate from manual AI configuration and local
// collection grants. It is never restored from SQLite or inferred from an agent
// profile. A provider/model/key change invalidates it, including in-flight work.
type proactiveAIApproval struct {
	revision       string
	configRevision string
	enabled        bool
	enabledAt      time.Time
	deviceIDs      []string
}

func (a *aiState) resetProactiveLocked(revision string) {
	a.proactive = proactiveAIApproval{revision: revision, deviceIDs: []string{}}
}

type proactiveDevice struct {
	ID string `json:"id"`
}
type proactiveAIView struct {
	SchemaVersion      string            `json:"schemaVersion"`
	Revision           string            `json:"revision"`
	Enabled            bool              `json:"enabled"`
	ConfigRevision     string            `json:"configRevision"`
	ProviderConfigured bool              `json:"providerConfigured"`
	BaseURL            string            `json:"baseURL"`
	Model              string            `json:"model"`
	DeviceIDs          []string          `json:"deviceIds"`
	AvailableDevices   []proactiveDevice `json:"availableDevices"`
	DataScope          string            `json:"dataScope"`
	LogsAllowed        bool              `json:"logsAllowed"`
	ResetsOnRestart    bool              `json:"resetsOnRestart"`
	MaxAnalysesPerHour int               `json:"maxAnalysesPerHour"`
	CooldownMinutes    int               `json:"cooldownMinutes"`
	MinIntervalSeconds int               `json:"minIntervalSeconds"`
	Reason             string            `json:"reason"`
}

func (h *operatorHandler) proactiveAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Method == http.MethodGet && r.ContentLength != 0 {
		fail(w, 400, "invalid_request", "Proactive settings require a bounded canonical request.")
		return
	}
	m := h.app.health
	if m == nil {
		fail(w, 409, "health_unavailable", "Proactive AI requires activated health checks.")
		return
	}
	if r.Method == http.MethodGet {
		h.writeProactiveAI(w, r)
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var in struct {
		ExpectedRevision string   `json:"expectedRevision"`
		ConfigRevision   string   `json:"configRevision"`
		Enabled          bool     `json:"enabled"`
		DeviceIDs        []string `json:"deviceIds"`
		ApprovedBaseURL  string   `json:"approvedBaseURL"`
		ApprovedModel    string   `json:"approvedModel"`
		DataScope        string   `json:"dataScope"`
		AcknowledgeData  bool     `json:"acknowledgeData"`
	}
	if !readObject(w, r, 8192, []string{"expectedRevision", "configRevision", "enabled", "deviceIds", "approvedBaseURL", "approvedModel", "dataScope", "acknowledgeData"}, &in) {
		return
	}
	if len(in.DeviceIDs) > 25 || in.DeviceIDs == nil || in.DataScope != analysis.HealthDataScope || len(in.ExpectedRevision) > 64 || len(in.ConfigRevision) > 64 || len(in.ApprovedBaseURL) > 512 || len(in.ApprovedModel) > 128 {
		fail(w, 400, "invalid_proactive_scope", "Choose the supported health-summary scope and devices.")
		return
	}
	seen := map[string]bool{}
	for _, id := range in.DeviceIDs {
		if !enrollmentcrypto.ValidID(id, "agent_") || seen[id] {
			fail(w, 400, "invalid_proactive_scope", "Choose distinct enrolled devices.")
			return
		}
		seen[id] = true
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	// Revocation must remain possible when the health source is unavailable.
	if !in.Enabled {
		a := h.app.ai
		a.mu.Lock()
		defer a.mu.Unlock()
		if in.ExpectedRevision != a.proactive.revision || in.ConfigRevision != a.config.Revision {
			fail(w, 409, "config_revision_mismatch", "Settings changed. Refresh before disabling.")
			return
		}
		revision, err := configRevision()
		if err != nil {
			fail(w, 500, "configuration_error", "Proactive settings could not be changed.")
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		if a.activeCancel != nil && a.activeOwner == "proactive" {
			a.activeCancel()
		}
		if err := a.persistScopeLocked(revision, false, nil, time.Now().UTC(), aiSettingsActor(r)); err != nil {
			fail(w, 503, "ai_settings_unavailable", "The saved disable could not be confirmed. Export is blocked; review protected storage.")
			return
		}
		a.resetProactiveLocked(revision)
		view := a.proactiveViewLocked([]proactiveDevice{})
		release()
		write(w, 200, view)
		return
	}
	// Lock order is health then AI. Provider calls hold neither mutex.
	m.mu.Lock()
	now := m.source.Now().UTC()
	inputs, err := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
	if err != nil {
		m.mu.Unlock()
		fail(w, 503, "health_unavailable", "Device authority is unavailable.")
		return
	}
	allowed, valid := investigationAuthority(inputs)
	if !valid {
		m.mu.Unlock()
		fail(w, 503, "health_unavailable", "Device authority is unavailable.")
		return
	}
	for _, input := range inputs {
		if input.AuthorityUntil.IsZero() || !now.Before(input.AuthorityUntil) {
			delete(allowed, input.DeviceID)
		}
	}
	a := h.app.ai
	a.mu.Lock()
	if in.ExpectedRevision != a.proactive.revision || in.ConfigRevision != a.config.Revision {
		a.mu.Unlock()
		m.mu.Unlock()
		fail(w, 409, "config_revision_mismatch", "Settings changed. Review the current destination and scope.")
		return
	}
	if in.Enabled {
		if !in.AcknowledgeData || !a.config.Configured || len(in.DeviceIDs) == 0 || in.ApprovedBaseURL != a.config.BaseURL || in.ApprovedModel != a.config.Model {
			a.mu.Unlock()
			m.mu.Unlock()
			fail(w, 400, "proactive_approval_required", "Approve the exact provider, model, devices and future health-summary transmissions.")
			return
		}
		for _, id := range in.DeviceIDs {
			if !allowed[id] {
				a.mu.Unlock()
				m.mu.Unlock()
				fail(w, 409, "health_unavailable", "A selected device is no longer authorized.")
				return
			}
		}
	}
	revision, err := configRevision()
	if err != nil {
		a.mu.Unlock()
		m.mu.Unlock()
		fail(w, 500, "configuration_error", "Proactive settings could not be changed.")
		return
	}
	if !operatorStillActive(w, r) {
		a.mu.Unlock()
		m.mu.Unlock()
		return
	}
	if a.activeCancel != nil && a.activeOwner == "proactive" {
		a.activeCancel()
	}
	if err := a.persistScopeLocked(revision, in.Enabled, in.DeviceIDs, now, aiSettingsActor(r)); err != nil {
		a.mu.Unlock()
		m.mu.Unlock()
		fail(w, 503, "ai_settings_unavailable", "Saved AI scope could not be confirmed. Export is blocked; review protected storage.")
		return
	}
	a.resetProactiveLocked(revision)
	if in.Enabled {
		sort.Strings(in.DeviceIDs)
		a.proactive = proactiveAIApproval{revision: revision, configRevision: a.config.Revision, enabled: true, enabledAt: now, deviceIDs: append([]string{}, in.DeviceIDs...)}
	}
	a.mu.Unlock()
	m.mu.Unlock()
	release()
	h.writeProactiveAI(w, r)
}
func (h *operatorHandler) writeProactiveAI(w http.ResponseWriter, r *http.Request) {
	m := h.app.health
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.source.Now().UTC()
	inputs, err := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
	if err != nil {
		fail(w, 503, "health_unavailable", "Device authority is unavailable.")
		return
	}
	allowed, valid := investigationAuthority(inputs)
	if !valid {
		fail(w, 503, "health_unavailable", "Device authority is unavailable.")
		return
	}
	for _, input := range inputs {
		if input.AuthorityUntil.IsZero() || !now.Before(input.AuthorityUntil) {
			delete(allowed, input.DeviceID)
		}
	}
	devices := []proactiveDevice{}
	for id := range allowed {
		devices = append(devices, proactiveDevice{ID: id})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	a := h.app.ai
	a.mu.Lock()
	if !a.persistenceCurrentLocked() {
		a.mu.Unlock()
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked. Review protected storage before use.")
		return
	}
	v := a.proactiveViewLocked(devices)
	a.mu.Unlock()
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, v)
}

func (a *aiState) proactiveViewLocked(devices []proactiveDevice) proactiveAIView {
	reason := "disabled"
	if !a.config.Configured {
		reason = "provider_not_configured"
	} else if a.proactive.enabled {
		reason = "enabled"
	}
	return proactiveAIView{SchemaVersion: "tracebolt.proactive-ai-settings.v1", Revision: a.proactive.revision, Enabled: a.proactive.enabled, ConfigRevision: a.config.Revision, ProviderConfigured: a.config.Configured, BaseURL: a.config.BaseURL, Model: a.config.Model, DeviceIDs: append([]string{}, a.proactive.deviceIDs...), AvailableDevices: devices, DataScope: analysis.HealthDataScope, LogsAllowed: false, ResetsOnRestart: a.config.ResetsOnRestart, MaxAnalysesPerHour: 6, CooldownMinutes: 30, MinIntervalSeconds: 60, Reason: reason}
}

// runProactiveMonitor is independent of the health evaluator: a slow model must
// not delay health transitions or recovery notifications. GETs never invoke it.
func (s *Server) runProactiveMonitor(ctx context.Context, m *healthMonitor) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var lastPrune time.Time
	for {
		// Local retention is independent of export approval and provider calls.
		// An idle/disabled manager still expires old model evidence.
		if now := time.Now().UTC(); lastPrune.IsZero() || now.Sub(lastPrune) >= time.Hour {
			cleanup, stop := context.WithTimeout(ctx, 5*time.Second)
			err := s.store.PruneHealthAnalyses(cleanup, now)
			stop()
			if err == nil {
				lastPrune = now
			}
		}
		_ = s.runProactiveAI(ctx, m)
		_ = s.runJournalAIStep(ctx, m)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Server) runProactiveAI(parent context.Context, m *healthMonitor) error {
	if parent.Err() != nil {
		return parent.Err()
	}
	// Fast disabled check means even scope reads are avoided until approval.
	a := s.ai
	a.mu.Lock()
	enabled := a.proactive.enabled && a.config.Configured && !a.busy
	a.mu.Unlock()
	if !enabled {
		return nil
	}
	m.mu.Lock()
	admissionStarted := time.Now()
	now := m.source.Now().UTC()
	inputs, err := m.source.HealthInputs(parent, map[string][]string{}, now)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	allowed, valid := investigationAuthority(inputs)
	if !valid {
		m.mu.Unlock()
		return errors.New("invalid proactive authority")
	}
	deadlines := map[string]time.Time{}
	for _, input := range inputs {
		if input.AuthorityUntil.IsZero() || !now.Before(input.AuthorityUntil) {
			delete(allowed, input.DeviceID)
		} else {
			deadlines[input.DeviceID] = input.AuthorityUntil
		}
	}
	a.mu.Lock()
	if !a.persistenceCurrentLocked() || !a.proactive.enabled || !a.config.Configured || a.busy || a.proactive.configRevision != a.config.Revision {
		a.mu.Unlock()
		m.mu.Unlock()
		return nil
	}
	approval := a.proactive
	service := a.service
	for _, id := range approval.deviceIDs {
		if !allowed[id] {
			continue
		}
		state, e := s.store.HealthState(parent, id)
		if e != nil {
			a.mu.Unlock()
			m.mu.Unlock()
			return e
		}
		// Stable newest-first incident iteration; no historical backfill before grant.
		for _, incident := range state.Incidents {
			if incident.ResolvedAt != nil || incident.OpenedAt.Before(approval.enabledAt) {
				continue
			}
			claim, e := s.store.ClaimHealthAnalysis(parent, id, incident.ID, approval.revision, approval.enabledAt, now)
			if e != nil {
				a.mu.Unlock()
				m.mu.Unlock()
				return e
			}
			if claim == nil {
				continue
			}
			// Recheck immediately before export. Admission/storage latency must not
			// extend the enrollment certificate's original authority deadline.
			checked := m.source.Now().UTC()
			fresh, checkErr := m.source.HealthInputs(parent, map[string][]string{}, checked)
			currentAllowed, unique := investigationAuthority(fresh)
			remaining := deadlines[id].Sub(now) - time.Since(admissionStarted)
			for _, input := range fresh {
				if input.DeviceID == id && (input.AuthorityUntil.IsZero() || !checked.Before(input.AuthorityUntil)) {
					delete(currentAllowed, id)
				}
				if input.DeviceID == id && input.AuthorityUntil.Sub(checked) < remaining {
					remaining = input.AuthorityUntil.Sub(checked)
				}
			}
			lastCheck := m.source.Now().UTC()
			if !a.persistenceCurrentLocked() || checkErr != nil || !unique || !currentAllowed[id] || checked.Before(now) || lastCheck.Before(checked) || lastCheck.Sub(now) > 5*time.Second || time.Since(admissionStarted) > 5*time.Second || remaining <= 0 || parent.Err() != nil {
				finishCtx, stop := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
				err := s.store.FinishHealthAnalysisFailure(finishCtx, id, incident.ID, approval.revision, "canceled", now)
				stop()
				a.mu.Unlock()
				m.mu.Unlock()
				return err
			}
			remaining -= lastCheck.Sub(checked)
			if remaining > analysis.MaxTimeout {
				remaining = analysis.MaxTimeout
			}
			deadline := time.Now().Add(remaining)
			ctx, cancel := context.WithDeadline(parent, deadline)
			a.busy = true
			a.activeID++
			run := a.activeID
			a.activeOwner = "proactive"
			a.activeCancel = cancel
			a.mu.Unlock()
			m.mu.Unlock()
			result, e := service.AnalyzeHealth(ctx, claim.Incident, claim.Check)
			cancel()
			// Disabling/config changes/revocation cannot make a superseded result visible.
			// Previously sent bytes cannot be recalled; there are no retries or fallbacks.
			m.mu.Lock()
			finished := m.source.Now().UTC()
			readStarted := time.Now()
			readCtx, stopRead := context.WithTimeout(parent, 5*time.Second)
			current, readErr := m.source.HealthInputs(readCtx, map[string][]string{}, finished)
			stopRead()
			confirmedAt := m.source.Now().UTC()
			finalAllowed, unique := investigationAuthority(current)
			stillAllowed := unique && finalAllowed[id] && !confirmedAt.Before(finished) && confirmedAt.Sub(finished) <= 5*time.Second && time.Since(readStarted) <= 5*time.Second
			for _, input := range current {
				if input.DeviceID == id && (input.AuthorityUntil.IsZero() || !confirmedAt.Before(input.AuthorityUntil)) {
					stillAllowed = false
				}
			}
			finished = confirmedAt
			a.mu.Lock()
			currentApproval := a.persistenceCurrentLocked() && a.proactive.enabled && a.proactive.revision == approval.revision && a.config.Revision == approval.configRevision
			// Keep approval validation and durable publication atomic with provider/
			// scope mutations. Only this bounded local write holds these locks;
			// the model call never does.
			defer func() {
				if a.activeID == run {
					a.busy = false
					a.activeCancel = nil
					a.activeOwner = ""
				}
				a.mu.Unlock()
				m.mu.Unlock()
			}()
			// Finalize even on process cancellation; a bounded local write never retries
			// inference. A failed finalization leaves durable running -> interrupted.
			finishCtx, stop := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
			defer stop()
			if !currentApproval || !stillAllowed || readErr != nil || finished.Before(now) || parent.Err() != nil {
				at := finished
				if at.Before(now) {
					at = now
				}
				return s.store.FinishHealthAnalysisFailure(finishCtx, id, incident.ID, approval.revision, "canceled", at)
			}
			if e != nil {
				return s.store.FinishHealthAnalysisFailure(finishCtx, id, incident.ID, approval.revision, "unavailable", finished)
			}
			return s.store.CompleteHealthAnalysis(finishCtx, id, incident.ID, approval.revision, result, finished)
		}
	}
	a.mu.Unlock()
	m.mu.Unlock()
	return nil
}
