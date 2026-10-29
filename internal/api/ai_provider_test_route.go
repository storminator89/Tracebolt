package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"localrmm/internal/analysis"
)

// testAIProvider sends only the analysis package's fixed synthetic fixture.
// It never reads cases or devices. The global slot is shared with manual and
// proactive analyses, and logout/config changes cancel the in-flight context.
// The provider may already have received bytes when cancellation occurs.
func (s *Server) testAIProvider(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ConfigRevision  string `json:"configRevision"`
		AcknowledgeTest bool   `json:"acknowledgeTest"`
	}
	if !readObject(w, r, 1024, []string{"configRevision", "acknowledgeTest"}, &input) {
		return
	}
	if !input.AcknowledgeTest || input.ConfigRevision == "" || len(input.ConfigRevision) > 64 {
		fail(w, 400, "invalid_ai_test", "Review the configured destination and explicitly confirm the synthetic test.")
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	s.ai.mu.Lock()
	if !s.ai.persistenceCurrentLocked() {
		s.ai.mu.Unlock()
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked. Review protected storage before use.")
		return
	}
	if input.ConfigRevision != s.ai.config.Revision {
		s.ai.mu.Unlock()
		fail(w, 409, "config_revision_mismatch", "Provider settings changed. Review the current destination before starting.")
		return
	}
	if !s.ai.config.Configured || s.ai.service == nil {
		s.ai.mu.Unlock()
		fail(w, 409, "ai_not_configured", "Configure a provider before testing.")
		return
	}
	if s.ai.busy {
		s.ai.mu.Unlock()
		fail(w, 409, "analysis_busy", "Another analysis is still running or canceling.")
		return
	}
	deadline := time.Now().Add(analysis.MaxTimeout)
	owner := ""
	if operator, exists := operatorContext(r); exists {
		owner = operator.session.ID
		if operator.session.ExpiresAt.Before(deadline) {
			deadline = operator.session.ExpiresAt
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	s.ai.busy = true
	s.ai.activeID++
	s.ai.activeOwner = owner
	run := s.ai.activeID
	s.ai.activeCancel = cancel
	service := s.ai.service
	s.ai.mu.Unlock()
	release() // Never hold the operator mutation gate over provider I/O.
	defer cancel()
	defer func() {
		s.ai.mu.Lock()
		if s.ai.activeID == run {
			s.ai.busy = false
			s.ai.activeCancel = nil
			s.ai.activeOwner = ""
		}
		s.ai.mu.Unlock()
	}()
	err := service.TestProvider(ctx)
	if !operatorStillActive(w, r) {
		return
	}
	if r.Context().Err() != nil {
		return
	}
	s.ai.mu.Lock()
	storageOK := s.ai.persistenceCurrentLocked()
	current := input.ConfigRevision == s.ai.config.Revision && s.ai.service == service && s.ai.config.Configured
	s.ai.mu.Unlock()
	if !storageOK {
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked. Review protected storage before use.")
		return
	}
	if !current {
		fail(w, 409, "config_revision_mismatch", "Provider settings changed. Review the current destination before starting.")
		return
	}
	// Storage validation may itself take time; recheck the operator immediately
	// before preparing the response. This is not proof of client receipt.
	if !operatorStillActive(w, r) || r.Context().Err() != nil {
		return
	}
	status := "unavailable"
	switch {
	case err == nil:
		status = "passed"
	case errors.Is(err, context.DeadlineExceeded):
		status = "timeout"
	case errors.Is(err, context.Canceled):
		status = "canceled"
	case errors.Is(err, analysis.ErrInvalidResponse), errors.Is(err, analysis.ErrResponseTooLarge):
		status = "invalid_response"
	case errors.Is(err, analysis.ErrBusy):
		status = "busy"
	}
	write(w, 200, struct {
		SchemaVersion  string `json:"schemaVersion"`
		ConfigRevision string `json:"configRevision"`
		Status         string `json:"status"`
	}{"tracebolt.ai-provider-test.v1", input.ConfigRevision, status})
}
