package api

import (
	"localrmm/internal/aiconfig"
	"localrmm/internal/analysis"
	"net/http"
	"time"
)

func aiSettingsActor(r *http.Request) string {
	if op, ok := operatorContext(r); ok && op.session.Named() {
		return op.session.ActorID()
	}
	return "shared-administrator"
}

// configurePersistentAI is startup-only. Validation and restoration never make a
// provider call, manufacture approval, or replace the original consent time.
func (s *Server) configurePersistentAI(settings *aiconfig.Settings, keyed bool) error {
	if settings == nil {
		return nil
	}
	snap, err := settings.Snapshot()
	if err != nil {
		return err
	}
	a := s.ai
	a.mu.Lock()
	defer a.mu.Unlock()
	a.persistence = settings
	a.persistentKeyAllowed = keyed
	a.config = defaultAIConfig(snap.Provider.Revision)
	a.resetProactiveLocked(snap.Scope.Revision)
	if !snap.Configured {
		return nil
	}
	p := snap.Provider
	allowed := []string{}
	if p.AllowRemoteEvidence {
		allowed = append(allowed, p.ApprovedOrigin)
	}
	provider, err := analysis.NewOpenAIProvider(analysis.OpenAIConfig{BaseURL: p.BaseURL, Model: p.Model, APIKey: p.APIKey, APIKeyOrigin: p.ApprovedOrigin, AllowedHTTPSOrigins: allowed, Timeout: a.timeout, UseLegacyMaxTokens: p.UseLegacyMaxTokens})
	if err != nil {
		return err
	}
	a.config.Configured = true
	a.config.BaseURL = p.BaseURL
	a.config.Model = p.Model
	a.config.EndpointOrigin = provider.Identity().EndpointOrigin
	a.config.KeyConfigured = p.APIKey != ""
	a.config.AllowRemoteEvidence = p.AllowRemoteEvidence
	a.config.UseLegacyMaxTokens = p.UseLegacyMaxTokens
	a.config.Storage = "protected-file"
	a.config.ResetsOnRestart = false
	a.service = analysis.NewService(provider)
	if snap.Scope.Enabled {
		a.proactive = proactiveAIApproval{revision: snap.Scope.Revision, configRevision: snap.Scope.ConfigRevision, enabled: true, enabledAt: snap.Scope.EnabledAt, deviceIDs: append([]string{}, snap.Scope.DeviceIDs...)}
	}
	return nil
}
func (a *aiState) blockPersistenceLocked() {
	if a.activeCancel != nil {
		a.activeCancel()
	}
	a.proactive.enabled = false
	a.service = analysis.NewService(nil)
	a.config.Configured = false
}
func (a *aiState) persistenceCurrentLocked() bool {
	if a.config.Storage != "protected-file" {
		return true
	}
	if a.persistence == nil {
		a.blockPersistenceLocked()
		return false
	}
	snap, err := a.persistence.Snapshot()
	if err != nil || !snap.Configured || snap.Provider.Revision != a.config.Revision || snap.Provider.BaseURL != a.config.BaseURL || snap.Provider.Model != a.config.Model || snap.Scope.Enabled != a.proactive.enabled || snap.Scope.Revision != a.proactive.revision || snap.Scope.Enabled && snap.Scope.ConfigRevision != a.config.Revision {
		a.blockPersistenceLocked()
		return false
	}
	return true
}
func (a *aiState) persistScopeLocked(revision string, enabled bool, ids []string, at time.Time, actor string) error {
	if a.config.Storage != "protected-file" {
		return nil
	}
	scope := aiconfig.Scope{Revision: revision, ConfigRevision: a.config.Revision, Enabled: enabled, DeviceIDs: []string{}, DataScope: analysis.HealthDataScope}
	if enabled {
		scope.EnabledAt = at
		scope.ApprovedAt = at
		scope.ApprovedBy = actor
		scope.DeviceIDs = append([]string{}, ids...)
	}
	if err := a.persistence.SaveScope(a.config.Revision, scope, actor, at); err != nil {
		a.blockPersistenceLocked()
		return err
	}
	return nil
}
