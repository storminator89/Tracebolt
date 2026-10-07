package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/aiconfig"
	"localrmm/internal/analysis"
	"localrmm/internal/store"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const defaultAIBaseURL = "http://127.0.0.1:11434/v1"

type publicAIConfig struct {
	PersistenceAvailable bool     `json:"persistenceAvailable"`
	PersistentKeyAllowed bool     `json:"persistentKeyAllowed"`
	Revision             string   `json:"revision"`
	Configured           bool     `json:"configured"`
	Provider             string   `json:"provider"`
	BaseURL              string   `json:"baseURL"`
	EndpointOrigin       string   `json:"endpointOrigin"`
	Model                string   `json:"model"`
	KeyConfigured        bool     `json:"keyConfigured"`
	UseLegacyMaxTokens   bool     `json:"useLegacyMaxTokens"`
	AllowRemoteEvidence  bool     `json:"allowRemoteEvidence"`
	Storage              string   `json:"storage"`
	ResetsOnRestart      bool     `json:"resetsOnRestart"`
	Busy                 bool     `json:"busy"`
	Limitations          []string `json:"limitations"`
}

type aiState struct {
	mu                   sync.Mutex
	proactive            proactiveAIApproval
	persistence          *aiconfig.Settings
	persistentKeyAllowed bool
	config               publicAIConfig
	service              *analysis.Service
	busy                 bool
	activeCancel         context.CancelFunc
	activeID             uint64
	activeOwner          string
	timeout              time.Duration // Internal bounded test seam, never user-controlled over HTTP.
}

func configRevision() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "cfg-" + hex.EncodeToString(b), nil
}
func defaultAIConfig(revision string) publicAIConfig {
	return publicAIConfig{Revision: revision, Provider: "openai-compatible", BaseURL: defaultAIBaseURL, EndpointOrigin: "http://127.0.0.1:11434", Storage: "memory-only", ResetsOnRestart: true, Limitations: []string{
		"Saving settings does not contact or test the provider. Settings and API keys are held only in server memory and reset on restart.",
		"Only literal loopback or an explicitly approved public HTTPS origin is supported. LAN/private destinations require a later reviewed policy.",
		"Loopback transport does not prove local inference: that server may forward requests elsewhere. Model provenance is a configured label, not weight verification.",
		"An explicit analysis sends the case title/summary and selected evidence title/source/detail/value/timestamps/quality. Operator notes, device names, IPs and unrelated telemetry are excluded.",
		"Evidence text is not secret-redacted. Review the case and the exact destination before starting an analysis.",
		"Manual case analysis has no command execution, extra collection, retry, fallback or remediation. Background health analysis requires a separate device/provider scope.",
	}}
}
func newAIState() (*aiState, error) {
	revision, err := configRevision()
	if err != nil {
		return nil, err
	}
	a := &aiState{config: defaultAIConfig(revision), service: analysis.NewService(nil), timeout: analysis.DefaultTimeout}
	a.resetProactiveLocked(revision)
	return a, nil
}
func (a *aiState) publicLocked() publicAIConfig {
	v := a.config
	v.Busy = a.busy
	v.PersistenceAvailable = a.persistence != nil
	v.PersistentKeyAllowed = a.persistence != nil && a.persistentKeyAllowed
	if v.Storage == "protected-file" {
		v.Limitations = append([]string{}, v.Limitations...)
		v.Limitations[0] = "Configuration and explicitly approved credentials are stored in a protected manager file, without an encryption-at-rest guarantee. Loading or saving does not contact the provider."
	}
	return v
}
func (s *Server) aiConfig(w http.ResponseWriter) {
	s.ai.mu.Lock()
	if !s.ai.persistenceCurrentLocked() {
		s.ai.mu.Unlock()
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked. Review protected storage before use.")
		return
	}
	view := s.ai.publicLocked()
	s.ai.mu.Unlock()
	write(w, 200, view)
}

type aiConfigRequest struct {
	AcknowledgeKeyStorage bool   `json:"acknowledgeKeyStorage,omitempty"`
	ExpectedRevision      string `json:"expectedRevision"`
	BaseURL               string `json:"baseURL"`
	Model                 string `json:"model"`
	APIKey                string `json:"apiKey"`
	ApprovedOrigin        string `json:"approvedOrigin"`
	AllowRemoteEvidence   bool   `json:"allowRemoteEvidence"`
	UseLegacyMaxTokens    bool   `json:"useLegacyMaxTokens"`
}

func (aiConfigRequest) String() string   { return "api.aiConfigRequest{secrets:redacted}" }
func (aiConfigRequest) GoString() string { return "api.aiConfigRequest{secrets:redacted}" }

// readObject rejects unknown and duplicate keys before typed decoding. API bodies
// accept scalar config fields only; no request can supply evidence or a provider.
func readObject(w http.ResponseWriter, r *http.Request, limit int64, fields []string, out any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			fail(w, 413, "body_too_large", "Request body exceeds this endpoint's byte limit.")
		} else {
			fail(w, 400, "invalid_body", "Request body could not be read.")
		}
		return false
	}
	invalid := func() bool {
		fail(w, 400, "invalid_json", "Exactly the expected typed fields are required.")
		return false
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return invalid()
	}
	expected := map[string]bool{}
	for _, field := range fields {
		expected[field] = true
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !expected[key] || seen[key] {
			return invalid()
		}
		seen[key] = true
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return invalid()
		}
		if bytes.Equal(value, []byte("null")) {
			return invalid()
		}
		if len(value) > 0 && value[0] == '"' {
			var text string
			if json.Unmarshal(value, &text) != nil || strings.ContainsRune(text, utf8.RuneError) {
				return invalid()
			}
		}
	}
	if _, err = decoder.Token(); err != nil || len(seen) != len(expected) {
		return invalid()
	}
	if _, err = decoder.Token(); err != io.EOF {
		return invalid()
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err = typed.Decode(out); err != nil {
		return invalid()
	}
	return operatorStillActive(w, r)
}
func (s *Server) authorizeJSONMutation(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Origin") != s.requiredOrigin(r) {
		fail(w, 403, "origin_required", "Same-origin header is required for local changes.")
		return false
	}
	tokens := r.Header.Values("X-CSRF-Token")
	if len(tokens) != 1 || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(s.requiredCSRF(r))) != 1 {
		fail(w, 403, "csrf_required", "A current CSRF token is required.")
		return false
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, 415, "json_required", "Content-Type must be application/json.")
		return false
	}
	return true
}
func (s *Server) aiMutation(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeJSONMutation(w, r) {
		return
	}
	switch r.URL.Path {
	case "/api/ai/config", "/api/ai/config/persistent":
		s.saveAIConfig(w, r)
		return
	case "/api/ai/config/clear":
		s.clearAIConfig(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "cases" || parts[3] != "analyze" || !validID(parts[2]) {
		fail(w, 404, "not_found", "Analysis endpoint not found.")
		return
	}
	s.analyzeCase(w, r, parts[2])
}
func (s *Server) saveAIConfig(w http.ResponseWriter, r *http.Request) {
	var input aiConfigRequest
	persistent := r.URL.Path == "/api/ai/config/persistent"
	fields := []string{"expectedRevision", "baseURL", "model", "apiKey", "approvedOrigin", "allowRemoteEvidence", "useLegacyMaxTokens"}
	if persistent {
		fields = append(fields, "acknowledgeKeyStorage")
	}
	if !readObject(w, r, 8192, fields, &input) {
		return
	}
	defer func() { input.APIKey = "" }() // Removes this reference; this is not secure memory erasure.
	invalid := func() {
		fail(w, 400, "invalid_ai_config", "Invalid provider settings. Use an exact loopback endpoint or explicitly approved public HTTPS origin, a model, and a fresh key where required.")
	}
	if len(input.ExpectedRevision) > 64 || input.Model == "" || len(input.ApprovedOrigin) > 512 {
		invalid()
		return
	}
	selected, err := url.Parse(input.BaseURL)
	if err != nil || input.ApprovedOrigin != selected.Scheme+"://"+selected.Host {
		invalid()
		return
	}
	loopback := selected.Hostname() == "127.0.0.1" || selected.Hostname() == "::1"
	if !loopback && (selected.Scheme != "https" || !input.AllowRemoteEvidence || input.APIKey == "") {
		invalid()
		return
	}
	// Protect public readbacks if a key was accidentally pasted into another field.
	if input.APIKey != "" && (strings.Contains(input.BaseURL, input.APIKey) || strings.Contains(input.Model, input.APIKey) || strings.Contains(input.ApprovedOrigin, input.APIKey)) {
		invalid()
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	s.ai.mu.Lock()
	defer s.ai.mu.Unlock()
	if input.ExpectedRevision != s.ai.config.Revision {
		fail(w, 409, "config_revision_mismatch", "Provider settings changed. Refresh them before continuing.")
		return
	}
	allowed := []string{}
	if !loopback {
		allowed = append(allowed, input.ApprovedOrigin)
	}
	provider, err := analysis.NewOpenAIProvider(analysis.OpenAIConfig{BaseURL: input.BaseURL, Model: input.Model, APIKey: input.APIKey, APIKeyOrigin: input.ApprovedOrigin, AllowedHTTPSOrigins: allowed, Timeout: s.ai.timeout, UseLegacyMaxTokens: input.UseLegacyMaxTokens})
	if err != nil {
		invalid()
		return
	}
	revision, err := configRevision()
	if err != nil {
		fail(w, 500, "configuration_error", "Provider settings could not be saved.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	if persistent && (s.ai.persistence == nil || input.APIKey != "" && (!input.AcknowledgeKeyStorage || !s.ai.persistentKeyAllowed)) {
		fail(w, 400, "ai_storage_approval_required", "Persistent provider storage requires explicit key-storage approval and HTTPS for a keyed provider.")
		return
	}
	if s.ai.persistence != nil {
		var err error
		if persistent {
			err = s.ai.persistence.SaveProvider(aiconfig.Provider{Revision: revision, BaseURL: input.BaseURL, Model: input.Model, APIKey: input.APIKey, ApprovedOrigin: input.ApprovedOrigin, AllowRemoteEvidence: input.AllowRemoteEvidence, UseLegacyMaxTokens: input.UseLegacyMaxTokens}, input.AcknowledgeKeyStorage, aiSettingsActor(r), time.Now().UTC())
		} else {
			err = s.ai.persistence.Forget(revision, revision, aiSettingsActor(r), time.Now().UTC())
		}
		if err != nil {
			s.ai.blockPersistenceLocked()
			fail(w, 503, "ai_settings_unavailable", "Saved AI settings could not be confirmed. Export is blocked; review protected storage before restarting.")
			return
		}
	}
	if s.ai.activeCancel != nil {
		s.ai.activeCancel()
	}
	view := defaultAIConfig(revision)
	if persistent {
		view.Storage = "protected-file"
		view.ResetsOnRestart = false
	}
	view.Configured = true
	view.BaseURL = input.BaseURL
	view.EndpointOrigin = provider.Identity().EndpointOrigin
	view.Model = input.Model
	view.KeyConfigured = input.APIKey != ""
	view.UseLegacyMaxTokens = input.UseLegacyMaxTokens
	view.AllowRemoteEvidence = input.AllowRemoteEvidence
	s.ai.resetProactiveLocked(revision)
	s.ai.config = view
	s.ai.service = analysis.NewService(provider)
	viewResult := s.ai.publicLocked()
	release()
	write(w, 200, viewResult)
}
func (s *Server) clearAIConfig(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedRevision string `json:"expectedRevision"`
	}
	if !readObject(w, r, 1024, []string{"expectedRevision"}, &input) {
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	s.ai.mu.Lock()
	defer s.ai.mu.Unlock()
	if input.ExpectedRevision != s.ai.config.Revision {
		fail(w, 409, "config_revision_mismatch", "Provider settings changed. Refresh them before continuing.")
		return
	}
	revision, err := configRevision()
	if err != nil {
		fail(w, 500, "configuration_error", "Provider settings could not be cleared.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	if s.ai.activeCancel != nil {
		s.ai.activeCancel()
	}
	if s.ai.persistence != nil {
		if err := s.ai.persistence.Forget(revision, revision, aiSettingsActor(r), time.Now().UTC()); err != nil {
			s.ai.blockPersistenceLocked()
			fail(w, 503, "ai_settings_unavailable", "Saved AI settings could not be cleared. Export is blocked; review protected storage before restarting.")
			return
		}
	}
	s.ai.resetProactiveLocked(revision)
	s.ai.config = defaultAIConfig(revision)
	s.ai.service = analysis.NewService(nil)
	viewResult := s.ai.publicLocked()
	release()
	write(w, 200, viewResult)
}

type caseAnalysisResponse struct {
	analysis.Result
	ConfigRevision string `json:"configRevision"`
	Superseded     bool   `json:"superseded"`
}

func (s *Server) analyzeCase(w http.ResponseWriter, r *http.Request, id string) {
	var input struct {
		ConfigRevision string `json:"configRevision"`
	}
	if !readObject(w, r, 1024, []string{"configRevision"}, &input) {
		return
	}
	// Instance policy is restored from trusted enrollment state. Client/case
	// tags cannot relabel a managed source as legacy/basic to permit export.
	s.mu.RLock()
	profile := s.aiCollectionProfile
	s.mu.RUnlock()
	if profile != "" && profile != "basic-readonly-v1" {
		fail(w, 403, "evidence_export_not_approved", "This collection profile is not approved for AI export.")
		return
	}
	c, err := s.store.Case(id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, 404, "not_found", "Case not found.")
		return
	}
	if err != nil {
		s.internal(w)
		return
	}
	if !operatorStillActive(w, r) {
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
	if s.ai.busy {
		s.ai.mu.Unlock()
		fail(w, 409, "analysis_busy", "Another analysis is still running or canceling.")
		return
	}
	deadline := time.Now().Add(analysis.MaxTimeout)
	owner := ""
	if operator, ok := operatorContext(r); ok {
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
	release()
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
	result, err := service.Analyze(ctx, c, c.Evidence)
	if operator, ok := operatorContext(r); ok && (operator.active == nil || !operator.active()) {
		fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
		return
	}
	if err != nil {
		fail(w, 422, "case_evidence_invalid", "The stored case evidence could not be safely prepared for analysis.")
		return
	}
	s.ai.mu.Lock()
	superseded := s.ai.config.Revision != input.ConfigRevision
	s.ai.mu.Unlock()
	write(w, 200, caseAnalysisResponse{Result: result, ConfigRevision: input.ConfigRevision, Superseded: superseded})
}

func (s *Server) aiConfigured() bool {
	s.ai.mu.Lock()
	defer s.ai.mu.Unlock()
	return s.ai.persistenceCurrentLocked() && s.ai.config.Configured
}
