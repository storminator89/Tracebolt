package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/analysis"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"net/http"
	"time"
)

const maxCaseAnalysisPreviews = 128
const caseAnalysisPreviewAge = 2 * time.Minute

type caseAnalysisPreview struct {
	SchemaVersion  string    `json:"schemaVersion"`
	CaseID         string    `json:"caseId"`
	ConfigRevision string    `json:"configRevision"`
	BaseURL        string    `json:"baseURL"`
	EndpointOrigin string    `json:"endpointOrigin"`
	Model          string    `json:"model"`
	PacketJSON     string    `json:"packetJSON"`
	PacketSHA256   string    `json:"packetSHA256"`
	ServerNow      time.Time `json:"serverNow"`
	ValidUntil     time.Time `json:"validUntil"`
	PreviewToken   string    `json:"previewToken"`
}

// Ephemeral admission metadata only. A preview is neither durable consent nor
// authority for other data, another case, provider revision or operator session.
type caseAnalysisPermit struct {
	Session, CaseID, Revision, Digest string
	Until                             time.Time
}

func caseAnalysisSession(r *http.Request) string {
	if op, ok := operatorContext(r); ok {
		return op.session.ID
	}
	// The development surface already has its own random instance CSRF boundary;
	// it must not manufacture a real operator session or bypass the LAN wrapper.
	return "development"
}

func caseAnalysisDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func failCaseAnalysisChanged(w http.ResponseWriter) {
	fail(w, 409, "analysis_preview_changed", "The packet, provider or review changed or expired. Review the exact packet again; no automatic retry was made.")
}

// caseAnalysisSnapshot never accepts evidence from the browser. It uses the
// existing BuildPacket provenance, duplicate, field and byte gates unchanged.
// json.Marshal is the exact canonical data-message encoding used by Service.
func (s *Server) caseAnalysisSnapshot(w http.ResponseWriter, id string) (model.Case, string, string, bool) {
	s.mu.RLock()
	profile := s.aiCollectionProfile
	s.mu.RUnlock()
	if profile != "" && profile != "basic-readonly-v1" {
		fail(w, 403, "evidence_export_not_approved", "This collection profile is not approved for AI export.")
		return model.Case{}, "", "", false
	}
	c, err := s.store.Case(id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, 404, "not_found", "Case not found.")
		return model.Case{}, "", "", false
	}
	if err != nil {
		s.internal(w)
		return model.Case{}, "", "", false
	}
	packet, err := analysis.BuildPacket(c, c.Evidence)
	if err != nil {
		fail(w, 422, "case_evidence_invalid", "The stored case evidence could not be safely prepared for analysis.")
		return model.Case{}, "", "", false
	}
	encoded, err := json.Marshal(packet)
	if err != nil || len(encoded) > analysis.MaxPacketBytes {
		fail(w, 422, "case_evidence_invalid", "The stored case evidence could not be safely prepared for analysis.")
		return model.Case{}, "", "", false
	}
	digest := sha256.Sum256(encoded)
	return c, string(encoded), hex.EncodeToString(digest[:]), true
}

// previewCaseAnalysis prepares a bounded private display only: no provider call,
// credential readback, raw packet persistence or authority beyond one attempt.
func (s *Server) previewCaseAnalysis(w http.ResponseWriter, r *http.Request, id string) {
	var empty struct{}
	if !readObject(w, r, 256, []string{}, &empty) {
		return
	}
	_, encoded, digest, ok := s.caseAnalysisSnapshot(w, id)
	if !ok {
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	a := s.ai
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.persistenceCurrentLocked() {
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked. Review protected storage before use.")
		return
	}
	now := time.Now().UTC()
	for token, permit := range a.casePreviews {
		if !now.Before(permit.Until) {
			delete(a.casePreviews, token)
		}
	}
	if len(a.casePreviews) >= maxCaseAnalysisPreviews {
		fail(w, 429, "analysis_preview_capacity", "Too many pending reviews; wait for expiration.")
		return
	}
	until := now.Add(caseAnalysisPreviewAge)
	if op, ok := operatorContext(r); ok && op.session.ExpiresAt.Before(until) {
		until = op.session.ExpiresAt.UTC()
	}
	if !now.Before(until) || r.Context().Err() != nil {
		failCaseAnalysisChanged(w)
		return
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		fail(w, 500, "configuration_error", "Review could not be prepared.")
		return
	}
	token := hex.EncodeToString(random[:])
	if a.casePreviews == nil {
		a.casePreviews = make(map[string]caseAnalysisPermit)
	}
	if _, exists := a.casePreviews[token]; exists {
		fail(w, 500, "configuration_error", "Review could not be prepared.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	a.casePreviews[token] = caseAnalysisPermit{Session: caseAnalysisSession(r), CaseID: id, Revision: a.config.Revision, Digest: digest, Until: until}
	view := caseAnalysisPreview{SchemaVersion: "tracebolt.case-analysis-preview.v1", CaseID: id, ConfigRevision: a.config.Revision, BaseURL: a.config.BaseURL, EndpointOrigin: a.config.EndpointOrigin, Model: a.config.Model, PacketJSON: encoded, PacketSHA256: digest, ServerNow: now, ValidUntil: until, PreviewToken: token}
	release()
	write(w, 200, view)
}
