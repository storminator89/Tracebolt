package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/analysis"
	"localrmm/internal/applicationcheck"
	"net/http"
	"time"
)

type networkReviewPreview struct {
	SchemaVersion  string    `json:"schemaVersion"`
	CheckID        string    `json:"checkId"`
	Kind           string    `json:"kind"`
	State          string    `json:"state"`
	Reason         string    `json:"reason"`
	ObservedAt     time.Time `json:"observedAt"`
	ValidUntil     time.Time `json:"validUntil"`
	SnapshotToken  string    `json:"snapshotToken"`
	ConfigRevision string    `json:"configRevision"`
	BaseURL        string    `json:"baseURL"`
	Model          string    `json:"model"`
}

// A preview is an ephemeral, session-bound single-use authority. Its deadline
// never extends the source freshness and its digest binds the original row.
type networkReviewPermit struct {
	Session, Digest, Revision string
	Until                     time.Time
}

// networkReviewSnapshot reads only the manager's already-retained observation.
// Its private generation is MAC-bound and never included in the model packet.
func (h *operatorHandler) networkReviewSnapshot(id string) (analysis.NetworkReview, time.Time, string, bool) {
	var view applicationcheck.View
	var generation string
	var ok bool
	if h.networkReviewFixture != nil {
		view, generation, ok = h.networkReviewFixture()
	} else if h.applicationCheckSettings != nil {
		view, generation, ok = h.applicationCheckSettings.ReviewStatus()
	} else if h.applicationChecks != nil {
		view, generation, ok = h.applicationChecks.Status(), "startup", true
	}
	if !ok || !view.Enabled || view.Vantage != "management_server" || view.MaxAgeSeconds <= 0 || view.MaxAgeSeconds > 7200 {
		return analysis.NetworkReview{}, time.Time{}, "", false
	}
	now := time.Now().UTC()
	if view.ServerNow.IsZero() || now.Sub(view.ServerNow) > 5*time.Second || view.ServerNow.Sub(now) > 5*time.Second {
		return analysis.NetworkReview{}, time.Time{}, "", false
	}
	var found *applicationcheck.Result
	for i := range view.Items {
		if view.Items[i].ID == id {
			if found != nil {
				return analysis.NetworkReview{}, time.Time{}, "", false
			}
			found = &view.Items[i]
		}
	}
	if found == nil || found.ObservedAt == nil {
		return analysis.NetworkReview{}, time.Time{}, "", false
	}
	x := analysis.NetworkReview{Kind: found.Kind, State: found.State, Reason: found.Reason, ObservedAt: found.ObservedAt.UTC()}
	until := x.ObservedAt.Add(time.Duration(view.MaxAgeSeconds) * time.Second)
	if !analysis.ValidNetworkReview(x) || x.ObservedAt.After(now) || !now.Before(until) {
		return analysis.NetworkReview{}, time.Time{}, "", false
	}
	return x, until, generation, true
}

func networkReviewToken(key [32]byte, id, generation, revision string, x analysis.NetworkReview, until time.Time) string {
	data, _ := json.Marshal(struct {
		ID, Generation, Revision string
		Observation              analysis.NetworkReview
		Until                    time.Time
	}{id, generation, revision, x, until})
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write([]byte("tracebolt.network-review.v1\x00"))
	_, _ = m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// Provider panics are untrusted and must not reach net/http's panic logger.
func safeNetworkReview(ctx context.Context, service *analysis.Service, x analysis.NetworkReview) (result analysis.Result, err error) {
	defer func() {
		if recover() != nil {
			result = analysis.Result{}
			err = analysis.ErrUnavailable
		}
	}()
	return service.AnalyzeNetworkReview(ctx, x)
}

func (h *operatorHandler) networkReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var in struct {
		CheckID        string `json:"checkId"`
		SnapshotToken  string `json:"snapshotToken"`
		ConfigRevision string `json:"configRevision"`
		Acknowledge    bool   `json:"acknowledge"`
	}
	fields := []string{"checkId"}
	run := r.URL.Path == "/api/ai/network-review/run"
	if run {
		fields = append(fields, "snapshotToken", "configRevision", "acknowledge")
	}
	if !readObject(w, r, 2048, fields, &in) {
		return
	}
	if len(in.CheckID) == 0 || len(in.CheckID) > 128 || run && (!in.Acknowledge || len(in.SnapshotToken) != 64 || len(in.ConfigRevision) > 64) {
		fail(w, 400, "invalid_network_review", "Review the exact observation and explicitly confirm this one-time export.")
		return
	}
	op, exists := operatorContext(r)
	if !exists || op.session.ID == "" {
		fail(w, 401, "authentication_required", "An authenticated operator session is required.")
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	x, until, generation, ok := h.networkReviewSnapshot(in.CheckID)
	if !ok {
		fail(w, 409, "network_review_unavailable", "The observation is unavailable or no longer current.")
		return
	}
	a := h.app.ai
	a.mu.Lock()
	if !a.persistenceCurrentLocked() {
		a.mu.Unlock()
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked.")
		return
	}
	if !a.config.Configured || a.service == nil {
		a.mu.Unlock()
		fail(w, 409, "ai_not_configured", "Configure a provider before this review.")
		return
	}
	revision := a.config.Revision
	digest := networkReviewToken(a.reviewKey, in.CheckID, generation, revision, x, until)
	if !run {
		now := time.Now().UTC()
		for k, p := range a.networkReviews {
			if !now.Before(p.Until) {
				delete(a.networkReviews, k)
			}
		}
		if len(a.networkReviews) >= 128 {
			a.mu.Unlock()
			fail(w, 429, "network_review_capacity", "Too many pending reviews; wait for expiration.")
			return
		}
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			a.mu.Unlock()
			fail(w, 500, "configuration_error", "Review could not be prepared.")
			return
		}
		token := hex.EncodeToString(secret[:])
		if a.networkReviews == nil {
			a.networkReviews = make(map[string]networkReviewPermit)
		}
		if _, duplicate := a.networkReviews[token]; duplicate {
			a.mu.Unlock()
			fail(w, 500, "configuration_error", "Review could not be prepared.")
			return
		}
		permitUntil := now.Add(2 * time.Minute)
		if until.Before(permitUntil) {
			permitUntil = until
		}
		if op.session.ExpiresAt.Before(permitUntil) {
			permitUntil = op.session.ExpiresAt
		}
		if !now.Before(permitUntil) {
			a.mu.Unlock()
			fail(w, 409, "network_review_unavailable", "The review has expired.")
			return
		}
		a.networkReviews[token] = networkReviewPermit{Session: op.session.ID, Digest: digest, Revision: revision, Until: permitUntil}
		view := networkReviewPreview{"tracebolt.ai-network-review-preview.v1", in.CheckID, x.Kind, x.State, x.Reason, x.ObservedAt, permitUntil, token, revision, a.config.BaseURL, a.config.Model}
		a.mu.Unlock()
		if !operatorStillActive(w, r) {
			return
		}
		write(w, 200, view)
		return
	}
	if a.busy {
		a.mu.Unlock()
		fail(w, 409, "analysis_busy", "Another analysis is running.")
		return
	}
	permit, exists := a.networkReviews[in.SnapshotToken]
	if !exists || permit.Session != op.session.ID {
		a.mu.Unlock()
		fail(w, 409, "network_review_changed", "Review the current observation and provider again.")
		return
	}
	// Consume before any possible provider call, including an uncertain failure.
	delete(a.networkReviews, in.SnapshotToken)
	if !time.Now().Before(permit.Until) || in.ConfigRevision != revision || permit.Revision != revision || !hmac.Equal([]byte(permit.Digest), []byte(digest)) {
		a.mu.Unlock()
		fail(w, 409, "network_review_changed", "Review the current observation and provider again.")
		return
	}
	deadline := time.Now().Add(analysis.MaxTimeout)
	if permit.Until.Before(deadline) {
		deadline = permit.Until
	}
	owner := op.session.ID
	if op.session.ExpiresAt.Before(deadline) {
		deadline = op.session.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	a.busy = true
	a.activeID++
	id := a.activeID
	a.activeOwner = owner
	a.activeCancel = cancel
	service := a.service
	a.mu.Unlock()
	release()
	defer cancel()
	defer func() {
		a.mu.Lock()
		if a.activeID == id {
			a.busy = false
			a.activeCancel = nil
			a.activeOwner = ""
		}
		a.mu.Unlock()
	}()
	// Recheck immediately before transmission; the bounded network call never
	// holds configuration or source locks. Already sent bytes cannot be recalled.
	current, currentUntil, currentGeneration, valid := h.networkReviewSnapshot(in.CheckID)
	if !operatorStillActive(w, r) {
		return
	}
	a.mu.Lock()
	storageOK := a.persistenceCurrentLocked()
	same := a.config.Revision == revision && a.service == service && a.config.Configured
	a.mu.Unlock()
	if !storageOK {
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked.")
		return
	}
	if !valid || !same || networkReviewToken(a.reviewKey, in.CheckID, currentGeneration, revision, current, currentUntil) != digest || ctx.Err() != nil {
		fail(w, 409, "network_review_changed", "Review the current observation and provider again.")
		return
	}
	result, err := safeNetworkReview(ctx, service, x)
	if !operatorStillActive(w, r) || r.Context().Err() != nil {
		return
	}
	current, currentUntil, currentGeneration, valid = h.networkReviewSnapshot(in.CheckID)
	a.mu.Lock()
	storageOK = a.persistenceCurrentLocked()
	same = a.config.Revision == revision && a.service == service && a.config.Configured
	a.mu.Unlock()
	if !storageOK {
		fail(w, 503, "ai_settings_unavailable", "Saved AI settings are blocked.")
		return
	}
	if !valid || !same || networkReviewToken(a.reviewKey, in.CheckID, currentGeneration, revision, current, currentUntil) != digest || !time.Now().Before(permit.Until) {
		fail(w, 409, "network_review_changed", "The observation or provider changed during analysis.")
		return
	}
	if err != nil {
		fail(w, 422, "network_review_uncertain", "The review did not complete. The provider may have received the observation; no automatic retry was made.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, struct {
		SchemaVersion  string          `json:"schemaVersion"`
		CheckID        string          `json:"checkId"`
		SnapshotToken  string          `json:"snapshotToken"`
		ConfigRevision string          `json:"configRevision"`
		Result         analysis.Result `json:"result"`
	}{"tracebolt.ai-network-review-result.v1", in.CheckID, in.SnapshotToken, revision, result})
}
