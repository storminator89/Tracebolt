package assessment

import (
	"errors"
	"sync"
	"time"
)

var ErrCachePromotion = errors.New("assessment_cache_promotion_rejected")

// RetainedAssessment keeps last-good results plus failure metadata. The original
// source and assessment times never advance merely because the cache was read.
type RetainedAssessment struct {
	Snapshot       *DebianSnapshot
	Assessment     *VulnerabilityAssessment
	LastAttemptAt  time.Time
	RefreshOutcome string
	FailureReason  string
}

// AssessmentCache is in-memory only. It has no fetcher, disk writes, scheduled
// jobs or network access. A future persistent store needs atomic equivalent semantics.
type AssessmentCache struct {
	mu    sync.RWMutex
	state RetainedAssessment
}

func (c *AssessmentCache) Commit(snapshot *DebianSnapshot, assessment VulnerabilityAssessment, now time.Time) error {
	if snapshot == nil || assessment.Quality.Coverage == Unknown || assessment.Quality.AssessedAt.IsZero() || assessment.Quality.AssessedAt.After(now) {
		return ErrCachePromotion
	}
	found := false
	for _, source := range assessment.Sources {
		if source.ID == snapshot.source.ID && source.SHA256 == snapshot.source.SHA256 {
			found = true
		}
	}
	if !found {
		return ErrCachePromotion
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Snapshot != nil && snapshot.source.FetchedAt.Before(c.state.Snapshot.source.FetchedAt) {
		return ErrCachePromotion
	}
	copied := cloneAssessment(assessment)
	c.state = RetainedAssessment{Snapshot: snapshot, Assessment: &copied, LastAttemptAt: now.UTC(), RefreshOutcome: "success"}
	return nil
}
func (c *AssessmentCache) RecordFailure(now time.Time, reason string) {
	// Do not preserve arbitrary error text, paths, response bodies or stderr.
	if !oneOf(reason, "fetch_failed", "parse_failed", "digest_mismatch", "refresh_timeout", "source_unavailable", "rollback_rejected") {
		reason = "refresh_failed"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.LastAttemptAt = now.UTC()
	c.state.RefreshOutcome = "failed"
	c.state.FailureReason = reason
}
func (c *AssessmentCache) View(now time.Time) RetainedAssessment {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state := c.state
	if state.RefreshOutcome == "" {
		state.RefreshOutcome = "never_attempted"
	}
	if state.Assessment != nil {
		copied := cloneAssessment(*state.Assessment)
		freshness := Fresh
		for _, source := range copied.Sources {
			freshness = combinedFreshness(freshness, source.FreshnessAt(now))
		}
		copied.Quality.Freshness = freshness
		if state.RefreshOutcome == "failed" {
			copied.Quality.ReasonCodes = appendUnique(copied.Quality.ReasonCodes, "last_refresh_failed")
		}
		state.Assessment = &copied
	}
	return state
}
func cloneAssessment(in VulnerabilityAssessment) VulnerabilityAssessment {
	out := in
	out.Sources = append([]SourceSnapshot(nil), in.Sources...)
	out.Matches = append([]Match(nil), in.Matches...)
	for i := range out.Matches {
		out.Matches[i].Qualifications = append([]string(nil), in.Matches[i].Qualifications...)
	}
	out.Quality.ExcludedScopes = append([]string(nil), in.Quality.ExcludedScopes...)
	out.Quality.ReasonCodes = append([]string(nil), in.Quality.ReasonCodes...)
	if in.Quality.AssessedItems != nil {
		out.Quality.AssessedItems = count(*in.Quality.AssessedItems)
	}
	if in.Quality.UnassessedItems != nil {
		out.Quality.UnassessedItems = count(*in.Quality.UnassessedItems)
	}
	if in.AffectedCVEs != nil {
		out.AffectedCVEs = count(*in.AffectedCVEs)
	}
	if in.ReviewCandidates != nil {
		out.ReviewCandidates = count(*in.ReviewCandidates)
	}
	return out
}
