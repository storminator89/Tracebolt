package assessment

import (
	"sync"
	"testing"
	"time"
)

func TestFailedRefreshRetainsLastGoodAssessment(t *testing.T) {
	var cache AssessmentCache
	initial := cache.View(testNow())
	if initial.Snapshot != nil || initial.Assessment != nil || initial.RefreshOutcome != "never_attempted" {
		t.Fatal("unrun cache looks assessed")
	}
	snapshot := fixtureSnapshot(t, nil)
	assessment := evaluate(t, fixtureInventory(t), snapshot)
	if err := cache.Commit(snapshot, assessment, testNow()); err != nil {
		t.Fatal(err)
	}
	later := testNow().Add(2 * time.Hour)
	cache.RecordFailure(later, "private URL/body should be sanitized")
	view := cache.View(later)
	if view.Snapshot != snapshot || view.Assessment == nil || view.RefreshOutcome != "failed" || view.FailureReason != "refresh_failed" {
		t.Fatal("refresh failure erased last-good state")
	}
	if view.Assessment.Quality.Freshness != Stale || view.Assessment.Quality.Coverage != Assessed || len(view.Assessment.Matches) != 1 || view.Assessment.Matches[0].Verdict != Affected || *view.Assessment.AffectedCVEs != 1 {
		t.Fatal("stale findings replaced by empty success")
	}
	if !view.Assessment.Quality.AssessedAt.Equal(testNow()) || !view.Snapshot.Source().FetchedAt.Equal(snapshot.Source().FetchedAt) {
		t.Fatal("cache read silently refreshed evidence age")
	}
	// Returned views must not mutate stored data, including pointers and slices.
	*view.Assessment.AffectedCVEs = 0
	view.Assessment.Matches[0].Verdict = Fixed
	view.Assessment.Sources[0].ExpiresAt = later.Add(time.Hour)
	again := cache.View(later)
	if *again.Assessment.AffectedCVEs != 1 || again.Assessment.Matches[0].Verdict != Affected || again.Assessment.Quality.Freshness != Stale {
		t.Fatal("cache aliases returned mutable result")
	}
}
func TestFailureBeforeFirstSuccessHasNoResult(t *testing.T) {
	var cache AssessmentCache
	cache.RecordFailure(testNow(), "parse_failed")
	view := cache.View(testNow())
	if view.Assessment != nil || view.Snapshot != nil || view.RefreshOutcome != "failed" {
		t.Fatal("failure manufactured empty assessment")
	}
}
func TestCacheRejectsRollbackAndMismatchedAssessment(t *testing.T) {
	var cache AssessmentCache
	snapshot := fixtureSnapshot(t, nil)
	assessment := evaluate(t, fixtureInventory(t), snapshot)
	if err := cache.Commit(snapshot, assessment, testNow()); err != nil {
		t.Fatal(err)
	}
	old := fixtureSnapshot(t, func(_ *debianDocument, s *SourceSnapshot) {
		s.FetchedAt = testNow().Add(-24 * time.Hour)
		s.ValidatedAt = s.FetchedAt
		s.ExpiresAt = testNow().Add(-time.Hour)
	})
	if err := cache.Commit(old, evaluate(t, fixtureInventory(t), old), testNow()); err != ErrCachePromotion {
		t.Fatal("rollback snapshot promoted")
	}
	assessment.Sources = nil
	if err := cache.Commit(snapshot, assessment, testNow()); err != ErrCachePromotion {
		t.Fatal("assessment from different source promoted")
	}
	if view := cache.View(testNow()); view.Snapshot != snapshot || len(view.Assessment.Matches) != 1 {
		t.Fatal("rejected promotion damaged last good")
	}
}
func TestCacheConcurrentViewsAreRaceSafe(t *testing.T) {
	var cache AssessmentCache
	snapshot := fixtureSnapshot(t, nil)
	assessment := evaluate(t, fixtureInventory(t), snapshot)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = cache.Commit(snapshot, assessment, testNow())
				cache.RecordFailure(testNow(), "fetch_failed")
				_ = cache.View(testNow())
			}
		}()
	}
	wg.Wait()
}
func TestFreshnessUnknownAndStaleAreIndependent(t *testing.T) {
	now := testNow()
	for _, source := range []SourceSnapshot{{}, {FetchedAt: now, ValidatedAt: now}, {FetchedAt: now.Add(time.Hour), ValidatedAt: now, ExpiresAt: now.Add(2 * time.Hour)}, {FetchedAt: now, ValidatedAt: now, ExpiresAt: now.Add(-time.Hour)}} {
		if source.FreshnessAt(now) != FreshnessUnknown {
			t.Fatal("unverified freshness treated as current")
		}
	}
	q := Quality{Coverage: Partial, Freshness: Stale}
	if q.Status() != StatusStale || q.Coverage != Partial {
		t.Fatal("combined status overwrote coverage")
	}
}
