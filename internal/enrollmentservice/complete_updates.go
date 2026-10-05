package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"time"
)

func (s *Service) CompleteUpdatesView(ctx context.Context, id string, now time.Time) (enrollmentstore.CompleteUpdatesStatus, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return enrollmentstore.CompleteUpdatesStatus{}, ErrConfiguration
	}
	return s.store.CompleteUpdatesView(enrollmentstore.WithCompleteUpdatesClock(ctx, s.Now), id, now)
}
func (s *Service) CompleteUpdatesPage(ctx context.Context, id string, request inventoryledger.PageRequest, now time.Time) (enrollmentstore.CompleteUpdatesPageResult, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return enrollmentstore.CompleteUpdatesPageResult{}, ErrConfiguration
	}
	return s.store.CompleteUpdatesPage(enrollmentstore.WithCompleteUpdatesClock(ctx, s.Now), id, request, now)
}
