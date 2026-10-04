package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/overviewledger"
	"time"
)

func (s *Service) CompleteOverviewView(ctx context.Context, id string, now time.Time) (enrollmentstore.OverviewStatus, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return enrollmentstore.OverviewStatus{}, ErrConfiguration
	}
	return s.store.OverviewView(enrollmentstore.WithOverviewClock(ctx, s.Now), id, now)
}
func (s *Service) CompleteOverviewPage(ctx context.Context, id string, request overviewledger.PageRequest, now time.Time) (enrollmentstore.OverviewPageResult, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return enrollmentstore.OverviewPageResult{}, ErrConfiguration
	}
	return s.store.OverviewPage(enrollmentstore.WithOverviewClock(ctx, s.Now), id, request, now)
}
