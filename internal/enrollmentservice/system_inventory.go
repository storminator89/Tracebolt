package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) SystemInventoryView(ctx context.Context, id string, now time.Time) (enrollmentstore.SystemView, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.SystemView{}, ErrConfiguration
	}
	return s.store.SystemView(ctx, id, now)
}
func (s *Service) SystemInventoryPage(ctx context.Context, id string, q enrollmentstore.SystemPageRequest, now time.Time) (enrollmentstore.SystemPageResult, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.SystemPageResult{}, ErrConfiguration
	}
	return s.store.SystemPage(ctx, id, q, now)
}
