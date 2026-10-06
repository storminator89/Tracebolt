package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"time"
)

func (s *Service) CompleteInventoryView(ctx context.Context, id string, now time.Time) (enrollmentstore.InventoryStatus, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.InventoryStatus{}, ErrConfiguration
	}
	return s.store.InventoryView(enrollmentstore.WithSystemViewClock(ctx, s.Now), id, now)
}
func (s *Service) CompleteInventoryPage(ctx context.Context, id string, request inventoryledger.PageRequest, now time.Time) (enrollmentstore.InventoryPageResult, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.InventoryPageResult{}, ErrConfiguration
	}
	return s.store.InventoryPage(ctx, id, request, now)
}
