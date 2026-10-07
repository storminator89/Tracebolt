package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) ResourceHistory(ctx context.Context, id string, now time.Time) (enrollmentstore.ResourceHistoryView, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.ResourceHistoryView{}, ErrConfiguration
	}
	return s.store.ResourceHistory(enrollmentstore.WithSystemViewClock(ctx, s.Now), id, now)
}
