package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) CachedUpdatesView(ctx context.Context, id string, now time.Time) (enrollmentstore.CachedUpdatesView, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.CachedUpdatesView{}, ErrConfiguration
	}
	return s.store.CachedUpdatesView(ctx, id, now)
}
