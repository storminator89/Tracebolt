package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) OperationalView(ctx context.Context, id string, now time.Time) (enrollmentstore.OperationalView, error) {
	return s.store.OperationalView(ctx, id, now)
}

// PackageView preserves current durable profile/identity state and latest-only
// package observation provenance; it performs no native collection or matching.
func (s *Service) PackageView(ctx context.Context, id string, now time.Time) (enrollmentstore.PackageView, error) {
	return s.store.PackageView(ctx, id, now)
}
