package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) WindowsInventoryView(ctx context.Context, id string, now time.Time) (enrollmentstore.WindowsInventoryView, error) {
	return s.store.WindowsInventoryView(ctx, id, now)
}
