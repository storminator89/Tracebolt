package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) WindowsInventoryView(ctx context.Context, id string, now time.Time) (enrollmentstore.WindowsInventoryView, error) {
	return s.store.WindowsInventoryView(ctx, id, now)
}

// Manager-owned cache maintenance does not authorize an endpoint source read.
func (s *Service) MaintainWindowsContext(ctx context.Context, slot uint64, now time.Time) error {
	return s.store.MaintainWindowsContext(ctx, slot, now)
}
