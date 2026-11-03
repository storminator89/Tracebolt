package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/macosinventorywire"
	"time"
)

func (s *Service) MacOSInventoryPage(ctx context.Context, device string, q enrollmentstore.MacOSInventoryQuery, now time.Time) (enrollmentstore.MacOSInventoryPage, error) {
	return s.store.MacOSInventoryPage(enrollmentstore.WithMacOSInventoryClock(ctx, s.Now), device, q, now)
}
func (s *Service) RecheckMacOSInventoryPage(ctx context.Context, p enrollmentstore.MacOSInventoryPage, now time.Time) error {
	return s.store.RecheckMacOSInventoryPage(enrollmentstore.WithMacOSInventoryClock(ctx, s.Now), p, now)
}
func (s *Service) MaintainMacOSInventory(ctx context.Context, now time.Time) error {
	return s.store.MaintainMacOSInventory(enrollmentstore.WithMacOSInventoryClock(ctx, s.Now), now)
}
func (s *Service) RunMacOSInventoryMaintenance(ctx context.Context, warn func()) error {
	return s.RunMacOSInventoryMaintenanceObserved(ctx, warn, nil)
}

// RunMacOSInventoryMaintenanceObserved reports each completed step, including
// failures, unless its parent context has been canceled.
func (s *Service) RunMacOSInventoryMaintenanceObserved(ctx context.Context, warn func(), observe func(time.Time, error)) error {
	if s == nil || s.serviceState == nil || s.binding.CollectionProfile != macosinventorywire.Profile || ctx == nil {
		return ErrConfiguration
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			e := s.MaintainMacOSInventory(ctx, s.Now().UTC())
			if ctx.Err() != nil {
				return nil
			}
			if observe != nil {
				observe(s.Now().UTC(), e)
			}
			if e != nil && warn != nil {
				warn()
			}
		}
	}
}
