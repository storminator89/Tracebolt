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
	return s.RunMacOSInventoryMaintenanceObserved(ctx, warn, MaintenanceObserver{})
}

// RunMacOSInventoryMaintenanceObserved records each actual bounded maintenance step.
func (s *Service) RunMacOSInventoryMaintenanceObserved(ctx context.Context, warn func(), observer MaintenanceObserver) error {
	if s == nil || s.serviceState == nil || s.binding.CollectionProfile != macosinventorywire.Profile || ctx == nil {
		return ErrConfiguration
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	return macOSInventoryMaintenanceLoop(ctx, s.MaintainMacOSInventory, s.Now, ticker.C, warn, observer)
}

// The private tick seam keeps the minute cadence testable without advancing
// endpoint/source time or weakening the actual step's cancellation budget.
func macOSInventoryMaintenanceLoop(ctx context.Context, maintain func(context.Context, time.Time) error, now func() time.Time, ticks <-chan time.Time, warn func(), observer MaintenanceObserver) error {
	if ctx == nil || maintain == nil || now == nil || ticks == nil {
		return ErrConfiguration
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, open := <-ticks:
			if !open {
				return nil
			}
			step, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			observer.start()
			e := maintain(step, now().UTC())
			cancel()
			observer.complete(e)
			if e != nil && ctx.Err() == nil && warn != nil {
				warn()
			}
		}
	}
}
