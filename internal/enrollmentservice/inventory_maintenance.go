package enrollmentservice

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"time"
)

const InventoryMaintenanceInterval = time.Second

// RunInventoryMaintenance is one fixed manager-owned loop, not an agent action
// or generic scheduler. A tick considers one known identity/domain and deletes
// at most256 rows/16 chunks. Every step restores current authority; no identity
// decision is cached across ticks. Busy/failing steps preserve data and retry on
// later rounds. A bounded warning callback never receives source content.
func (s *Service) RunInventoryMaintenance(ctx context.Context, warn func()) error {
	if s == nil || s.serviceState == nil || s.store == nil || ctx == nil || s.binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		return ErrConfiguration
	}
	ticker := time.NewTicker(InventoryMaintenanceInterval)
	defer ticker.Stop()
	var slot uint64
	var lastWarning time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := s.Now().UTC()
			step, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			_, e := s.store.MaintainInventoryStep(step, slot, now)
			cancel()
			slot++
			if ctx.Err() != nil {
				return nil
			}
			if e != nil && !errors.Is(e, enrollmentstore.ErrInventoryBusy) && !errors.Is(e, enrollmentstore.ErrBusy) && warn != nil && (lastWarning.IsZero() || !now.Before(lastWarning.Add(time.Minute))) {
				warn()
				lastWarning = now
			}
		}
	}
}
