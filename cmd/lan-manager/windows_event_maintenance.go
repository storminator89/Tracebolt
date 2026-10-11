package main

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstore"
	"time"
)

// This manager-owned loop handles bounded Windows request metadata/cache and complete-generation reclamation.
// It creates no endpoint grant, credential, source read or background capture.
func runWindowsEventMaintenance(ctx context.Context, s *enrollmentservice.Service, warn func()) error {
	if ctx == nil || s == nil || s.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return enrollmentservice.ErrConfiguration
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	tick := 0
	return windowsEventMaintenanceLoop(ctx, func(ctx context.Context, now time.Time) error {
		tick++
		e := s.MaintainWindowsContext(ctx, uint64(tick), now)
		if servicesErr := s.MaintainWindowsFullServices(ctx, now); e == nil {
			e = servicesErr
		}
		if softwareErr := s.MaintainWindowsFullSoftware(ctx, now); e == nil {
			e = softwareErr
		}
		if tick%5 == 0 {
			if eventErr := s.MaintainWindowsEventContent(ctx, now); e == nil {
				e = eventErr
			}
		}
		return e
	}, s.Now, ticker.C, warn)
}
func windowsEventMaintenanceLoop(ctx context.Context, maintain func(context.Context, time.Time) error, now func() time.Time, ticks <-chan time.Time, warn func()) error {
	if ctx == nil || maintain == nil || now == nil || ticks == nil {
		return enrollmentservice.ErrConfiguration
	}
	var lastWarning time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ticks:
			if !ok {
				return nil
			}
			at := now().UTC()
			step, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			err := maintain(step, at)
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			if err != nil && !errors.Is(err, enrollmentstore.ErrBusy) && warn != nil && (lastWarning.IsZero() || at.Before(lastWarning) || !at.Before(lastWarning.Add(time.Minute))) {
				warn()
				lastWarning = at
			}
		}
	}
}
