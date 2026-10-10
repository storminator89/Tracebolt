package api

import (
	"context"
	"time"
)

// evaluateWindowsHealthMonitors deliberately runs the independent contracts in
// sequence. Both use the same bounded enrollment-store reader, so starting two
// simultaneous loops would discard continuity through self-induced busy errors.
func evaluateWindowsHealthMonitors(ctx context.Context, contact *windowsContactMonitor, capacity *windowsCapacityMonitor) (contactErr, capacityErr error) {
	if contact != nil {
		step, cancel := context.WithTimeout(ctx, 10*time.Second)
		contactErr = contact.evaluate(step)
		cancel()
	}
	if ctx.Err() != nil {
		return contactErr, ctx.Err()
	}
	if capacity != nil {
		step, cancel := context.WithTimeout(ctx, 10*time.Second)
		capacityErr = capacity.evaluate(step)
		cancel()
	}
	return
}

// RunWindowsHealthMonitors is the production Windows scheduler. It preserves
// separate contact/percentage/service authority, durable ledgers and restart epochs, with
// independent disk/CPU/RAM/selected-service ledgers, no concurrent self-contention or host activity. Shutdown joins this worker
// before the enrollment and operator stores close.
func (s *Server) RunWindowsHealthMonitors(ctx context.Context, warnContact, warnCapacity func()) error {
	s.mu.RLock()
	contact, capacity := s.windowsContact, s.windowsCapacity
	s.mu.RUnlock()
	if contact == nil && capacity == nil {
		return nil
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	warnings := [2]func(){warnContact, warnCapacity}
	last := [2]time.Time{}
	for {
		contactErr, capacityErr := evaluateWindowsHealthMonitors(ctx, contact, capacity)
		if ctx.Err() != nil {
			return nil
		}
		now := time.Now()
		for i, err := range []error{contactErr, capacityErr} {
			if err != nil && warnings[i] != nil && (last[i].IsZero() || now.Sub(last[i]) >= time.Minute) {
				warnings[i]()
				last[i] = now
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
