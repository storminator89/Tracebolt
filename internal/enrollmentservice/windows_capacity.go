package enrollmentservice

import (
	"context"
	"localrmm/internal/windowscapacity"
	"time"
)

// WindowsCapacityInputs deliberately does not widen Linux HealthInputs.
func (s *Service) WindowsCapacityInputs(ctx context.Context, now time.Time) ([]windowscapacity.Input, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return nil, ErrConfiguration
	}
	return s.store.WindowsCapacityInputs(ctx, now)
}
