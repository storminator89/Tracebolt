package enrollmentservice

import (
	"context"
	"localrmm/internal/windowscontact"
	"time"
)

// WindowsContactInputs deliberately does not widen Linux HealthInputs.
func (s *Service) WindowsContactInputs(ctx context.Context, now time.Time) ([]windowscontact.Input, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return nil, ErrConfiguration
	}
	return s.store.WindowsContactInputs(ctx, now)
}
