package enrollmentservice

import (
	"context"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsservicehealth"
	"time"
)

// WindowsCapacityInputs deliberately does not widen Linux HealthInputs.
func (s *Service) WindowsCapacityInputs(ctx context.Context, now time.Time) ([]windowscapacity.Input, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return nil, ErrConfiguration
	}
	return s.store.WindowsCapacityInputs(ctx, now)
}

func (s *Service) WithWindowsCompleteServiceAuthority(ctx context.Context, expected windowsservicehealth.Input, fn func(func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithWindowsCompleteServiceAuthority(ctx, expected, s.Now, fn)
}

// Acknowledgement pins current source presence or absence without granting it.
func (s *Service) WithWindowsCompleteIncidentAuthority(ctx context.Context, expected windowsservicehealth.Input, fn func(func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithWindowsCompleteIncidentAuthority(ctx, expected, s.Now, fn)
}
