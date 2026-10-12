package enrollmentservice

import (
	"context"
	"localrmm/internal/windowscontact"
	"time"
)

// Manager-only policy ownership lease; grants no endpoint permission.
func (s *Service) WithWindowsMonitoringAuthority(ctx context.Context, expected []windowscontact.Input, fn func(func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithWindowsMonitoringAuthority(ctx, expected, s.Now, fn)
}
