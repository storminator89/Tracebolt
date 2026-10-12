package enrollmentservice

import (
	"context"
	"localrmm/internal/windowscontact"
	"time"
)

// Receipt-bound read-only lease; no collector or endpoint authority is added.
func (s *Service) WithWindowsNotificationAuthority(ctx context.Context, expected windowscontact.Input, fn func(func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithWindowsNotificationAuthority(ctx, expected, s.Now, fn)
}
