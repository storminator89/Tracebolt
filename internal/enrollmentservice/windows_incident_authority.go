package enrollmentservice

import (
	"context"
	"localrmm/internal/windowscontact"
	"time"
)

// This manager-only lease keeps current enrollment authority locked through the
// separate operator acknowledgement commit; it grants no endpoint operation.
func (s *Service) WithWindowsIncidentAuthority(ctx context.Context, expected windowscontact.Input, fn func(func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithWindowsIncidentAuthority(ctx, expected, s.Now, fn)
}
