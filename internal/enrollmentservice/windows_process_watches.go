package enrollmentservice

import (
	"context"
	watch "localrmm/internal/windowsprocesswatch"
	"time"
)

func (s *Service) WithWindowsProcessWatchAuthority(ctx context.Context, device string, names []string, fn func(watch.Input, func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithWindowsProcessWatchAuthority(ctx, device, names, s.Now, fn)
}
