package enrollmentservice

import (
	"context"
	"localrmm/internal/linuxprocesswatch"
	"time"
)

// Existing complete-process observations only; no collection or grant is added.
func (s *Service) WithLinuxProcessWatch(ctx context.Context, device string, names []string, epoch string, fn func(linuxprocesswatch.Input, func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithLinuxProcessWatch(ctx, device, names, epoch, s.Now, fn)
}
