package enrollmentservice

import (
	"context"
	"localrmm/internal/linuxmountwatch"
	"time"
)

func (s *Service) WithLinuxMountWatch(ctx context.Context, device string, target *linuxmountwatch.Target, epoch string, fn func(linuxmountwatch.Input, func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithLinuxMountWatch(ctx, device, target, epoch, s.Now, fn)
}
