package enrollmentservice

import (
	"context"
	"localrmm/internal/health"
	"time"
)

func (s *Service) HealthInputs(ctx context.Context, services map[string][]string, now time.Time) ([]health.Input, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return nil, ErrConfiguration
	}
	return s.store.HealthInputs(ctx, services, now)
}
