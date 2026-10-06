package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) FleetEndpointIdentityView(ctx context.Context, now time.Time) (enrollmentstore.FleetEndpointIdentityView, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.FleetEndpointIdentityView{}, ErrConfiguration
	}
	return s.store.FleetEndpointIdentityView(enrollmentstore.WithSystemViewClock(ctx, s.Now), now)
}
