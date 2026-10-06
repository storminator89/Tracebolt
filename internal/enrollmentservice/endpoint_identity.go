package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"time"
)

func (s *Service) EndpointIdentityView(ctx context.Context, id string, now time.Time) (enrollmentstore.EndpointIdentityView, error) {
	if s == nil || s.store == nil {
		return enrollmentstore.EndpointIdentityView{}, ErrConfiguration
	}
	return s.store.EndpointIdentityView(enrollmentstore.WithSystemViewClock(ctx, s.Now), id, now)
}
