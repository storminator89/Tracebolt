package enrollmentservice

import (
	"context"
	"os"
	"time"
)

func (s *Service) CustomerEnrollmentLeaseIdentity() (os.FileInfo, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return nil, ErrConfiguration
	}
	return s.store.CustomerEnrollmentLeaseIdentity()
}

func (s *Service) WithCustomerIdentityExclusion(ctx context.Context, ids []string, fn func(func(time.Time) error) error) error {
	if s == nil || s.serviceState == nil || s.store == nil {
		return ErrConfiguration
	}
	return s.store.WithCustomerIdentityExclusion(ctx, ids, s.Now, fn)
}
