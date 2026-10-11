package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullservices"
	"time"
)

func (s *Service) InitializeWindowsFullServices(ctx context.Context) error {
	if s == nil || s.serviceState == nil {
		return ErrConfiguration
	}
	return s.store.InitializeWindowsFullServices(ctx)
}
func (s *Service) ApplyWindowsFullServices(ctx context.Context, id, cert string, m windowsfullservices.Message, raw []byte, now time.Time) (windowsfullservices.Receipt, error) {
	return s.store.ApplyWindowsFullServices(enrollmentstore.WithWindowsFullServicesClock(ctx, s.Now), id, cert, m, raw, now)
}
func (s *Service) WindowsFullServicesPage(ctx context.Context, id string, q windowsfullservices.Query, now time.Time) (windowsfullservices.Page, error) {
	return s.store.WindowsFullServicesPage(enrollmentstore.WithWindowsFullServicesClock(ctx, s.Now), id, q, now)
}
func (s *Service) MaintainWindowsFullServices(ctx context.Context, now time.Time) error {
	return s.store.MaintainWindowsFullServices(ctx, now)
}
func (s *Service) RecheckWindowsFullServicesPage(ctx context.Context, p windowsfullservices.Page, now time.Time) error {
	return s.store.RecheckWindowsFullServicesPage(enrollmentstore.WithWindowsFullServicesClock(ctx, s.Now), p, now)
}
