package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"time"
)

func (s *Service) InitializeWindowsFullSoftware(ctx context.Context) error {
	if s == nil || s.serviceState == nil {
		return ErrConfiguration
	}
	return s.store.InitializeWindowsFullSoftware(ctx)
}
func (s *Service) ApplyWindowsFullSoftware(ctx context.Context, id, cert string, m windowsfullsoftware.Message, raw []byte, now time.Time) (windowsfullsoftware.Receipt, error) {
	return s.store.ApplyWindowsFullSoftware(enrollmentstore.WithWindowsFullSoftwareClock(ctx, s.Now), id, cert, m, raw, now)
}
func (s *Service) WindowsFullSoftwarePage(ctx context.Context, id string, q windowsfullsoftware.Query, now time.Time) (windowsfullsoftware.Page, error) {
	return s.store.WindowsFullSoftwarePage(enrollmentstore.WithWindowsFullSoftwareClock(ctx, s.Now), id, q, now)
}
func (s *Service) MaintainWindowsFullSoftware(ctx context.Context, now time.Time) error {
	return s.store.MaintainWindowsFullSoftware(ctx, now)
}
func (s *Service) RecheckWindowsFullSoftwarePage(ctx context.Context, p windowsfullsoftware.Page, now time.Time) error {
	return s.store.RecheckWindowsFullSoftwarePage(enrollmentstore.WithWindowsFullSoftwareClock(ctx, s.Now), p, now)
}
