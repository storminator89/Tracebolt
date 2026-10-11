package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsusersoftware"
	"time"
)

func (s *Service) InitializeWindowsUserSoftware(ctx context.Context) error {
	if s == nil || s.serviceState == nil {
		return ErrConfiguration
	}
	return s.store.InitializeWindowsUserSoftware(ctx)
}
func (s *Service) ApplyWindowsUserSoftware(ctx context.Context, id, cert string, m windowsusersoftware.Message, raw []byte, now time.Time) (windowsusersoftware.Receipt, error) {
	return s.store.ApplyWindowsUserSoftware(enrollmentstore.WithWindowsUserSoftwareClock(ctx, s.Now), id, cert, m, raw, now)
}
func (s *Service) WindowsUserSoftwarePage(ctx context.Context, id string, q windowsusersoftware.Query, now time.Time) (windowsusersoftware.Page, error) {
	return s.store.WindowsUserSoftwarePage(enrollmentstore.WithWindowsUserSoftwareClock(ctx, s.Now), id, q, now)
}
func (s *Service) MaintainWindowsUserSoftware(ctx context.Context, now time.Time) error {
	return s.store.MaintainWindowsUserSoftware(ctx, now)
}
func (s *Service) RecheckWindowsUserSoftwarePage(ctx context.Context, p windowsusersoftware.Page, now time.Time) error {
	return s.store.RecheckWindowsUserSoftwarePage(enrollmentstore.WithWindowsUserSoftwareClock(ctx, s.Now), p, now)
}
