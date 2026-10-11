package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsnetworkcontext"
	"time"
)

func (s *Service) InitializeWindowsNetworkContext(ctx context.Context) error {
	if s == nil || s.serviceState == nil {
		return ErrConfiguration
	}
	return s.store.InitializeWindowsNetworkContext(ctx)
}
func (s *Service) ApplyWindowsNetworkContext(ctx context.Context, id, cert string, m windowsnetworkcontext.Message, raw []byte, now time.Time) (windowsnetworkcontext.Receipt, error) {
	return s.store.ApplyWindowsNetworkContext(enrollmentstore.WithWindowsNetworkContextClock(ctx, s.Now), id, cert, m, raw, now)
}
func (s *Service) WindowsNetworkContextPage(ctx context.Context, id string, q windowsnetworkcontext.Query, now time.Time) (windowsnetworkcontext.Page, error) {
	return s.store.WindowsNetworkContextPage(enrollmentstore.WithWindowsNetworkContextClock(ctx, s.Now), id, q, now)
}
func (s *Service) MaintainWindowsNetworkContext(ctx context.Context, now time.Time) error {
	return s.store.MaintainWindowsNetworkContext(ctx, now)
}
func (s *Service) RecheckWindowsNetworkContextPage(ctx context.Context, p windowsnetworkcontext.Page, now time.Time) error {
	return s.store.RecheckWindowsNetworkContextPage(enrollmentstore.WithWindowsNetworkContextClock(ctx, s.Now), p, now)
}
