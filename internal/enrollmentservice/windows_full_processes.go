package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullprocesses"
	"time"
)

func (s *Service) InitializeWindowsFullProcesses(ctx context.Context) error {
	if s == nil || s.serviceState == nil {
		return ErrConfiguration
	}
	return s.store.InitializeWindowsFullProcesses(ctx)
}
func (s *Service) ApplyWindowsFullProcesses(ctx context.Context, id, cert string, m windowsfullprocesses.Message, raw []byte, now time.Time) (windowsfullprocesses.Receipt, error) {
	return s.store.ApplyWindowsFullProcesses(enrollmentstore.WithWindowsFullProcessesClock(ctx, s.Now), id, cert, m, raw, now)
}
func (s *Service) WindowsFullProcessesPage(ctx context.Context, id string, q windowsfullprocesses.Query, now time.Time) (windowsfullprocesses.Page, error) {
	return s.store.WindowsFullProcessesPage(enrollmentstore.WithWindowsFullProcessesClock(ctx, s.Now), id, q, now)
}
func (s *Service) MaintainWindowsFullProcesses(ctx context.Context, now time.Time) error {
	return s.store.MaintainWindowsFullProcesses(ctx, now)
}
func (s *Service) RecheckWindowsFullProcessesPage(ctx context.Context, p windowsfullprocesses.Page, now time.Time) error {
	return s.store.RecheckWindowsFullProcessesPage(enrollmentstore.WithWindowsFullProcessesClock(ctx, s.Now), p, now)
}
