package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"time"
)

func (s *Service) WindowsFleetSoftwarePage(ctx context.Context, q windowsfullsoftware.FleetQuery, now time.Time) (windowsfullsoftware.FleetPage, error) {
	return s.store.WindowsFleetSoftwarePage(enrollmentstore.WithWindowsFullSoftwareClock(ctx, s.Now), q, now)
}
func (s *Service) RecheckWindowsFleetSoftwarePage(ctx context.Context, p windowsfullsoftware.FleetPage, now time.Time) error {
	return s.store.RecheckWindowsFleetSoftwarePage(enrollmentstore.WithWindowsFullSoftwareClock(ctx, s.Now), p, now)
}
