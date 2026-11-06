package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"time"
)

// This facade supplies the existing trusted clock to private read projections.
// It does not enroll, grant, collect, change identity or create retained records.
func (s *Service) WindowsFleetSoftwareHistoryPage(ctx context.Context, q windowsfullsoftware.FleetQuery, now time.Time) (windowsfullsoftware.FleetHistoryPage, error) {
	return s.store.WindowsFleetSoftwareHistoryPage(enrollmentstore.WithWindowsFullSoftwareClock(ctx, s.Now), q, now)
}
func (s *Service) RecheckWindowsFleetSoftwareHistoryPage(ctx context.Context, p windowsfullsoftware.FleetHistoryPage, now time.Time) error {
	return s.store.RecheckWindowsFleetSoftwareHistoryPage(enrollmentstore.WithWindowsFullSoftwareClock(ctx, s.Now), p, now)
}
