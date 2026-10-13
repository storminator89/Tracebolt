package store

import (
	"context"
	"database/sql"
	"localrmm/internal/windowsservicehealth"
	"time"
)

// ConfigureFleetGroupService applies only to an exact original stored member.
// This adds no durable job, inheritance or new authorization to service policy.
func (s *Store) ConfigureFleetGroupService(ctx context.Context, selection FleetGroupMaintenanceSelection, input windowsservicehealth.Input, enabled bool, names []string, expected uint64, clock func() time.Time, guard func(time.Time) error) (windowsservicehealth.State, error) {
	if !selection.valid() {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	target := WindowsMaintenanceTarget{DeviceID: input.DeviceID, InvitationID: input.InvitationID, CertificateHash: input.CertificateHash, Domain: "service"}
	return s.configureWindowsServiceGuarded(ctx, input, enabled, names, expected, clock, guard, func(tx *sql.Tx) error { return checkFleetGroupMaintenance(ctx, tx, &selection, target) })
}
