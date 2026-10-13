package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

// A reviewed organizational selection adds a commit-time constraint. It never
// grants Windows authority, which must already be held by the caller's enrollment
// lease. Identity is the private original enrollment binding, not a device label.
type FleetGroupMaintenanceSelection struct {
	Manager       string
	GroupID       string
	GroupRevision uint64
	Identity      string
}

func (v FleetGroupMaintenanceSelection) valid() bool {
	return enrollmentcrypto.ValidHash(v.Manager) && enrollmentcrypto.ValidID(v.GroupID, "group_") && v.GroupRevision >= 1 && v.GroupRevision <= MaxFleetGroupRevision && enrollmentcrypto.ValidHash(v.Identity)
}

// StartFleetGroupMaintenance shares the existing one-target start transaction,
// including overlap, capacity, immutable ends and notification suppression. It
// adds no group job or durable state and does not change the old v1 operation.
func (s *Store) StartFleetGroupMaintenance(ctx context.Context, selection FleetGroupMaintenanceSelection, target WindowsMaintenanceTarget, expected uint64, endsAt time.Time, intent string, clock func() time.Time, guard func(time.Time, time.Time) error) (WindowsMaintenanceState, error) {
	if !selection.valid() {
		return WindowsMaintenanceState{}, ErrWindowsMaintenance
	}
	return s.changeWindowsMaintenance(ctx, target, expected, endsAt, intent, 0, clock, guard, &selection)
}

// EndFleetGroupMaintenance ends only the reviewed latest active window. The
// original group membership and revision are checked in the same transaction as
// the existing exact target revision, window ID and original-end guards.
func (s *Store) EndFleetGroupMaintenance(ctx context.Context, selection FleetGroupMaintenanceSelection, target WindowsMaintenanceTarget, expected, windowID uint64, clock func() time.Time, guard func(time.Time, time.Time) error) (WindowsMaintenanceState, error) {
	if !selection.valid() || windowID < 1 || windowID > MaxWindowsMaintenanceRevision {
		return WindowsMaintenanceState{}, ErrWindowsMaintenance
	}
	return s.changeWindowsMaintenance(ctx, target, expected, time.Time{}, "", windowID, clock, guard, &selection)
}

func checkFleetGroupMaintenance(ctx context.Context, tx *sql.Tx, selection *FleetGroupMaintenanceSelection, target WindowsMaintenanceTarget) error {
	if selection == nil {
		return nil
	}
	group, err := monitoringGroup(ctx, tx, selection.Manager, selection.GroupID, selection.GroupRevision)
	if errors.Is(err, ErrFleetMonitoringConflict) {
		return ErrWindowsMaintenanceConflict
	}
	if err != nil {
		return err
	}
	if !monitoringMember(group, target.DeviceID, selection.Identity) {
		return ErrWindowsMaintenanceConflict
	}
	return nil
}
