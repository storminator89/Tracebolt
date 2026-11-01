package enrollmentstore

import (
	"context"
	"database/sql"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/managerstatus"
)

// ManagerStatus validates current authority without expiry, retention, issuance,
// persistence or other transitions. Terminal records still consume quota.
func (s *Store) ManagerStatus(ctx context.Context) managerstatus.ProbeResult {
	if s == nil || s.storeState == nil || s.checkPath() != nil {
		return managerstatus.ProbeResult{State: managerstatus.Unavailable}
	}
	return managerstatus.SQLiteProbe(ctx, s.db, func(ctx context.Context, c *sql.Conn) (managerstatus.ProbeResult, error) {
		tx, err := s.load(ctx, c)
		if err != nil {
			return managerstatus.ProbeResult{}, err
		}
		if physicalInventoryProfile(s.config.Binding.CollectionProfile) {
			if err = s.inventoryConnectionCapacity(ctx, c); err != nil {
				return managerstatus.ProbeResult{}, err
			}
		}
		if err = s.checkPath(); err != nil {
			return managerstatus.ProbeResult{}, err
		}
		counts := &managerstatus.CapacityMetrics{Limit: s.config.RecordLimit}
		for _, snapshot := range tx.engine.Snapshots() {
			counts.Used++
			switch snapshot.State {
			case enrollmentstate.Activated:
				counts.Active++
			case enrollmentstate.Expired, enrollmentstate.Canceled, enrollmentstate.Rejected, enrollmentstate.Revoked:
				counts.Terminal++
			default:
				counts.Pending++
			}
		}
		result := managerstatus.ProbeResult{State: managerstatus.OK, Capacity: counts, Storage: &managerstatus.StorageMetrics{MaxDatabaseBytes: uint64(databaseCap(s.config.Binding.CollectionProfile)), MaxWALBytes: uint64(sidecarCap(s.config.Binding.CollectionProfile, "-wal"))}}
		if counts.Used >= counts.Limit {
			result.State = managerstatus.Full
		}
		return result, nil
	})
}
