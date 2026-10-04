package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/overviewledger"
	"sort"
	"time"
)

// InventoryMaintenanceResult contains only bounded maintenance metadata. This
// method is an internal trusted-manager operation, never an agent endpoint.
type InventoryMaintenanceResult struct {
	DeviceID                   string
	Section                    string
	RowsDeleted, ChunksDeleted int
	GenerationRemoved          bool
}

// MaintainInventoryStep selects one of at most 25 freshly resolved issued
// identities and three fixed domains. The caller's rolling slot only chooses
// fairness, never authority. At most one eligible noncurrent generation batch
// (256 rows,16 chunks) is reclaimed in this one current-authority transaction.
// Current generations, replay floors and original receipt ages are untouched.
func (s *Store) MaintainInventoryStep(ctx context.Context, slot uint64, now time.Time) (InventoryMaintenanceResult, error) {
	zero := InventoryMaintenanceResult{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out InventoryMaintenanceResult
	e = s.transact(ctx, func(t *transaction) error {
		if !validStoreTime(now) {
			return enrollmentstate.ErrInvalid
		}
		devices := []string{}
		for _, snap := range t.engine.Snapshots() {
			if completeProfile(snap.Binding.CollectionProfile) && snap.Platform == "linux" && snap.Activation.At != 0 && enrollmentcrypto.ValidHash(snap.Issuance.CertificateHash) {
				devices = append(devices, snap.Approval.DeviceID)
			}
		}
		if len(devices) > 25 {
			return ErrStorage
		}
		if len(devices) == 0 {
			return nil
		}
		sort.Strings(devices)
		device := devices[(slot/3)%uint64(len(devices))]
		section := []string{"packages", "processes", "volumes"}[slot%3]
		out.DeviceID, out.Section = device, section
		if section == "packages" {
			snap, e := s.inventoryMaintenanceAuthority(t, device, now)
			if errors.Is(e, inventoryledger.ErrNotFound) {
				return nil
			}
			if e != nil {
				return e
			}
			id, e := eligibleInventoryGeneration(ctx, t, device, false, now)
			if e != nil || id == "" {
				return e
			}
			result, e := completeLedger().Cleanup(ctx, t.conn, device, id, now)
			if e != nil {
				return e
			}
			if result.Done {
				if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_inventory_generations WHERE device=? AND generation=?`, device, id); e != nil {
					return ErrStorage
				}
			}
			r := t.inventory[snap.InvitationID]
			r.MaintenanceAt = &now
			t.inventory[snap.InvitationID] = r
			out.RowsDeleted, out.ChunksDeleted, out.GenerationRemoved = result.RowsDeleted, result.ChunksDeleted, result.Done
			return nil
		}
		if !t.overviewEnabled {
			return nil
		}
		snap, e := s.overviewMaintenanceAuthority(t, device, section, now)
		if errors.Is(e, overviewledger.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		namespace := overviewDevice(device, section)
		id, e := eligibleInventoryGeneration(ctx, t, namespace, true, now)
		if e != nil || id == "" {
			return e
		}
		result, e := overviewLedger().Cleanup(ctx, t.conn, namespace, id, now)
		if e != nil {
			return e
		}
		if result.Done {
			if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_overview_generations WHERE device=? AND generation=?`, namespace, id); e != nil {
				return ErrStorage
			}
		}
		key := overviewRecordKey(snap.InvitationID, section)
		r := t.overview[key]
		r.MaintenanceAt = &now
		t.overview[key] = r
		out.RowsDeleted, out.ChunksDeleted, out.GenerationRemoved = result.RowsDeleted, result.ChunksDeleted, result.Done
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

func eligibleInventoryGeneration(ctx context.Context, t *transaction, device string, overview bool, now time.Time) (string, error) {
	table, limit, ttl := "fi_generations", int(inventoryLimits().DeviceGenerations), inventoryledger.CursorTTL
	if overview {
		table, limit, ttl = "co_generations", int(overviewLimits().DeviceGenerations), overviewledger.CursorTTL
	}
	// Table is one of two constants; no caller input becomes a SQL identifier.
	rows, e := t.conn.QueryContext(ctx, `SELECT generation,state,expires_at,retired_at FROM `+table+` WHERE device=? AND state IN ('garbage','staging','retired') ORDER BY started_at,generation LIMIT ?`, device, limit)
	if e != nil {
		return "", ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var id, state, expiry, retired string
		if rows.Scan(&id, &state, &expiry, &retired) != nil {
			return "", ErrStorage
		}
		if state == "garbage" {
			return id, nil
		}
		text := expiry
		if state == "retired" {
			text = retired
		}
		at, e := time.Parse(time.RFC3339Nano, text)
		if e != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != text {
			return "", ErrStorage
		}
		if state == "retired" {
			at = at.Add(ttl)
		}
		if !now.Before(at) {
			return id, nil
		}
	}
	if rows.Err() != nil {
		return "", ErrStorage
	}
	return "", nil
}
