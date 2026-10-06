package enrollmentstore

import (
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"time"
)

type inventoryViewReadState struct {
	checkedAt           time.Time
	certificateNotAfter int64
}

// RecheckAt ages only already authorized package metadata after COMMIT and
// immediately before API output. Original capture, receipt, retention and replay
// fields survive; clock rollback cannot revive an expired generation.
func (v InventoryStatus) RecheckAt(now time.Time) (InventoryStatus, error) {
	if v.readState == nil || !validStoreTime(now) || !validStoreTime(v.readState.checkedAt) || !validStoreTime(v.ServerNow) {
		return InventoryStatus{}, ErrStorage
	}
	now = now.UTC()
	if now.Before(v.readState.checkedAt) {
		now = v.readState.checkedAt
	}
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	if now.Unix() >= v.readState.certificateNotAfter {
		return InventoryStatus{}, enrollmentstate.ErrExpired
	}
	v.ServerNow = now
	age := func(in *inventoryledger.GenerationStatus) *inventoryledger.GenerationStatus {
		if in == nil {
			return nil
		}
		out := *in
		if (out.State == "complete" || out.State == "pending" || out.State == "retired") && !now.Before(out.ExpiresAt) {
			out.State = "expired"
		}
		return &out
	}
	v.Complete, v.Transfer = age(v.Complete), age(v.Transfer)
	return v, nil
}
