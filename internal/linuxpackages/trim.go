package linuxpackages

import (
	"encoding/json"
	"sort"
)

// Trim validates a local full or already-truncated snapshot, clones its mutable
// members, sorts by name/architecture and retains a deterministic fitting prefix.
// Source totals and capture identity/time are never rewritten. It has no I/O.
func Trim(s Snapshot) (Snapshot, error) {
	return trimToBudget(s, MaxSnapshotBytes)
}

func trimToBudget(s Snapshot, budget int) (Snapshot, error) {
	if budget <= 0 || budget > MaxSnapshotBytes {
		return Snapshot{}, ErrSnapshotLimit
	}
	if err := validateShape(s, MaxDpkgRecords, false); err != nil {
		return Snapshot{}, err
	}
	s = cloneSnapshot(s)
	sort.Slice(s.Inventory.Items, func(i, j int) bool { return rowLess(s.Inventory.Items[i], s.Inventory.Items[j]) })
	if len(s.Inventory.Items) > MaxExportRows {
		s.Inventory.Items = s.Inventory.Items[:MaxExportRows]
		markTruncated(&s.Inventory, ReasonItemLimit)
	}
	for {
		b, err := json.Marshal(s)
		if err != nil {
			return Snapshot{}, ErrInvalidSnapshot
		}
		if len(b) <= budget {
			if err := Validate(s); err != nil {
				return Snapshot{}, err
			}
			// Do not retain omitted rows through the backing array/capacity of
			// the returned prefix. The output owns only its exported rows.
			items := make([]PackageRow, len(s.Inventory.Items))
			copy(items, s.Inventory.Items)
			s.Inventory.Items = items
			return s, nil
		}
		if len(s.Inventory.Items) == 0 {
			return Snapshot{}, ErrSnapshotLimit
		}
		s.Inventory.Items = s.Inventory.Items[:len(s.Inventory.Items)-1]
		markTruncated(&s.Inventory, ReasonByteLimit)
	}
}

func markTruncated(x *Inventory, reason Reason) {
	x.Complete = false
	x.Truncated = true
	if reason == ReasonByteLimit || x.Reason != ReasonByteLimit {
		x.Reason = reason
	}
}

func cloneSnapshot(s Snapshot) Snapshot {
	s.Release.Fields.ID = clonePointer(s.Release.Fields.ID)
	s.Release.Fields.VersionID = clonePointer(s.Release.Fields.VersionID)
	s.Release.Fields.VersionCodename = clonePointer(s.Release.Fields.VersionCodename)
	s.Inventory.ObservedCount = clonePointer(s.Inventory.ObservedCount)
	s.Inventory.InstalledCount = clonePointer(s.Inventory.InstalledCount)
	if s.Inventory.Items != nil {
		s.Inventory.Items = append(make([]PackageRow, 0, len(s.Inventory.Items)), s.Inventory.Items...)
	}
	return s
}

func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	value := *p
	return &value
}
