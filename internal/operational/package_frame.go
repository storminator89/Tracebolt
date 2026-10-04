package operational

import "encoding/json"

// MaxPackageFrameSnapshotBytes reserves space for the separate package snapshot
// without changing the operational-v1 standalone contract or its 48 KiB cap.
const MaxPackageFrameSnapshotBytes = 32 << 10

// TrimForPackageFrame validates and deep-clones an existing operational-v1
// snapshot, then removes deterministic trailing rows to fit the new frame's
// reservation. Collection identity, time, duration and observed counts survive;
// removed rows are explicitly partial. The caller's snapshot is never modified.
func TrimForPackageFrame(s Snapshot) (Snapshot, error) {
	return trimForPackageFrame(s, MaxPackageFrameSnapshotBytes)
}

func trimForPackageFrame(s Snapshot, budget int) (Snapshot, error) {
	if budget <= 0 || budget > MaxPackageFrameSnapshotBytes || Validate(s) != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	var result Snapshot
	if json.Unmarshal(raw, &result) != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	for {
		raw, err = json.Marshal(result)
		if err != nil {
			return Snapshot{}, ErrInvalidSnapshot
		}
		if len(raw) <= budget {
			// Re-decode the final representation so omitted rows and pointer
			// values cannot remain reachable through any output backing array.
			var bounded Snapshot
			if json.Unmarshal(raw, &bounded) != nil || Validate(bounded) != nil {
				return Snapshot{}, ErrInvalidSnapshot
			}
			return bounded, nil
		}
		v := &result.Sections
		switch {
		case len(v.Software.Items) > 0:
			dropLast(&v.Software)
		case len(v.Services.Items) > 0 && v.Services.Items[len(v.Services.Items)-1].ActiveState != "failed":
			dropLast(&v.Services)
		case len(v.Events.Items) > 0 && v.Events.Items[len(v.Events.Items)-1].Priority > 3:
			dropLast(&v.Events)
		case len(v.Processes.Items) > 0:
			dropLast(&v.Processes)
		case len(v.Network.Items) > 0:
			dropLast(&v.Network)
		case len(v.Volumes.Items) > 0:
			dropLast(&v.Volumes)
		case len(v.Events.Items) > 0:
			dropLast(&v.Events)
		case len(v.Services.Items) > 0:
			dropLast(&v.Services)
		default:
			return Snapshot{}, ErrInvalidSnapshot
		}
	}
}
