package overviewledger

import (
	"fmt"
	"localrmm/internal/completeoverview"
	"localrmm/internal/overviewgeneration"
)

// displayKey is a fixed normalized operator order, separate from canonical wire
// identity order. The ordinal tie-breaker is retained in the indexed query. The
// key never goes into a cursor; a MAC-bound row ordinal resolves it server-side.
func displayKey(r overviewgeneration.Row) string {
	if r.Process != nil {
		return fmt.Sprintf("%010d", r.Process.PID)
	}
	v := r.Volume
	rank := 5
	switch v.Kind {
	case "local":
		rank = 1
		if v.Measurement.Status == completeoverview.Observed {
			rank = 0
		}
	case "memory":
		rank = 2
	case "remote":
		rank = 3
	case "unknown":
		rank = 4
	}
	root := 1
	if v.MountPoint == "/" {
		root = 0
	}
	return fmt.Sprintf("%d%d\x00%s\x00%s", rank, root, v.MountPoint, v.ID)
}
