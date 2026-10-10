package lanclient

import (
	"context"

	"localrmm/internal/model"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsprocessmetrics"
)

// This private value is installed only for a fresh capture after process consent
// validation. It is neither a grant nor part of a frame, ledger or retry payload.
// Passing it through the capture context keeps sibling refits on the same policy.
type processMetricSelfPIDKey struct{}

func withProcessMetricSelfPID(ctx context.Context, pid uint32) context.Context {
	return context.WithValue(ctx, processMetricSelfPIDKey{}, pid)
}

func processMetricSelfPID(ctx context.Context) uint32 {
	if ctx == nil {
		return 0
	}
	pid, _ := ctx.Value(processMetricSelfPIDKey{}).(uint32)
	return pid
}

func collectWindowsForProcessMetrics(ctx context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
	if selfPID := processMetricSelfPID(ctx); selfPID != 0 {
		return windowsmanaged.CollectForProcessMetrics(ctx, generation, selfPID)
	}
	return windowsmanaged.Collect(ctx, generation)
}

func minimumProcessMetricSnapshot(s windowsprocessmetrics.Snapshot, selfPID uint32) windowsprocessmetrics.Snapshot {
	rows := s.Rows
	s.Rows = []windowsprocessmetrics.Process{}
	if selfPID != 0 {
		for _, row := range rows {
			if row.PID == selfPID {
				s.Rows = append(s.Rows, row)
				break
			}
		}
	}
	s.Truncated = s.ObservedCount > uint32(len(s.Rows))
	return s
}

func canTrimProcessMetricRows(s windowsprocessmetrics.Snapshot, selfPID uint32) bool {
	for _, row := range s.Rows {
		if selfPID == 0 || row.PID != selfPID {
			return true
		}
	}
	return false
}
