package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"sort"
	"time"
)

// The primary reserve applies to earlier optional providers too. A cooperative
// timeout returns an honest current-generation unavailable envelope, never nil
// (which means disabled), while unrelated source errors keep their original
// failure semantics. Native calls that ignore context remain outside this bound.
func windowsOptionalSource[S any](ctx context.Context, collect func(context.Context) (S, error), unavailable func() (S, error)) (S, error) {
	var zero S
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel, run := patchOptionalContext(ctx)
	defer cancel()
	if !run {
		return unavailable()
	}
	s, err := collect(bounded)
	if ctx.Err() != nil {
		return zero, ctx.Err()
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) && (err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		return unavailable()
	}
	return s, err
}
func eventsWithPrimaryReserve(collect eventCollector, at time.Time) eventCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, generation string, c windowseventhealth.Consent, binding string) (windowseventhealth.Snapshot, error) {
		return windowsOptionalSource(ctx, func(ctx context.Context) (windowseventhealth.Snapshot, error) {
			return collect(ctx, generation, c, binding)
		}, func() (windowseventhealth.Snapshot, error) {
			s := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: c.GrantID, GenerationID: generation, CollectedAt: at, Channels: []windowseventhealth.Channel{}}
			for _, channel := range []string{"Application", "System"} {
				s.Channels = append(s.Channels, windowseventhealth.Channel{Channel: channel, Quality: "unavailable", Reason: context.DeadlineExceeded.Error(), Rows: []windowseventhealth.Event{}})
			}
			return s, nil
		})
	}
}
func volumesWithPrimaryReserve(collect volumeCollector, at time.Time) volumeCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, generation string, c windowsvolumes.Consent, binding string) (windowsvolumes.Snapshot, error) {
		return windowsOptionalSource(ctx, func(ctx context.Context) (windowsvolumes.Snapshot, error) {
			return collect(ctx, generation, c, binding)
		}, func() (windowsvolumes.Snapshot, error) {
			return windowsvolumes.Snapshot{SchemaVersion: windowsvolumes.SchemaVersion, Scope: windowsvolumes.Scope, GrantID: c.GrantID, GenerationID: generation, CollectedAt: at, Quality: "unavailable", Reason: context.DeadlineExceeded.Error(), Rows: []windowsvolumes.Volume{}}, nil
		})
	}
}
func processMetricsWithPrimaryReserve(collect processMetricCollector) processMetricCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, pids []uint32, generation, grant string, at time.Time) (windowsprocessmetrics.Snapshot, error) {
		return windowsOptionalSource(ctx, func(ctx context.Context) (windowsprocessmetrics.Snapshot, error) {
			return collect(ctx, pids, generation, grant, at)
		}, func() (windowsprocessmetrics.Snapshot, error) {
			s := windowsprocessmetrics.Snapshot{SchemaVersion: windowsprocessmetrics.SchemaVersion, Scope: windowsprocessmetrics.Scope, GrantID: grant, GenerationID: generation, CollectedAt: at, ObservedCount: uint32(len(pids)), Rows: []windowsprocessmetrics.Process{}}
			for _, pid := range pids {
				s.Rows = append(s.Rows, windowsprocessmetrics.Process{PID: pid, CPUQuality: "unavailable", MemoryQuality: "unavailable"})
			}
			sort.Slice(s.Rows, func(i, j int) bool { return s.Rows[i].PID < s.Rows[j].PID })
			// The public fitter requires an already byte-valid snapshot. Bound
			// this newly constructed fallback first, preserving any admitted self.
			for {
				raw, err := json.Marshal(s)
				if err != nil {
					return windowsprocessmetrics.Snapshot{}, windowsprocessmetrics.ErrInvalid
				}
				if len(raw) <= windowsprocessmetrics.MaxBytes {
					return s, windowsprocessmetrics.Validate(s)
				}
				i := len(s.Rows) - 1
				for i >= 0 && processMetricSelfPID(ctx) != 0 && s.Rows[i].PID == processMetricSelfPID(ctx) {
					i--
				}
				if i < 0 {
					return windowsprocessmetrics.Snapshot{}, windowsprocessmetrics.ErrInvalid
				}
				copy(s.Rows[i:], s.Rows[i+1:])
				s.Rows = s.Rows[:len(s.Rows)-1]
				s.Truncated = true
			}
		})
	}
}
func networkWithPrimaryReserve(collect networkCollector) networkCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, generation, grant string, at time.Time) (windowsnetwork.Snapshot, error) {
		return windowsOptionalSource(ctx, func(ctx context.Context) (windowsnetwork.Snapshot, error) { return collect(ctx, generation, grant, at) }, func() (windowsnetwork.Snapshot, error) {
			return windowsnetwork.Snapshot{SchemaVersion: windowsnetwork.SchemaVersion, Scope: windowsnetwork.Scope, GrantID: grant, GenerationID: generation, CollectedAt: at, Quality: "unavailable", Rows: []windowsnetwork.Endpoint{}}, nil
		})
	}
}
func serviceStartupWithPrimaryReserve(collect serviceStartupCollector) serviceStartupCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, rows []windowsmanaged.Service, generation, grant string, at time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
		return windowsOptionalSource(ctx, func(ctx context.Context) (windowsmanaged.ServiceStartupSnapshot, error) {
			return collect(ctx, rows, generation, grant, at)
		}, func() (windowsmanaged.ServiceStartupSnapshot, error) {
			digest, err := windowsmanaged.ServiceStartupRowsSHA256(rows)
			if err != nil {
				return windowsmanaged.ServiceStartupSnapshot{}, err
			}
			s := windowsmanaged.ServiceStartupSnapshot{SchemaVersion: windowsmanaged.ServiceStartupSchemaVersion, Scope: windowsmanaged.ServiceStartupScope, GrantID: grant, GenerationID: generation, CollectedAt: at, ServicesSHA256: digest, RequestedCount: uint32(len(rows)), Rows: []windowsmanaged.ServiceStartupRow{}}
			for i := range rows {
				s.Rows = append(s.Rows, windowsmanaged.ServiceStartupRow{ServiceIndex: uint32(i), StartupQuality: "unavailable", DelayedAutoQuality: "unavailable"})
			}
			return windowsmanaged.FitServiceStartupBudget(s, windowsmanaged.ServiceStartupMaxBytes)
		})
	}
}
func adapterContextWithPrimaryReserve(collect adapterContextCollector) adapterContextCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, generation, grant string, at time.Time) (windowsadapters.Snapshot, error) {
		return windowsOptionalSource(ctx, func(ctx context.Context) (windowsadapters.Snapshot, error) {
			return collect(ctx, generation, grant, at)
		}, func() (windowsadapters.Snapshot, error) {
			return windowsadapters.Snapshot{SchemaVersion: windowsadapters.SchemaVersion, Scope: windowsadapters.Scope, GrantID: grant, GenerationID: generation, CollectedAt: at, Quality: "unavailable", Rows: []windowsadapters.Adapter{}}, nil
		})
	}
}
