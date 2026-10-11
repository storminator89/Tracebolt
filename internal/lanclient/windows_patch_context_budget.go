package lanclient

import (
	"context"
	"errors"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsupdates"
	"time"
)

const windowsPatchSourceBudget = 5 * time.Second
const windowsPatchSendReserve = 3 * time.Second

// Patch and cache are independently isolated native processes. When both scopes
// are enabled their original 15-second maxima must not consume the primary
// attempt's whole deadline. Bound each to five seconds and preserve three
// seconds of any remaining parent deadline for fitting/staging/delivery. This
// changes no outer deadline and does not affect the existing cache-only path.
// A late/absent optional result becomes a finite unavailable envelope; real
// parent cancellation still stops the entire attempt.
type patchBudgetKey struct{}
type patchSourceBudget struct{ limit, reserve time.Duration }

func patchOptionalContext(ctx context.Context) (context.Context, context.CancelFunc, bool) {
	budget := patchSourceBudget{windowsPatchSourceBudget, windowsPatchSendReserve}
	// Private deterministic test seam. No CLI, IPC or config controls these limits.
	if v, ok := ctx.Value(patchBudgetKey{}).(patchSourceBudget); ok && v.limit > 0 && v.reserve > 0 && v.limit <= budget.limit && v.reserve <= budget.reserve {
		budget = v
	}
	if deadline, ok := ctx.Deadline(); ok {
		available := time.Until(deadline) - budget.reserve
		if available <= 0 {
			return ctx, func() {}, false
		}
		if available < budget.limit {
			budget.limit = available
		}
	}
	bounded, cancel := context.WithTimeout(ctx, budget.limit)
	return bounded, cancel, true
}
func updatesWithPatchBudget(collect updatesCollector) updatesCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowsupdates.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		empty := func() (windowsupdates.Snapshot, error) {
			return windowsupdates.Snapshot{SchemaVersion: windowsupdates.SchemaVersion, Scope: windowsupdates.Scope, GrantID: r.Consent.GrantID, GenerationID: r.GenerationID, CollectedAt: r.CollectedAt, Source: "wua-cache", CacheFreshness: "unknown", Quality: "unavailable", Reason: windowsupdates.ErrBudget.Error(), Rows: []windowsupdates.Update{}}, nil
		}
		if !run {
			return empty()
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowsupdates.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return empty()
		}
		return s, e
	}
}
func patchContextWithBudget(collect patchContextCollector) patchContextCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowspatchcontext.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowspatchcontext.Empty(r, windowspatchcontext.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowspatchcontext.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowspatchcontext.Empty(r, windowspatchcontext.ErrBudget.Error()), nil
		}
		return s, e
	}
}

func securityPostureWithBudget(collect securityPostureCollector) securityPostureCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowssecurity.Request) (windowssecurity.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowssecurity.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowssecurity.Empty(r, windowssecurity.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowssecurity.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowssecurity.Empty(r, windowssecurity.ErrBudget.Error()), nil
		}
		return s, e
	}
}

func sessionContextWithBudget(collect sessionContextCollector) sessionContextCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowssessions.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowssessions.Empty(r, windowssessions.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowssessions.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowssessions.Empty(r, windowssessions.ErrBudget.Error()), nil
		}
		return s, e
	}
}
