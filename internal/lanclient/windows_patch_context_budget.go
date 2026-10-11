package lanclient

import (
	"context"
	"errors"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
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

func hardwareContextWithBudget(collect hardwareContextCollector) hardwareContextCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowshardware.Request) (windowshardware.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowshardware.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowshardware.Empty(r, windowshardware.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowshardware.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowshardware.Empty(r, windowshardware.ErrBudget.Error()), nil
		}
		return s, e
	}
}
func storageContextWithBudget(collect storageContextCollector) storageContextCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowsstorage.Request) (windowsstorage.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowsstorage.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowsstorage.Empty(r, windowsstorage.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowsstorage.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowsstorage.Empty(r, windowsstorage.ErrBudget.Error()), nil
		}
		return s, e
	}
}

// Each optional group rotates its leading source on successive odd/even pairs.
// Each gets the existing full ceiling when its group and source lead; a slow
// sibling cannot permanently consume that opportunity. No scheduler state or
// pending retry bytes are changed.
func collectWindowsContextGroup(ctx context.Context, sequence uint64, jobs []func(context.Context) error) error {
	for index := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		offset := int(((sequence - 1) / 2) % uint64(len(jobs)))
		if err := jobs[(offset+index)%len(jobs)](ctx); err != nil {
			return err
		}
	}
	return nil
}

func securityCoverageWithBudget(collect securityCoverageCollector) securityCoverageCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowssecuritycoverage.Request) (windowssecuritycoverage.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowssecuritycoverage.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowssecuritycoverage.Empty(r, windowssecuritycoverage.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowssecuritycoverage.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowssecuritycoverage.Empty(r, windowssecuritycoverage.ErrBudget.Error()), nil
		}
		return s, e
	}
}

func resourceContextWithBudget(collect resourceContextCollector) resourceContextCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowsresourcecontext.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowsresourcecontext.Empty(r, windowsresourcecontext.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowsresourcecontext.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowsresourcecontext.Empty(r, windowsresourcecontext.ErrBudget.Error()), nil
		}
		return s, e
	}
}

func storageIOWithBudget(collect storageIOCollector) storageIOCollector {
	if collect == nil {
		return nil
	}
	return func(ctx context.Context, r windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
		if e := ctx.Err(); e != nil {
			return windowsstorageio.Snapshot{}, e
		}
		bounded, cancel, run := patchOptionalContext(ctx)
		defer cancel()
		if !run {
			return windowsstorageio.Empty(r, windowsstorageio.ErrBudget.Error()), nil
		}
		s, e := collect(bounded, r)
		if ctx.Err() != nil {
			return windowsstorageio.Snapshot{}, ctx.Err()
		}
		if errors.Is(bounded.Err(), context.DeadlineExceeded) && (e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled)) {
			return windowsstorageio.Empty(r, windowsstorageio.ErrBudget.Error()), nil
		}
		return s, e
	}
}
