package windowsservice

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestRuntimeStopDoesNotHideDiagnosedOrJoinedFailure(t *testing.T) {
	cause := errors.New("fixture authority failure")
	for _, failure := range []error{Mark(PhaseRetainedState, ReasonStateRejected, cause), Mark(PhaseHandoff, ReasonHandoffInvalid, errors.Join(cause, context.Canceled)), errors.Join(cause, context.Canceled)} {
		controls := make(chan control, 1)
		controls <- controlStop
		worker := func(ctx context.Context, _ func()) error { <-ctx.Done(); return failure }
		err := runLifecycle(context.Background(), worker, controls, func(status) {})
		if err == nil || !errors.Is(err, cause) {
			t.Fatal("service Stop converted authority failure to success")
		}
	}
}
func TestRuntimeStopStillNormalizesOnlyCanceledChains(t *testing.T) {
	for _, outcome := range []error{context.Canceled, fmt.Errorf("fixture: %w", context.Canceled), Mark(PhaseLifecycle, ReasonInterrupted, context.Canceled)} {
		controls := make(chan control, 1)
		controls <- controlStop
		if err := runLifecycle(context.Background(), func(ctx context.Context, _ func()) error { <-ctx.Done(); return outcome }, controls, func(status) {}); err != nil {
			t.Fatal("normal cancellation stopped being graceful")
		}
	}
}
