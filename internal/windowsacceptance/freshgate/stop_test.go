package freshgate

import (
	"context"
	"errors"
	"localrmm/internal/windowsservice"
	"testing"
)

func TestOwnedStopPendingStatesAndNoReplay(t *testing.T) {
	for _, tt := range []struct {
		name   string
		states []windowsservice.State
		stops  int
	}{{"stopped", []windowsservice.State{windowsservice.Stopped}, 0}, {"start-pending", []windowsservice.State{windowsservice.StartPending, windowsservice.Running, windowsservice.StopPending, windowsservice.Stopped}, 1}, {"already-stopping", []windowsservice.State{windowsservice.StopPending, windowsservice.Stopped}, 0}, {"delayed-stop", []windowsservice.State{windowsservice.Running, windowsservice.Running, windowsservice.StopPending, windowsservice.Stopped}, 1}} {
		t.Run(tt.name, func(t *testing.T) {
			i, calls := 0, 0
			e := StopOwned(context.Background(), OwnedStopSteps{Check: func() bool { return true }, Inspect: func() (windowsservice.State, error) {
				if i >= len(tt.states) {
					t.Fatal("read beyond sequence")
				}
				x := tt.states[i]
				i++
				return x, nil
			}, Stop: func() error { calls++; return nil }, Pause: func(context.Context) error { return nil }})
			if e != nil || calls != tt.stops {
				t.Fatal("stop sequence", e, calls)
			}
		})
	}
}
func TestOwnedStopRefusesUnknownCancelledAndAmbiguous(t *testing.T) {
	for _, mode := range []string{"unknown", "cancelled", "guard", "inspect", "stop-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			calls := 0
			e := StopOwned(ctx, OwnedStopSteps{Check: func() bool { return mode != "guard" }, Inspect: func() (windowsservice.State, error) {
				if mode == "inspect" {
					return 0, errors.New("inert")
				}
				if mode == "unknown" {
					return 99, nil
				}
				return windowsservice.Running, nil
			}, Stop: func() error { calls++; return errors.New("indeterminate synthetic stop") }, Pause: func(context.Context) error { return errors.New("no retry") }})
			if e == nil || calls > 1 || mode != "stop-error" && calls != 0 {
				t.Fatal("unsafe stop sequence", e, calls)
			}
		})
	}
}
