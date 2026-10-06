package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestArgumentBoundaryIsInert(t *testing.T) {
	for _, args := range [][]string{{"--build-info"}, {"--help"}, {"--policy", "/tmp/anything"}, {"--pid", "1"}, {"--build-info", "extra"}, {"capture"}, {"--"}} {
		calls := 0
		var out, err bytes.Buffer
		code := run(context.Background(), args, &out, &err, func(context.Context) error { calls++; return nil })
		expected := 2
		if len(args) == 1 && args[0] == "--build-info" {
			expected = 0
		}
		if code != expected || calls != 0 {
			t.Fatalf("args %q: code=%d calls=%d", args, code, calls)
		}
		if expected == 0 && !strings.Contains(out.String(), "deployment v2 activated-client contract required") {
			t.Fatal("missing source gate")
		}
	}
}
func TestEntryUsesOnlyInjectedRuntime(t *testing.T) {
	for _, failure := range []error{nil, errors.New("fixture")} {
		calls := 0
		var out, err bytes.Buffer
		code := run(context.Background(), nil, &out, &err, func(context.Context) error { calls++; return failure })
		expected := 0
		if failure != nil {
			expected = 1
		}
		if code != expected || calls != 1 {
			t.Fatal("entry boundary")
		}
	}
}

func TestCoordinatedCancellationExitsCleanly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		canceled bool
		err      error
		code     int
	}{
		{"coordinated", true, context.Canceled, 0},
		{"unrelated", true, errors.New("prerequisite failure"), 1},
		{"unowned-cancellation", false, context.Canceled, 1},
		{"deadline", true, context.DeadlineExceeded, 1},
		{"mixed-failure", true, errors.Join(context.Canceled, errors.New("failure")), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, diagnostic bytes.Buffer
			code := run(ctx, nil, &out, &diagnostic, func(context.Context) error {
				if tc.canceled {
					cancel()
				}
				return tc.err
			})
			if code != tc.code || (diagnostic.Len() == 0) != (tc.code == 0) {
				t.Fatalf("code=%d diagnostic=%q", code, diagnostic.String())
			}
		})
	}
}

func TestCancellationDoesNotFinishBeforeRuntimeCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, cleanup := make(chan struct{}), make(chan struct{})
	finished := make(chan int, 1)
	go func() {
		var out, diagnostic bytes.Buffer
		finished <- run(ctx, nil, &out, &diagnostic, func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			<-cleanup
			return ctx.Err()
		})
	}()
	<-entered
	cancel()
	select {
	case <-finished:
		t.Fatal("shutdown abandoned runtime cleanup")
	default:
	}
	close(cleanup)
	if code := <-finished; code != 0 {
		t.Fatalf("exit=%d", code)
	}
}
