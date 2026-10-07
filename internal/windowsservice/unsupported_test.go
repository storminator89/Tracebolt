//go:build !windows

package windowsservice

import (
	"context"
	"errors"
	"testing"
)

func TestNonWindowsPublicAPIsRejectWithoutMutation(t *testing.T) {
	ctx := context.Background()
	if _, err := Plan(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := Inspect(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := ApplyInstall(ctx, InstallPlan{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	for _, fn := range []func(context.Context, Receipt) (ApplyResult, error){ApplyStart, ApplyStop, ApplyUninstall} {
		if _, err := fn(ctx, Receipt{}); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	}
	if err := Run(ctx, func(context.Context, func()) error { t.Fatal("worker executed"); return nil }); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := ValidateRuntimeIdentity(); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
