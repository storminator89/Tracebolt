package windowsupdatejob

import (
	"context"
	"time"
)

// The key and setter remain private to the executor kernel. An adapter cannot
// replace the signed start deadline or manufacture a fence through this API.
type installStartKey struct{}
type installStartBounds struct{ floor, consentBefore, leafBefore int64 }
type installStartFence struct {
	floor, before, consentBefore, leafBefore int64
	current                                  func(context.Context) (installStartBounds, error)
	now                                      func() time.Time
}

func withInstallStartFence(ctx context.Context, floor, before, consentBefore, leafBefore int64) context.Context {
	return context.WithValue(ctx, installStartKey{}, installStartFence{floor: floor, before: before, consentBefore: consentBefore, leafBefore: leafBefore})
}

func withInstallStartCurrent(ctx context.Context, clock func() time.Time, check func(context.Context) (installStartBounds, error)) context.Context {
	f, ok := ctx.Value(installStartKey{}).(installStartFence)
	if !ok || check == nil || clock == nil {
		return ctx
	}
	f.current = check
	f.now = clock
	return context.WithValue(ctx, installStartKey{}, f)
}

// CheckInstallStart reads the original signed start fence installed by Execute.
// Native adapters must call it on their owner thread immediately before dispatch,
// after every potentially blocking preparation/token/COM lookup. It does not
// bound operation duration or replace the kernel's durable attempted marker.
// The admitted consent/current-leaf bounds are retained too; a shorter current
// credential cannot outlive its own authority during blocking preparation.
// Missing/malformed fences, cancellation, expiry and clock rollback fail closed.
func CheckInstallStart(ctx context.Context, now time.Time) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, ok := ctx.Value(installStartKey{}).(installStartFence)
	if !ok || !validTime(f.floor) || !validTime(f.before) || !validTime(f.consentBefore) || !validTime(f.leafBefore) || f.floor >= f.before || f.floor >= f.consentBefore || f.floor >= f.leafBefore {
		return ErrAuthority
	}
	n := now.UTC().Unix()
	if !validTime(n) || n < f.floor || n >= f.before || n >= f.consentBefore || n >= f.leafBefore {
		return ErrExpired
	}
	if f.current != nil {
		fresh, err := f.current(ctx)
		if err != nil {
			return err
		}
		if !validTime(fresh.floor) || !validTime(fresh.consentBefore) || !validTime(fresh.leafBefore) || fresh.floor >= fresh.consentBefore || fresh.floor >= fresh.leafBefore {
			return ErrAuthority
		}
		if f.now == nil {
			return ErrAuthority
		}
		n = f.now().UTC().Unix()
		if !validTime(n) || n < f.floor || n >= f.before || n >= f.consentBefore || n >= f.leafBefore || n < fresh.floor || n >= fresh.consentBefore || n >= fresh.leafBefore {
			return ErrExpired
		}
		return ctx.Err()
	}
	return nil
}

// CheckNativeInstallStart is the one-use final gate after COM name resolution,
// token and volatile installer checks. Preliminary kernel checks remain reusable.
type nativeInstallStartKey struct{}

func nativeInstallStart(ctx context.Context) bool { return ctx.Value(nativeInstallStartKey{}) == true }
func CheckNativeInstallStart(ctx context.Context, now time.Time) error {
	if ctx == nil {
		return ErrAuthority
	}
	return CheckInstallStart(context.WithValue(ctx, nativeInstallStartKey{}, true), now)
}
