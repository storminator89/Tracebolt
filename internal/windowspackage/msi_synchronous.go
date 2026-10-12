package windowspackage

import "context"

type synchronousMSIKey struct{}

// RequireSynchronousMSI only adds restrictions to managed-package inspection.
// It cannot make a package eligible or confer install authority.
func RequireSynchronousMSI(ctx context.Context) context.Context {
	return context.WithValue(ctx, synchronousMSIKey{}, true)
}
func synchronousMSIRequired(ctx context.Context) bool { return ctx.Value(synchronousMSIKey{}) == true }

// CustomAction type is a signed MSI integer. Reject every asynchronous flag,
// including async/wait and async/no-wait. This cannot detect arbitrary detached
// work inside otherwise synchronous code, which requires exact package review.
func synchronousCustomActionType(t int32) bool { return t >= 0 && t <= 0xffff && t&0x80 == 0 }
