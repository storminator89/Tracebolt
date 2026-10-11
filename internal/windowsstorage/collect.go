package windowsstorage

import (
	"context"
	"errors"
)

type DriveSource func(context.Context) (Drives, error)
type DiskSource func(context.Context) (Disks, error)

func CollectWithSources(ctx context.Context, r Request, drives DriveSource, disks DiskSource) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(r.Consent, r.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !r.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	s := Empty(r, ErrUnavailable.Error())
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if drives != nil {
		v, e := drives(ctx)
		if e != nil {
			v = EmptyDrives(SafeReason(e))
		}
		if !validDrives(v) {
			v = EmptyDrives(ErrMetadata.Error())
		}
		s.Drives = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if disks != nil {
		v, e := disks(ctx)
		if e != nil {
			v = EmptyDisks(SafeReason(e))
		}
		if !validDisks(v) {
			v = EmptyDisks(ErrMetadata.Error())
		}
		s.Disks = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	return FitBudget(s, MaxBytes)
}
func CollectNativeDrives(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nativeDrives, nil)
}
func CollectNativeDisks(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nativeDisks)
}
func SafeReason(e error) string {
	switch {
	case errors.Is(e, ErrDenied):
		return ErrDenied.Error()
	case errors.Is(e, ErrUnsupported):
		return ErrUnsupported.Error()
	case errors.Is(e, ErrMetadata):
		return ErrMetadata.Error()
	case errors.Is(e, ErrBounds):
		return ErrBounds.Error()
	case errors.Is(e, ErrPartial):
		return ErrPartial.Error()
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget.Error()
	default:
		return ErrUnavailable.Error()
	}
}

func observedField(value string, e error, units int) Field {
	if e != nil {
		return emptyField(SafeReason(e))
	}
	if value == "" {
		return Field{Quality: "empty"}
	}
	if !validLabel(value, units) {
		return emptyField(ErrMetadata.Error())
	}
	return Field{&value, "observed"}
}
